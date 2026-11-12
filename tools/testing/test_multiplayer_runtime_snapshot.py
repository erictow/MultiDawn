"""Offline native-layout, consistency, redaction and CLI checks. No game is opened."""
import argparse
import json
import struct
import unittest

import multiplayer_runtime_snapshot as snapshot


class Memory:
    base = 0x100000000

    def __init__(self):
        self.data = bytearray(0x90000)

    def put(self, address, fmt, *values):
        struct.pack_into("<" + fmt, self.data, address - self.base, *values)

    def blob(self, address, value):
        start = address - self.base
        self.data[start:start + len(value)] = value

    def read(self, address, size):
        snapshot.checked_range(address, size)
        start = address - self.base
        if start < 0 or start + size > len(self.data):
            raise OSError("Fixture address is unmapped")
        return bytes(self.data[start:start + size])


class SnapshotTests(unittest.TestCase):
    def trace_event(self, pid=42, manager="0000000100010000", mode=6, identity=0,
                    definition="0000000100020000"):
        return (f"client level=info t=1 ev=native_session stage=manager_update pid={pid} "
                f"manager={manager} mode={mode} identity={identity} definition={definition}\n")

    def test_trace_filters_pid_and_uses_latest_definition(self):
        text = self.trace_event(pid=99, manager="0000000100030000")
        text += self.trace_event()
        text += self.trace_event(mode=7, definition="0x0000000100040000")
        sessions, definitions = snapshot.trace_addresses(text, 42)
        self.assertEqual(sessions, [0x100010000])
        self.assertEqual(definitions, [0x100040000])
        with self.assertRaisesRegex(ValueError, "requested PID"):
            snapshot.trace_addresses(text, 100)

    def test_trace_drops_retired_and_null_definitions(self):
        text = self.trace_event() + self.trace_event(identity=-1, mode=-1)
        with self.assertRaisesRegex(ValueError, "initialized"):
            snapshot.trace_addresses(text, 42)
        sessions, definitions = snapshot.trace_addresses(self.trace_event(definition="0000000000000000"), 42)
        self.assertEqual(sessions, [0x100010000])
        self.assertEqual(definitions, [])

    def test_trace_rejects_invalid_pointers_and_excess_sessions(self):
        for fields in ({"manager": "0000000000000000"}, {"definition": "FFFFFFFFFFFFFFFF"}):
            with self.assertRaises(ValueError):
                snapshot.trace_addresses(self.trace_event(**fields), 42)
        text = "".join(self.trace_event(manager=f"{0x100010000 + i * 0x20000:016X}") for i in range(17))
        with self.assertRaisesRegex(ValueError, "16 initialized"):
            snapshot.trace_addresses(text, 42)

    def test_trace_does_not_treat_similar_log_events_as_addresses(self):
        text = self.trace_event().replace("stage=manager_update", "stage=manager_update_call")
        with self.assertRaisesRegex(ValueError, "initialized"):
            snapshot.trace_addresses(text, 42)

    def test_addresses_and_bounds(self):
        self.assertEqual(snapshot.address("0x100000000"), 0x100000000)
        self.assertEqual(snapshot.address("65536"), 65536)
        for value in ("0", "-1", "0x800000000000", "garbage"):
            with self.assertRaises(argparse.ArgumentTypeError):
                snapshot.address(value)
        for start, size in ((0, 4), (65536, 0), (65536, 65537), (snapshot.MAX_ADDRESS, 2)):
            with self.assertRaises(ValueError):
                snapshot.checked_range(start, size)

    def test_descriptor_does_not_emit_opaque_identities(self):
        data = bytearray(128)
        struct.pack_into("<Q", data, 0, 0x123456789)
        data[8:14] = bytes([192, 168, 1, 124, 0xB8, 0x75])
        data[38:44] = bytes([10, 0, 0, 2, 0x39, 0x30])
        data[93] = 0
        data[94:110] = b"PRIVATE-KEY-1234"
        data[110:128] = b"OPAQUE-IDENTITY-12"
        result = snapshot.descriptor(bytes(data))
        self.assertEqual(result["address"]["local"], "192.168.1.124:30136")
        self.assertEqual(result["address"]["public"], "10.0.0.2:12345")
        self.assertTrue(result["security_identity_present"])
        self.assertTrue(result["online_identity_present"])
        encoded = json.dumps(result)
        self.assertNotIn("PRIVATE", encoded)
        self.assertNotIn("OPAQUE", encoded)
        self.assertNotIn(data[94:110].hex(), encoded)
        self.assertEqual(set(result), {"machine_id", "address", "security_identity_present", "online_identity_present", "present"})
        with self.assertRaises(ValueError):
            snapshot.descriptor(bytes(127))

    def test_steam_address_never_becomes_a_fictitious_ip(self):
        for method in (1, 6, 7, 255):
            data = bytearray(86)
            opaque = b"steam:OPAQUE-PEER-IDENTITY"
            data[:len(opaque)] = opaque
            data[85] = method
            result = snapshot.net_address(bytes(data))
            self.assertNotIn("local", result)
            self.assertNotIn("public", result)
            self.assertNotIn("OPAQUE", json.dumps(result))
            self.assertNotIn("115.116.101.97", json.dumps(result))
            self.assertEqual(result["method_valid"], method <= 7)
            self.assertEqual(result["transport"], "steam" if method in (6, 7) else "other")

    def make_session(self):
        memory = Memory()
        session = memory.base + 0x10000
        replica = session + 0x868
        for offset, fmt, value in ((4, "I", 42), (12, "i", 1), (20, "i", 1),
                                   (28, "I", 2), (40, "Q", 3), (48, "Q", 2)):
            memory.put(replica + offset, fmt, value)
        for index in range(2):
            row = session + 0x8A0 + index * 184
            memory.put(row + 8, "Q", 86)
            memory.put(row + 112, "Q", 8)
            memory.put(row + 120, "Q", 123 + index)
            memory.put(row + 136, "Q", 500 + index)
            memory.put(row + 168, "Q", 1)
            memory.put(row + 176, "I", index)
            memory.put(session + 0x1FB8 + index * 288, "i", 5)
        memory.put(session + 0x1AEF8, "i", 6)
        memory.put(session + 0xE938, "i", 1)
        memory.put(session + 0xE93C, "i", 1)
        memory.put(session + 0x1C7C0, "i", 9)
        return memory, session

    def test_session_layout_and_authority(self):
        memory, session = self.make_session()
        result = snapshot.session_snapshot(memory.read, session)
        self.assertEqual(result["revision"], 42)
        self.assertEqual(result["host_member"], 1)
        self.assertEqual(result["members"][1]["machine_id"], "0x000000000000007C")
        self.assertEqual(result["members"][1]["player_slot"], 1)
        self.assertTrue(result["authority_state_range"])
        self.assertTrue(result["membership_header_stable"])
        memory.put(session + 0x1AEF8, "i", 4)
        self.assertFalse(snapshot.session_snapshot(memory.read, session)["authority_state_range"])

    def test_session_rejects_inconsistent_table(self):
        memory, session = self.make_session()
        memory.put(session + 0x868 + 40, "Q", 7)
        with self.assertRaisesRegex(ValueError, "counts/mask"):
            snapshot.session_snapshot(memory.read, session)
        memory, session = self.make_session()
        memory.put(session + 0x8A0 + 8, "Q", 85)
        with self.assertRaisesRegex(ValueError, "lengths"):
            snapshot.session_snapshot(memory.read, session)

    def make_players(self):
        memory, session = self.make_session()
        memory.put(session + 0x1C7C0, "i", 1)
        replica = session + 0x868
        memory.put(replica + 15184, "II", 2, 3)
        for slot in range(2):
            row = replica + 15192 + slot * 424
            memory.put(row + 4, "QIII", 0x110000100001234 + slot, slot, 0, 10 + slot)
            memory.blob(row + 32, b"PRIVATE-PLAYER-CONFIG")
        return memory, session

    def test_opt_in_native_players_preserves_public_ownership_only(self):
        memory, session = self.make_players()
        self.assertNotIn("players", snapshot.session_snapshot(memory.read, session))
        result = snapshot.session_snapshot(memory.read, session, True)
        self.assertEqual(result["player_mask"], "0x00000003")
        self.assertEqual(result["players"], [
            {"slot": 0, "player_id": "0x0110000100001234", "member_index": 0, "owned_index": 0, "sequence": 10},
            {"slot": 1, "player_id": "0x0110000100001235", "member_index": 1, "owned_index": 0, "sequence": 11}])
        self.assertTrue(result["player_header_stable"])
        self.assertEqual(result["identity_fingerprint"], "0x249F395BE192EE32")
        self.assertNotIn("PRIVATE-PLAYER", json.dumps(result))
        # No player's private configuration bytes are even read.
        def bounded_read(start, size):
            for slot in range(2):
                private = session + 0x868 + 15192 + slot * 424 + 32
                self.assertFalse(start < private + 20 and start + size > private)
            return memory.read(start, size)
        snapshot.session_snapshot(bounded_read, session, True)

    def test_native_players_reject_counts_slots_ids_and_owners(self):
        changes = [(15184, "I", 33), (15188, "I", 1),
                   (15192 + 4, "Q", 0), (15192 + 424 + 4, "Q", 0x110000100001234),
                   (15192 + 12, "I", 2), (15192 + 16, "I", 1)]
        for offset, fmt, value in changes:
            with self.subTest(offset=offset):
                memory, session = self.make_players()
                memory.put(session + 0x868 + offset, fmt, value)
                with self.assertRaisesRegex(ValueError, "Native player"):
                    snapshot.session_snapshot(memory.read, session, True)
        for offset, value in ((0x8A0 + 184 + 176, 0), (0x8A0 + 176, 32)):
            memory, session = self.make_players()
            memory.put(session + offset, "I", value)
            with self.assertRaisesRegex(ValueError, "Native player"):
                snapshot.session_snapshot(memory.read, session, True)

    def test_native_player_header_stability_is_reported(self):
        memory, session = self.make_players()
        calls = 0
        def changing_read(start, size):
            nonlocal calls
            data = memory.read(start, size)
            if start == session + 0x868 + 15184:
                calls += 1
                if calls == 3:
                    return struct.pack("<II", 1, 1)
            return data
        result = snapshot.session_snapshot(changing_read, session, True)
        self.assertFalse(result["player_header_stable"])
        self.assertNotIn("identity_fingerprint", result)

    def test_identity_fingerprint_ignores_revision_and_private_configuration(self):
        memory, session = self.make_players()
        before = snapshot.session_snapshot(memory.read, session, True)["identity_fingerprint"]
        memory.put(session + 0x868 + 4, "I", 12345)
        memory.blob(session + 0x868 + 15192 + 32, b"CHANGED-PRIVATE-DATA")
        self.assertEqual(snapshot.session_snapshot(memory.read, session, True)["identity_fingerprint"], before)
        memory.put(session + 0x868 + 15192 + 4, "Q", 0x123456789ABCDEF)
        self.assertNotEqual(snapshot.session_snapshot(memory.read, session, True)["identity_fingerprint"], before)
        memory.put(session + 0x1C7C0, "i", 9)
        self.assertNotIn("identity_fingerprint", snapshot.session_snapshot(memory.read, session, True))

    def test_native_player_empty_table(self):
        memory, session = self.make_session()
        for index in range(2):
            memory.put(session + 0x8A0 + index * 184 + 168, "Q", 0)
        result = snapshot.session_snapshot(memory.read, session, True)
        self.assertEqual(result["players"], [])
        self.assertEqual(result["player_mask"], "0x00000000")

    def test_group_back_pointers_and_ownership(self):
        memory = Memory()
        group, peer = memory.base + 0x30000, memory.base + 0x50000
        manager, view, index = group + 0x270, peer + 0xA8, 2
        memory.put(manager + 0x18 + index * 8, "Q", view)
        memory.put(manager + 0x110, "I", 1 << index)
        memory.blob(manager + 0x114, b"\xff\xff\x00\x00\x00\x00" * 8192)
        memory.put(manager + 0x114 + 9 * 6, "h", 7)
        memory.put(manager + 0xC920, "B", 1 << 7)
        for offset, fmt, value in ((0x48, "Q", group), (0x50, "I", index), (0x54, "Q", 912),
                                   (0x5C, "I", 1), (0xB8, "Q", manager), (0xB4, "I", index)):
            memory.put(peer + offset, fmt, value)
        result = snapshot.group_snapshot(memory.read, group)
        self.assertEqual(result["owned_global_slots"], [7])
        self.assertEqual(result["handle_mappings"], [{"handle_slot": 9, "global_slot": 7}])
        self.assertEqual(result["peers"][0]["member_index"], 1)
        self.assertTrue(result["ownership_stable"])
        memory.put(peer + 0x48, "Q", group + 1)
        with self.assertRaisesRegex(ValueError, "back-pointers"):
            snapshot.group_snapshot(memory.read, group)

    def test_managed_definition_flags_and_redaction(self):
        memory = Memory()
        definition = memory.base + 0x70000
        memory.put(definition, "i", 3)
        memory.blob(definition + 0x57C + 94, b"CURRENT-KEY-12345")
        memory.blob(definition + 0x94E + 94, b"PENDING-KEY-12345")
        memory.put(definition + 0x94C, "BB", 1, 1)
        result = snapshot.definition_snapshot(memory.read, definition)
        self.assertEqual(result["enabled"], 1)
        self.assertTrue(result["current"]["security_identity_present"])
        self.assertTrue(result["pending"]["security_identity_present"])
        self.assertNotIn("KEY", json.dumps(result))

    def test_unstable_reads_are_rejected(self):
        values = iter((b"a", b"b"))
        with self.assertRaisesRegex(ValueError, "changed"):
            snapshot.stable(lambda start, size: next(values), 65536, 1)

    def test_cli_requires_explicit_process_and_path(self):
        args = snapshot.parser().parse_args(["--pid", "123", "--game-exe", "test/destiny2.exe",
                                             "--output", "test.json", "--group", "0x100000000"])
        self.assertEqual(args.pid, 123)
        self.assertEqual(args.group, [0x100000000])
        self.assertEqual(snapshot.PROCESS_ACCESS, 0x410)


if __name__ == "__main__":
    unittest.main()
