"""Read-only build-86657 session/facet evidence. Never launches or writes to a process."""
from __future__ import annotations

import argparse
import ctypes as ct
from ctypes import wintypes as wt
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

BUILD = "86657.20.08.23.1800.d2_rc"
MAX_ADDRESS = 0x7FFFFFFFFFFF
MAX_READ = 65536
PROCESS_ACCESS = 0x0400 | 0x0010  # QUERY_INFORMATION | VM_READ only
# These observers are quarantined in bootflow_hook_lifecycle.cpp, so their
# original targets should remain intact. A mismatch stops layout interpretation.
SIGNATURES = {
    "membership_decode": (0x173BFC0, "488bc45341564883ec78488968084d8b"),
    "manager_activate": (0x177E940, "48895c24185556574154415541564157488dac2440fdffff"),
    "managed_migration": (0x1796000, "4055535641564157488dac2480fcffff4881ec80040000"),
}


def address(text: str) -> int:
    try:
        value = int(text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use a decimal address or a 0x-prefixed address") from error
    if not 0x10000 <= value <= MAX_ADDRESS:
        raise argparse.ArgumentTypeError("Address is outside the 64-bit user address range")
    return value


def checked_range(start: int, size: int) -> None:
    if not 0x10000 <= start <= MAX_ADDRESS or not 0 < size <= MAX_READ or start + size - 1 > MAX_ADDRESS:
        raise ValueError("Read is outside the bounded 64-bit user address range")


def unpack(data: bytes, offset: int, fmt: str) -> int:
    return struct.unpack_from("<" + fmt, data, offset)[0]


def bits(data: bytes) -> list[int]:
    return [index for index in range(len(data) * 8) if data[index // 8] & (1 << (index % 8))]


def net_address(data: bytes) -> dict:
    if len(data) != 86:
        raise ValueError("NetAddr must contain 86 bytes")
    # Methods 6/7 contain a Steam identity, not IPv4 endpoints. Treating that
    # payload as an IP leaks opaque identity bytes and produces fictitious IPs.
    method = data[85]
    result = {"method": method, "method_valid": method <= 7, "present": any(data),
              "transport": "direct_ip" if method == 0 else "steam" if method in (6, 7) else "other"}
    if method != 0:
        return result
    def endpoint(offset: int) -> str:
        return ".".join(str(v) for v in data[offset:offset + 4]) + ":" + str(unpack(data, offset + 4, "H"))
    result.update(local=endpoint(0), public=endpoint(30))
    return result


def descriptor(data: bytes) -> dict:
    if len(data) != 128:
        raise ValueError("Managed description must contain 128 bytes")
    # The cached kind-22 body begins at payload byte 8: machine[8], NetAddr[86],
    # security identity[16], online identity[18]. Never emit either identity blob.
    return {"machine_id": f"0x{unpack(data, 0, 'Q'):016X}",
            "address": net_address(data[8:94]),
            "security_identity_present": any(data[94:110]),
            "online_identity_present": any(data[110:128]), "present": any(data)}


def stable(read, start: int, size: int) -> bytes:
    first = read(start, size)
    if len(first) != size or first != read(start, size):
        raise ValueError("Sample changed during the two reads; retry at a stable game state")
    return first


def trace_addresses(text: str, pid: int) -> tuple[list[int], list[int]]:
    """Select the latest initialized manager observations for this exact process."""
    pattern = re.compile(r"(?:^|\s)ev=native_session stage=manager_update pid=(\d+) "
        r"manager=(?:0x)?([0-9A-Fa-f]{1,16}) mode=(-?\d+) identity=(-?\d+) "
        r"definition=(?:0x)?([0-9A-Fa-f]{1,16})(?:\s|$)")
    latest = {}
    for line in text.splitlines():
        match = pattern.search(line)
        if match is None or int(match[1]) != pid:
            continue
        manager, definition = int(match[2], 16), int(match[5], 16)
        checked_range(manager, 1)
        if definition:
            checked_range(definition, 1)
        latest[manager] = (int(match[3]), int(match[4]), definition)
    initialized = [(manager, definition) for manager, (mode, identity, definition) in latest.items()
                   if mode >= 0 and 0 <= identity < 7]
    if not initialized:
        raise ValueError("Trace contains no initialized native session for the requested PID")
    if len(initialized) > 16:
        raise ValueError("Trace exceeds the bounded capacity of 16 initialized sessions")
    return [manager for manager, _ in initialized], list(dict.fromkeys(
        definition for _, definition in initialized if definition))


def native_players_snapshot(read, session: int, members: list[dict]) -> dict:
    # Build-86657 replica layout: session_state.cpp, player count/mask at
    # 15184/15188 and 32 rows of 424 bytes starting at 15192. Read only the
    # 25-byte identity/ownership prefix, never the remaining player config.
    base = session + 0x868
    header = stable(read, base + 15184, 8)
    count, mask = struct.unpack("<II", header)
    slots = [member["player_slot"] for member in members if member["player_slot"] is not None]
    if (count > 32 or count != mask.bit_count() or len(set(slots)) != len(slots)
            or any(not 0 <= slot < 32 for slot in slots)
            or mask != sum(1 << slot for slot in slots)):
        raise ValueError("Native player counts/mask do not match member ownership")
    owners = {member["index"]: member for member in members}
    players, identities = [], set()
    for slot in range(32):
        if not mask & (1 << slot):
            continue
        row = stable(read, base + 15192 + slot * 424, 25)
        identity, owner, owned_index, sequence = struct.unpack_from("<QIII", row, 4)
        if (identity == 0 or identity in identities or owner not in owners
                or owners[owner]["player_slot"] != slot or owned_index != 0):
            raise ValueError("Native player identity/ownership is inconsistent")
        identities.add(identity)
        players.append({"slot": slot, "player_id": f"0x{identity:016X}",
                        "member_index": owner, "owned_index": owned_index, "sequence": sequence})
    return {"player_mask": f"0x{mask:08X}", "players": players,
            "player_header_stable": read(base + 15184, 8) == header}


def session_snapshot(read, session: int, include_players: bool = False) -> dict:
    # SessionState replica starts at session+0x868. Its offsets are documented in
    # middleware/gameplay/group/session_state.cpp and the native handoff probe.
    prefix = stable(read, session + 0x868, 56)
    count = unpack(prefix, 28, "I")
    mask = unpack(prefix, 40, "Q")
    array_count = unpack(prefix, 48, "Q")
    if count > 32 or array_count > 32 or mask >> 32 or count != mask.bit_count() or count != array_count:
        raise ValueError("Membership counts/mask do not match the build-86657 layout")
    result = {"address": hex(session), "revision": unpack(prefix, 4, "I"),
              "host_member": unpack(prefix, 12, "i"), "succession_member": unpack(prefix, 20, "i"),
              "member_mask": f"0x{mask:08X}", "members": []}
    controls = {}
    for name, offset, fmt in (("mode", 0x1AEF8, "i"), ("pending_member", 0xE938, "i"),
                              ("registered_member", 0xE93C, "i"), ("handoff_ready", 0xE92D, "B"),
                              ("managed_identity", 0x1C7C0, "i")):
        controls[name] = unpack(stable(read, session + offset, struct.calcsize(fmt)), 0, fmt)
    result["control"] = controls
    for index in range(32):
        if not mask & (1 << index):
            continue
        row = stable(read, session + 0x8A0 + index * 0xB8, 184)
        if unpack(row, 8, "Q") != 86 or unpack(row, 112, "Q") != 8:
            raise ValueError("Membership address/machine lengths do not match the native layout")
        state = unpack(stable(read, session + 0x1FB8 + index * 0x120, 4), 0, "i")
        owned_count = unpack(row, 168, "Q")
        if owned_count > 1:
            raise ValueError("Member local-player count exceeds the supported one-player layout")
        result["members"].append({"index": index, "machine_id": f"0x{unpack(row, 120, 'Q'):016X}",
                                   "join_id": f"0x{unpack(row, 136, 'Q'):016X}", "state": state,
                                   "address": net_address(row[16:102]),
                                   "player_slot": unpack(row, 176, "I") if owned_count else None})
    result["migration_cache"] = descriptor(stable(read, session + 0x1AF04, 128))
    if include_players:
        result.update(native_players_snapshot(read, session, result["members"]))
    # Detect movement/reallocation while traversing, without suspending a thread.
    result["membership_header_stable"] = read(session + 0x868, 56) == prefix
    result["authority_state_range"] = 6 <= controls["mode"] <= 9
    return result


def definition_snapshot(read, definition: int) -> dict:
    flags = stable(read, definition + 0x94C, 2)
    result = {"address": hex(definition), "role": unpack(stable(read, definition, 4), 0, "i"),
              "enabled": flags[0], "pending_valid": flags[1],
              "current": descriptor(stable(read, definition + 0x57C, 128)),
              "pending": descriptor(stable(read, definition + 0x94E, 128))}
    result["flags_stable"] = read(definition + 0x94C, 2) == flags
    return result


def group_snapshot(read, group: int) -> dict:
    # Native facet peer layout: native_replication_observer.cpp, add_hook.
    manager = group + 0x270
    slots = stable(read, manager + 0x18, 31 * 8)
    mask_bytes = stable(read, manager + 0x110, 4)
    owned = stable(read, manager + 0xC920, 128)
    mapping = stable(read, manager + 0x114, 8192 * 6)
    result = {"address": hex(group), "facet_manager": hex(manager),
              "peer_mask": f"0x{unpack(mask_bytes, 0, 'I'):08X}", "peers": [],
              "owned_global_slots": bits(owned), "handle_mappings": []}
    for index in range(31):
        view = unpack(slots, index * 8, "Q")
        if not view:
            continue
        peer = view - 0xA8
        row = stable(read, peer, 0xC0)
        if (unpack(row, 0x48, "Q") != group or unpack(row, 0x50, "I") != index
                or unpack(row, 0xB8, "Q") != manager or unpack(row, 0xB4, "I") != index):
            raise ValueError("Facet peer back-pointers changed or do not match the pinned layout")
        result["peers"].append({"index": index, "address": hex(peer),
                                 "machine_id": f"0x{unpack(row, 0x54, 'Q'):016X}",
                                 "member_index": unpack(row, 0x5C, "I"), "active": row[0x44],
                                 "role_flags": list(row[0x45:0x47]),
                                 "transport": hex(unpack(row, 0x68, "Q"))})
    for slot in range(8192):
        global_slot = unpack(mapping, slot * 6, "h")
        if global_slot == -1:
            continue
        if not 0 <= global_slot < 1024:
            raise ValueError("Facet handle map contains an out-of-range global slot")
        result["handle_mappings"].append({"handle_slot": slot, "global_slot": global_slot})
    result["ownership_stable"] = (read(manager + 0x18, 31 * 8) == slots
        and read(manager + 0x110, 4) == mask_bytes and read(manager + 0xC920, 128) == owned
        and read(manager + 0x114, 8192 * 6) == mapping)
    return result


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def file_version(path: Path) -> str:
    version = ct.WinDLL("version", use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ct.POINTER(wt.DWORD)]
    version.GetFileVersionInfoSizeW.restype = wt.DWORD
    version.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ct.c_void_p]
    version.GetFileVersionInfoW.restype = wt.BOOL
    version.VerQueryValueW.argtypes = [ct.c_void_p, wt.LPCWSTR, ct.POINTER(ct.c_void_p), ct.POINTER(wt.UINT)]
    version.VerQueryValueW.restype = wt.BOOL
    size = version.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        raise OSError("Executable has no readable Windows version resource")
    data = ct.create_string_buffer(size)
    if not version.GetFileVersionInfoW(str(path), 0, size, data):
        raise ct.WinError(ct.get_last_error())
    pointer, length = ct.c_void_p(), wt.UINT()
    if not version.VerQueryValueW(data, "\\VarFileInfo\\Translation", ct.byref(pointer), ct.byref(length)) or length.value < 4:
        raise ValueError("Executable has no version translation")
    translations = ct.string_at(pointer, length.value)
    for offset in range(0, len(translations) - 3, 4):
        language, codepage = struct.unpack_from("<HH", translations, offset)
        query = f"\\StringFileInfo\\{language:04x}{codepage:04x}\\FileVersion"
        if version.VerQueryValueW(data, query, ct.byref(pointer), ct.byref(length)) and length.value:
            return ct.wstring_at(pointer).strip()
    raise ValueError("Executable has no FileVersion string")


class ProcessReader:
    def __init__(self, pid: int, expected_exe: Path):
        self.handle = None
        self.kernel = ct.WinDLL("kernel32", use_last_error=True)
        self.psapi = ct.WinDLL("psapi", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        self.kernel.OpenProcess.restype = wt.HANDLE
        self.kernel.CloseHandle.argtypes = [wt.HANDLE]
        self.kernel.CloseHandle.restype = wt.BOOL
        self.kernel.ReadProcessMemory.argtypes = [wt.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.POINTER(ct.c_size_t)]
        self.kernel.ReadProcessMemory.restype = wt.BOOL
        self.kernel.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ct.POINTER(wt.DWORD)]
        self.kernel.QueryFullProcessImageNameW.restype = wt.BOOL
        self.psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ct.c_void_p, wt.DWORD, ct.POINTER(wt.DWORD), wt.DWORD]
        self.psapi.EnumProcessModulesEx.restype = wt.BOOL
        self.psapi.GetModuleFileNameExW.argtypes = [wt.HANDLE, ct.c_void_p, wt.LPWSTR, wt.DWORD]
        self.psapi.GetModuleFileNameExW.restype = wt.DWORD
        self.handle = self.kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not self.handle:
            raise ct.WinError(ct.get_last_error())
        try:
            path, length = ct.create_unicode_buffer(32768), wt.DWORD(32768)
            if not self.kernel.QueryFullProcessImageNameW(self.handle, 0, path, ct.byref(length)):
                raise ct.WinError(ct.get_last_error())
            if Path(path.value).resolve() != expected_exe:
                raise ValueError("PID executable path does not match --game-exe")
            if file_version(expected_exe) != BUILD:
                raise ValueError("Executable FileVersion is not the supported build " + BUILD)
            self.modules = self._modules()
            self.base = next(base for base, path in self.modules if path == expected_exe)
            dos = self.read(self.base, 64)
            if dos[:2] != b"MZ":
                raise ValueError("Loaded executable is not PE")
            nt = self.read(self.base + unpack(dos, 60, "I"), 26)
            if nt[:4] != b"PE\0\0" or unpack(nt, 4, "H") != 0x8664 or unpack(nt, 24, "H") != 0x20B:
                raise ValueError("Loaded executable is not AMD64 PE32+")
        except BaseException:
            self.close()
            raise

    def _modules(self):
        modules, needed = (ct.c_void_p * 1024)(), wt.DWORD()
        if not self.psapi.EnumProcessModulesEx(self.handle, modules, ct.sizeof(modules), ct.byref(needed), 3):
            raise ct.WinError(ct.get_last_error())
        if needed.value > ct.sizeof(modules):
            raise ValueError("Process module list exceeds bounded capacity")
        result = []
        for base in modules[:needed.value // ct.sizeof(ct.c_void_p)]:
            path = ct.create_unicode_buffer(32768)
            length = self.psapi.GetModuleFileNameExW(self.handle, base, path, len(path))
            if not length or length >= len(path):
                raise ValueError("Cannot identify a loaded module")
            result.append((base, Path(path.value).resolve()))
        return result

    def read(self, start: int, size: int) -> bytes:
        checked_range(start, size)
        data, copied = ct.create_string_buffer(size), ct.c_size_t()
        if not self.kernel.ReadProcessMemory(self.handle, start, data, size, ct.byref(copied)) or copied.value != size:
            raise OSError(f"Cannot read {size} bytes at {start:#x}")
        return data.raw

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--pid", required=True, type=int)
    result.add_argument("--game-exe", required=True, type=Path, help="Exact executable path of the already-running isolated test installation")
    result.add_argument("--output", required=True, type=Path, help="New JSON file; existing files are never overwritten")
    result.add_argument("--group", action="append", type=address, default=[], help="Native group address from this process's native_replication log; repeatable")
    result.add_argument("--session", action="append", type=address, default=[], help="Verified native session/manager address; repeatable")
    result.add_argument("--fireteam-manager", type=address, help="Verified world manager; selects its primary session at +0x18 + primary*0x1C8A0")
    result.add_argument("--managed-definition", action="append", type=address, default=[], help="Verified managed-session definition address; repeatable")
    result.add_argument("--trace-log", type=Path, help="Read PID-matching opt-in native-session events from a log (maximum 32 MiB)")
    result.add_argument("--native-players", action="store_true", help="Read public native player IDs and validate their membership ownership; omit player configuration")
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if os.name != "nt" or ct.sizeof(ct.c_void_p) != 8:
        raise ValueError("Run with 64-bit Python on Windows")
    if not 0 < args.pid <= 0xFFFFFFFF or any(len(values) > 16 for values in (args.group, args.session, args.managed_definition)):
        raise ValueError("PID must be positive and each address list is limited to 16")
    if args.native_players and not (args.session or args.trace_log or args.fireteam_manager):
        raise ValueError("--native-players requires a session address, manager, or trace log")
    expected = args.game_exe.resolve(strict=True)
    if expected.name.lower() != "destiny2.exe":
        raise ValueError("--game-exe must name destiny2.exe")
    if args.output.exists():
        raise FileExistsError("Output already exists; choose a new file")
    traced_sessions, traced_definitions = [], []
    if args.trace_log:
        if args.trace_log.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("Trace log exceeds the 32 MiB input limit")
        with args.trace_log.open("rb") as trace:
            contents = trace.read(32 * 1024 * 1024 + 1)
        if len(contents) > 32 * 1024 * 1024:
            raise ValueError("Trace log exceeded the input limit while reading")
        traced_sessions, traced_definitions = trace_addresses(contents.decode("utf-8-sig"), args.pid)
        if any(len(set(explicit + traced)) > 16 for explicit, traced in
               ((args.session, traced_sessions), (args.managed_definition, traced_definitions))):
            raise ValueError("Combined trace and explicit addresses exceed the 16-entry limit")
    process = ProcessReader(args.pid, expected)
    try:
        report = {"schema": "multidawn-runtime-snapshot-v1", "captured_utc": datetime.now(timezone.utc).isoformat(),
                  "pid": args.pid, "build": BUILD, "game_exe": str(expected), "game_sha256": sha256(expected),
                  "image_base": hex(process.base), "process_access": "QUERY_INFORMATION|VM_READ",
                  "layout_verified": False, "signatures": {}, "groups": [], "sessions": [], "managed_definitions": [],
                  "limitations": ["Read-only samples do not establish gameplay or successful replication.",
                      "Addresses must come from this live process; the tool neither scans for nor calls native managers.",
                      "No keys, opaque identity blobs, raw memory dumps, or player profile bodies are emitted.",
                      "Two-read stability is a consistency check, not an atomic snapshot."]}
        for name, (rva, expected_hex) in SIGNATURES.items():
            wanted = bytes.fromhex(expected_hex)
            report["signatures"][name] = {"rva": hex(rva), "matches": process.read(process.base + rva, len(wanted)) == wanted}
        report["layout_verified"] = all(item["matches"] for item in report["signatures"].values())
        report["loaded_dawn_modules"] = [{"path": str(path), "base": hex(base), "sha256": sha256(path)}
            for base, path in process.modules if path.name.lower() == "steam_api64.dll"]
        if report["layout_verified"]:
            sessions = list(args.session) + traced_sessions
            definitions = list(args.managed_definition) + traced_definitions
            if args.trace_log:
                report["address_source"] = "PID-matching native manager-update trace"
            if args.fireteam_manager:
                primary = unpack(stable(process.read, args.fireteam_manager + 0x10, 4), 0, "i")
                if not 0 <= primary <= 3:
                    raise ValueError("Primary fireteam index is outside 0..3")
                sessions.append(args.fireteam_manager + 0x18 + primary * 0x1C8A0)
                report["primary_fireteam"] = {"world_manager": hex(args.fireteam_manager), "primary_index": primary,
                    "session": hex(sessions[-1])}
            for values, key, sample in ((args.group, "groups", group_snapshot),
                                        (sessions, "sessions", lambda read, pointer: session_snapshot(read, pointer, args.native_players)),
                                        (definitions, "managed_definitions", definition_snapshot)):
                for pointer in dict.fromkeys(values):
                    try:
                        report[key].append(sample(process.read, pointer))
                    except (OSError, ValueError, struct.error) as error:
                        report[key].append({"address": hex(pointer), "error": str(error)})
        else:
            report["error"] = "Native code signatures differ. No session/facet layouts were interpreted."
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
        print(str(args.output.resolve()))
        return 0 if report["layout_verified"] and not any("error" in row for key in ("groups", "sessions", "managed_definitions") for row in report[key]) else 2
    finally:
        process.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, StopIteration) as error:
        print("Snapshot refused: " + str(error), file=sys.stderr)
        sys.exit(2)
