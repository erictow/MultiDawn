using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("MultiDawn Launcher")]
[assembly: System.Reflection.AssemblyProduct("MultiDawn Launcher")]
[assembly: System.Reflection.AssemblyVersion("0.5.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("0.5.0.0")]

namespace MultiDawn.Launcher
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--native-companion-test")
            {
                if (args.Length != 3) return 2;
                try { File.WriteAllText(args[2], NativeCompanionTest.Run(args[1])); return 0; }
                catch (Exception error) { File.WriteAllText(args[2], "FAIL: " + error + Environment.NewLine); return 1; }
            }
            if (args.Length > 0 && args[0] == "--validate-install")
            {
                if (args.Length != 3) return 2;
                System.Text.StringBuilder validation = new System.Text.StringBuilder();
                validation.AppendLine("MultiDawn read-only installation validation. The game was not started.");
                validation.AppendLine("Game folder: " + args[1]);
                string error = GameLaunch.Validate(args[1], delegate(string line) { validation.AppendLine(line); });
                validation.AppendLine(error == null ? "PASS: installation is eligible for solo launch." : "FAIL: " + error);
                File.WriteAllText(args[2], validation.ToString());
                Console.Write(validation.ToString());
                return error == null ? 0 : 1;
            }
            if (args.Length > 0 && args[0] == "--self-test")
            {
                int result;
                string report;
                try
                {
                    result = PairingSelfTests.Run();
                    report = PairingSelfTests.Report;
                    if (result == 0) report += LauncherSelfTests.Run();
                    if (result == 0) report += RuntimeBridgeSelfTests.Run();
                    if (result == 0) report += InvitationV2SelfTests.Run();
                    if (result == 0) report += FriendsSelfTests.Run();
                    report += result == 0 ? "PASS: launcher validation, UI state, TCP pairing, and native companion protocol tests.\r\n" : "FAIL: " + PairingSelfTests.LastError + "\r\n";
                }
                catch (Exception ex) { result = 1; report = "FAIL: " + ex + "\r\n"; }
                Console.Write(report);
                if (args.Length > 1) File.WriteAllText(args[1], report);
                return result;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using (LauncherForm form = new LauncherForm())
            {
                if (args.Length == 2 && args[0] == "--capture-preview")
                {
                    form.PreparePreview();
                    using (Bitmap bitmap = new Bitmap(form.Width, form.Height))
                    {
                        form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, form.Size));
                        bitmap.Save(args[1], System.Drawing.Imaging.ImageFormat.Png);
                    }
                    return 0;
                }
                Application.Run(form);
            }
            return 0;
        }
    }

    internal static class GameLaunch
    {
        internal const string GameVersion = "86657.20.08.23.1800.d2_rc";
        internal static string Validate(string gameRoot) { return Validate(gameRoot, null); }
        internal static string Validate(string gameRoot, Action<string> report)
        {
            if (String.IsNullOrWhiteSpace(gameRoot)) return "Choose your separate Dawn game folder.";
            string root;
            try { root = Path.GetFullPath(gameRoot); }
            catch (Exception) { return "Choose a valid game folder."; }
            string exe = Path.Combine(root, "destiny2.exe");
            if (!File.Exists(exe)) return "This folder does not contain destiny2.exe.";
            try
            {
                if (FileVersionInfo.GetVersionInfo(exe).FileVersion != GameVersion)
                    return "Unsupported game build. Dawn requires " + GameVersion + ".";
                if (report != null) report("PASS: destiny2.exe build " + GameVersion);
                string error = ValidateRuntime(root, report);
                if (error != null) return error;
                if (!Directory.Exists(Path.Combine(root, "packages"))) return "The complete game packages folder is required.";
                if (report != null) report("PASS: packages directory exists. Package contents were not verified.");
            }
            catch (Exception ex) { return "Could not validate the installation: " + ex.Message; }
            return null;
        }

        internal static string ValidateRuntime(string root, Action<string> report)
        {
            foreach (string relative in new[] { "", "bin/x64" })
            {
                string location = Path.Combine(root, relative);
                string dll = Path.Combine(location, "steam_api64.dll");
                if (relative == "" && !File.Exists(dll))
                {
                    if (report != null) report("INFO: no root Steam DLL; validating the legacy bin/x64 Dawn installation.");
                    continue;
                }
                string display = relative == "" ? "steam_api64.dll" : relative + "/steam_api64.dll";
                if (!File.Exists(dll)) return "Install Dawn first. Missing Dawn DLL: " + display;
                FileVersionInfo version = FileVersionInfo.GetVersionInfo(dll);
                if (version.ProductName != "Dawn") return "A non-Dawn Steam DLL is present at " + display + ". Use a separate Dawn installation.";
                if (report != null) report("PASS: " + display + " identifies as Dawn " + version.FileVersion);
                string settings = Path.Combine(location, "Dawn/settings.json");
                if (!File.Exists(settings)) return "Dawn settings are missing at " + (relative == "" ? "Dawn/settings.json" : relative + "/Dawn/settings.json") + ". Install a complete release first.";
                string error = ValidateLocalSettings(File.ReadAllText(settings));
                if (error != null) return error;
                if (report != null) report("PASS: " + (relative == "" ? "Dawn/settings.json" : relative + "/Dawn/settings.json") + " uses the local server.");
            }
            return null;
        }

        internal static string DetectGameRoot(string launcherDirectory)
        {
            DirectoryInfo directory = new DirectoryInfo(Path.GetFullPath(launcherDirectory));
            for (int depth = 0; depth <= 2 && directory != null; depth++, directory = directory.Parent)
            {
                string candidate = depth == 0 ? directory.FullName : null;
                if (candidate != null && File.Exists(Path.Combine(candidate, "destiny2.exe"))) return candidate;
                candidate = Path.Combine(directory.FullName, "expectedOutput", "Destiny 2 Dawn");
                if (File.Exists(Path.Combine(candidate, "destiny2.exe"))) return candidate;
            }
            return null;
        }

        internal static string ValidateLocalSettings(string json)
        {
            try
            {
                Dictionary<string, object> document = new JavaScriptSerializer().DeserializeObject(json) as Dictionary<string, object>;
                if (document == null) return "Dawn settings must be a JSON object.";
                object clientValue, externalValue, enabledValue;
                if (!document.TryGetValue("client", out clientValue)) return null;
                Dictionary<string, object> client = clientValue as Dictionary<string, object>;
                if (client == null) return "Dawn client settings must be a JSON object.";
                if (!client.TryGetValue("external_server", out externalValue)) return null;
                Dictionary<string, object> external = externalValue as Dictionary<string, object>;
                if (external == null) return "Dawn external server settings must be a JSON object.";
                if (!external.TryGetValue("enabled", out enabledValue)) return null;
                if (!(enabledValue is bool)) return "Dawn external_server.enabled must be true or false.";
                if ((bool)enabledValue) return "Solo Play needs client.external_server.enabled set to false in each installed Dawn/settings.json file. Your files have been left unchanged.";
                return null;
            }
            catch (Exception) { return "Dawn settings contain invalid JSON. Correct the settings before launching."; }
        }

        internal static ProcessStartInfo CreateStartInfo(string gameRoot)
        {
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Path.GetFullPath(gameRoot), "destiny2.exe"));
            info.WorkingDirectory = Path.GetFullPath(gameRoot);
            info.UseShellExecute = false;
            foreach (string key in info.EnvironmentVariables.Keys.Cast<string>().ToArray())
                if (key.StartsWith("DAWN_SESSION_", StringComparison.OrdinalIgnoreCase) || key.StartsWith("DAWN_COMPANION_", StringComparison.OrdinalIgnoreCase)) info.EnvironmentVariables.Remove(key);
            info.EnvironmentVariables["DAWN_SESSION_MODE"] = "solo";
            info.EnvironmentVariables["DAWN_FOREST_BASELINE"] = "1";
            return info;
        }
        internal static string Persona(string root)
        {
            try
            {
                string settings = Path.Combine(root, "bin/x64/Dawn/settings.json");
                var document = new JavaScriptSerializer().DeserializeObject(File.ReadAllText(settings)) as Dictionary<string, object>;
                var steam = document["steam"] as Dictionary<string, object>;
                var user = steam["user"] as Dictionary<string, object>;
                string name = user["persona_name"] as string;
                if (!String.IsNullOrEmpty(name) && name.Length <= 127 && name.All(c => c >= 32 && c <= 126)) return name;
            }
            catch (Exception) { }
            return "Player";
        }
    }

    internal sealed class LauncherForm : Form
    {
        private readonly Color background = Color.FromArgb(20, 24, 32);
        private readonly Color panelColor = Color.FromArgb(29, 35, 46);
        private readonly Color muted = Color.FromArgb(174, 186, 205);
        private readonly Color accent = Color.FromArgb(89, 199, 200);
        private TextBox gameRoot, pairCode, joinAddress, joinPort, friendNickname;
        private CheckBox multiplayer;
        private Button browse, play, host, join, disconnect, copy, saveFriend, removeFriend;
        private ComboBox address, savedFriends;
        private NumericUpDown port;
        private Label gameStatus, sessionStatus, peerStatus, modeLabel, friendStatus;
        private PairSession session;
        private RuntimeBridge runtimeBridge;
        private Process game;
        private bool busy, closing;
        private readonly string configPath;
        private readonly FriendStore friendStore;
        private bool friendsAvailable;

        internal LauncherForm()
        {
            Text = "MultiDawn Launcher";
            ClientSize = new Size(760, 958);
            MinimumSize = new Size(600, 480);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = background;
            ForeColor = Color.WhiteSmoke;
            Font = new Font("Segoe UI", 10F);
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScroll = true;
            configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MultiDawn", "launcher-path.txt");
            friendStore = new FriendStore(Path.Combine(Path.GetDirectoryName(configPath), "friends.json"));
            BuildControls();
            LoadPath();
            LoadFriends(null);
            RefreshState();
            FormClosing += delegate { closing = true; if (runtimeBridge != null) runtimeBridge.Dispose(); if (session != null) session.Dispose(); if (game != null) game.Dispose(); };
        }

        protected override void OnShown(EventArgs args)
        {
            base.OnShown(args);
            // Leave room for a vertical scrollbar without introducing horizontal
            // scrolling at the default width. Narrow windows may still scroll.
            AutoScrollMinSize = new Size(Controls.Cast<Control>().Max(c => c.Right) + 12, Controls.Cast<Control>().Max(c => c.Bottom) + 12);
            Rectangle screen = Screen.FromControl(this).WorkingArea;
            Size = new Size(Math.Min(Width, screen.Width), Math.Min(Height, screen.Height));
            if (ShowInTaskbar) CenterToScreen();
        }

        private Label LabelAt(string text, int x, int y, int width, int height, Color color, float size)
        {
            Label label = new Label { Text = text, Location = new Point(x, y), Size = new Size(width, height), ForeColor = color,
                Font = new Font("Segoe UI", size), BackColor = Color.Transparent };
            Controls.Add(label); return label;
        }
        private Button ButtonAt(string text, int x, int y, int width, EventHandler action)
        {
            Button button = new DarkButton { Text = text, Location = new Point(x, y), Size = new Size(width, 36), FlatStyle = FlatStyle.Flat,
                BackColor = panelColor, ForeColor = Color.WhiteSmoke, UseVisualStyleBackColor = false, Cursor = Cursors.Hand };
            button.FlatAppearance.BorderColor = Color.FromArgb(75, 90, 111);
            button.Click += action; Controls.Add(button); return button;
        }
        private TextBox TextAt(int x, int y, int width)
        {
            TextBox box = new TextBox { Location = new Point(x, y), Size = new Size(width, 30), BackColor = panelColor,
                ForeColor = Color.WhiteSmoke, BorderStyle = BorderStyle.FixedSingle };
            Controls.Add(box); return box;
        }
        private void BuildControls()
        {
            LabelAt("MULTIDAWN", 30, 24, 700, 42, Color.White, 26);
            LabelAt("Your Dawn installation. One place to start.", 32, 75, 690, 26, muted, 11);
            LabelAt("GAME FOLDER", 32, 119, 400, 24, accent, 9);
            gameRoot = TextAt(32, 148, 576);
            gameRoot.AccessibleName = "Dawn game folder";
            gameRoot.TextChanged += delegate { RefreshState(); };
            browse = ButtonAt("Browse...", 620, 143, 108, Browse);
            gameStatus = LabelAt("", 32, 188, 696, 46, muted, 9);

            multiplayer = new CheckBox { Text = "Multiplayer", Location = new Point(32, 244), Size = new Size(160, 32), AutoSize = false,
                ForeColor = Color.WhiteSmoke, Font = new Font("Segoe UI", 12) };
            multiplayer.CheckedChanged += delegate { RefreshState(); };
            Controls.Add(multiplayer);
            modeLabel = LabelAt("Solo mode", 505, 249, 223, 26, accent, 10);
            modeLabel.TextAlign = ContentAlignment.TopRight;
            LabelAt("Pair with a friend over LAN or VPN. Saved friends remember their address;\r\na current host code is still required. Multiplayer gameplay is unavailable.",
                32, 285, 696, 49, muted, 10);

            LabelAt("HOST ADDRESS", 32, 348, 360, 22, accent, 9);
            LabelAt("PAIRING PORT (TCP)", 512, 348, 216, 22, accent, 9);
            address = new ComboBox { Location = new Point(32, 376), Size = new Size(464, 30), DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = panelColor, ForeColor = Color.WhiteSmoke, FlatStyle = FlatStyle.Flat };
            Controls.Add(address);
            foreach (IPAddress ip in LocalAddresses()) address.Items.Add(ip.ToString());
            address.SelectedIndex = 0;
            port = new NumericUpDown { Location = new Point(512, 376), Size = new Size(216, 30), Minimum = 1024, Maximum = 65535,
                Value = 30979, BackColor = panelColor, ForeColor = Color.WhiteSmoke };
            Controls.Add(port);
            LabelAt("JOIN IPv4 OVERRIDE (OPTIONAL)", 32, 421, 464, 22, accent, 9);
            LabelAt("JOIN PORT (OPTIONAL)", 512, 421, 216, 22, accent, 9);
            joinAddress = TextAt(32, 449, 464); joinAddress.MaxLength = 15; joinAddress.AccessibleName = "Optional join IPv4 override";
            joinPort = TextAt(512, 449, 216); joinPort.MaxLength = 5; joinPort.AccessibleName = "Optional join port override";
            LabelAt("CURRENT HOST PAIR CODE", 32, 488, 600, 22, accent, 9);
            pairCode = TextAt(32, 516, 576); pairCode.MaxLength = 128;
            pairCode.Font = new Font("Consolas", 11); pairCode.AccessibleName = "Pair code";
            copy = ButtonAt("Copy code", 620, 511, 108, CopyCode);
            host = ButtonAt("Host", 32, 561, 150, Host);
            join = ButtonAt("Join", 194, 561, 150, Join);
            disconnect = ButtonAt("Disconnect", 356, 561, 150, Disconnect);
            sessionStatus = LabelAt("", 32, 607, 696, 43, muted, 10);
            peerStatus = LabelAt("", 32, 650, 696, 25, accent, 9);
            LabelAt("SAVED MULTIDAWN FRIENDS", 32, 691, 600, 22, accent, 9);
            savedFriends = new ComboBox { Location = new Point(32, 719), Size = new Size(464, 30), DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = panelColor, ForeColor = Color.WhiteSmoke, FlatStyle = FlatStyle.Flat, AccessibleName = "Saved MultiDawn friend" };
            savedFriends.SelectedIndexChanged += SelectFriend; Controls.Add(savedFriends);
            removeFriend = ButtonAt("Remove friend", 512, 714, 216, RemoveFriend);
            LabelAt("PARTNER NICKNAME", 32, 760, 464, 22, accent, 9);
            friendNickname = TextAt(32, 786, 464); friendNickname.MaxLength = 64; friendNickname.Text = "My friend";
            friendNickname.AccessibleName = "Nickname for authenticated partner";
            saveFriend = ButtonAt("Save paired partner", 512, 781, 216, SaveFriend);
            friendStatus = LabelAt("", 32, 827, 696, 48, muted, 9);
            play = ButtonAt("Play solo", 512, 889, 216, Play);
            play.BackColor = Color.FromArgb(36, 91, 99);
            LabelAt("Build 86657 required. Pair codes are private: share only with your partner.\r\nPairing uses plain TCP. Use a trusted LAN or an encrypted VPN.", 32, 889, 459, 50, muted, 8.5F);
            AcceptButton = play;
        }

        private static IEnumerable<IPAddress> LocalAddresses()
        {
            List<IPAddress> addresses = new List<IPAddress>();
            try
            {
                foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (adapter.OperationalStatus != OperationalStatus.Up || adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (UnicastIPAddressInformation item in adapter.GetIPProperties().UnicastAddresses)
                        if (item.Address.AddressFamily == AddressFamily.InterNetwork && !addresses.Contains(item.Address)) addresses.Add(item.Address);
                }
            }
            catch (NetworkInformationException) { }
            if (addresses.Count == 0) addresses.Add(IPAddress.Loopback);
            return addresses;
        }
        private void LoadPath()
        {
            try { if (File.Exists(configPath)) gameRoot.Text = File.ReadAllText(configPath).Trim(); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            if (String.IsNullOrEmpty(gameRoot.Text) || !File.Exists(Path.Combine(gameRoot.Text, "destiny2.exe")))
            {
                string detected = GameLaunch.DetectGameRoot(AppDomain.CurrentDomain.BaseDirectory);
                if (detected != null) gameRoot.Text = detected;
            }
        }
        private void SavePath()
        {
            try { Directory.CreateDirectory(Path.GetDirectoryName(configPath)); File.WriteAllText(configPath, gameRoot.Text.Trim()); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        private void Browse(object sender, EventArgs args)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog { Description = "Select the separate game folder containing Dawn's destiny2.exe", SelectedPath = gameRoot.Text })
                if (dialog.ShowDialog(this) == DialogResult.OK) { gameRoot.Text = dialog.SelectedPath; SavePath(); }
        }
        private void RefreshState()
        {
            if (play == null) return;
            bool running = game != null;
            bool mp = multiplayer.Checked;
            bool active = session != null;
            gameRoot.Enabled = browse.Enabled = !mp && !running && !busy;
            multiplayer.Enabled = !active && !busy && !running;
            host.Enabled = join.Enabled = mp && !active && !busy && !running;
            pairCode.Enabled = mp && !running;
            pairCode.ReadOnly = active || busy;
            copy.Enabled = mp && active && session.IsHost && !String.IsNullOrEmpty(pairCode.Text);
            disconnect.Enabled = mp && (active || busy) && !running;
            address.Enabled = port.Enabled = mp && !active && !busy && !running;
            joinAddress.Enabled = joinPort.Enabled = mp && !active && !busy && !running;
            savedFriends.Enabled = mp && !active && !busy && !running && friendsAvailable;
            removeFriend.Enabled = savedFriends.Enabled && savedFriends.SelectedItem is SavedFriend;
            string pairedIdentity; IPEndPoint pairedEndpoint;
            bool paired = active && session.TryPeerEndpoint(out pairedIdentity, out pairedEndpoint);
            friendNickname.Enabled = mp && paired && !running && !busy && friendsAvailable;
            saveFriend.Enabled = friendNickname.Enabled;
            modeLabel.Text = mp ? "Pairing preview" : "Solo mode";
            string validation = GameLaunch.Validate(gameRoot.Text.Trim());
            gameStatus.Text = running ? "Destiny 2 is running. Close the game to change launch settings." : validation ?? "Dawn installation found. Ready for solo play.";
            gameStatus.ForeColor = running || validation == null ? accent : muted;
            play.Text = running ? "Game running" : mp ? "Gameplay unavailable" : "Play solo";
            play.Enabled = !mp && !running && !busy && validation == null;
            if (!active && !busy)
            {
                sessionStatus.Text = mp ? "Choose Host to create a code, or paste your partner's code and choose Join." : "Solo Play starts Dawn with its normal in-process server.";
                peerStatus.Text = "";
            }
        }
        private PairSession CreateSession()
        {
            PairSession value = new PairSession(FriendStore.LoadOrCreateIdentity(Path.GetDirectoryName(configPath)), (int)port.Value);
            value.StatusChanged += delegate(string status) { Dispatch(delegate { if (session == value) sessionStatus.Text = status; }); };
            value.PeerChanged += delegate(bool paired) { Dispatch(delegate {
                if (session != value) return;
                peerStatus.Text = paired ? "Partner connected. This lobby does not carry gameplay packets." : "Waiting for a partner.";
                RefreshState();
            }); };
            value.PeerEndpointChanged += delegate { Dispatch(delegate { if (session == value) RefreshStateKeepingStatus(); }); };
            return value;
        }
        private async void Host(object sender, EventArgs args)
        {
            if (busy || session != null) return;
            PairSession value;
            try { value = CreateSession(); } catch (Exception ex) { sessionStatus.Text = FriendlyError(ex); return; }
            busy = true; session = value; RefreshState();
            sessionStatus.Text = "Opening a pairing lobby...";
            try
            {
                await value.HostAsync(IPAddress.Parse((string)address.SelectedItem), (int)port.Value);
                if (session != value) return;
                runtimeBridge = new RuntimeBridge(value, GameLaunch.Persona(gameRoot.Text.Trim()));
                pairCode.Text = value.Code;
                sessionStatus.Text = "Hosting. Share this code with your partner on the same LAN or VPN.";
                peerStatus.Text = "Waiting for a partner. Firewall access may be required for this TCP port.";
            }
            catch (Exception ex) { if (session == value) { value.Dispose(); session = null; sessionStatus.Text = FriendlyError(ex); } }
            finally { busy = false; RefreshStateKeepingStatus(); }
        }
        private async void Join(object sender, EventArgs args)
        {
            if (busy || session != null) return;
            string code = pairCode.Text.Trim();
            IPAddress target = null; int? targetPort = null;
            SavedFriend selectedFriend = savedFriends.SelectedItem as SavedFriend;
            try
            {
                PairCode.Parse(code);
                if (!String.IsNullOrWhiteSpace(joinAddress.Text)) target = FriendStore.ParseAddress(joinAddress.Text);
                if (!String.IsNullOrWhiteSpace(joinPort.Text))
                {
                    int parsedPort;
                    if (!Int32.TryParse(joinPort.Text.Trim(), out parsedPort) || parsedPort < 1 || parsedPort > 65535)
                        throw new ArgumentException("Join port must be between 1 and 65535, or left empty to use the current code.");
                    targetPort = parsedPort;
                }
            }
            catch (Exception ex) { sessionStatus.Text = FriendlyError(ex); return; }
            PairSession value;
            try { value = CreateSession(); } catch (Exception ex) { sessionStatus.Text = FriendlyError(ex); return; }
            busy = true; session = value; RefreshState();
            sessionStatus.Text = "Connecting to your partner...";
            try
            {
                await value.JoinAsync(code, target, targetPort, selectedFriend == null ? null : selectedFriend.PeerId);
                if (session != value) return;
                runtimeBridge = new RuntimeBridge(value, GameLaunch.Persona(gameRoot.Text.Trim()));
                sessionStatus.Text = "Paired with host. Gameplay launch is unavailable in this build.";
                peerStatus.Text = "Partner connected. No local game server has been stopped or redirected.";
            }
            catch (Exception ex) { if (session == value) { value.Dispose(); session = null; sessionStatus.Text = FriendlyError(ex); } }
            finally { busy = false; RefreshStateKeepingStatus(); }
        }
        private void RefreshStateKeepingStatus()
        {
            string status = sessionStatus.Text, peer = peerStatus.Text;
            RefreshState(); sessionStatus.Text = status; peerStatus.Text = peer;
        }

        private void LoadFriends(string selectedIdentity)
        {
            savedFriends.Items.Clear(); savedFriends.Items.Add("Use current code without a saved friend");
            try
            {
                foreach (SavedFriend value in friendStore.Load()) savedFriends.Items.Add(value);
                friendsAvailable = true;
                friendStatus.Text = "Save a partner after pairing. Addresses can change; ask for a current host code each time.";
            }
            catch (Exception error)
            {
                friendsAvailable = false;
                friendStatus.Text = "Saved friends could not be read and were preserved: " + error.Message;
            }
            savedFriends.SelectedIndex = 0;
            if (selectedIdentity != null)
                for (int index = 1; index < savedFriends.Items.Count; ++index)
                    if (((SavedFriend)savedFriends.Items[index]).PeerId == selectedIdentity) { savedFriends.SelectedIndex = index; break; }
        }

        private void SelectFriend(object sender, EventArgs args)
        {
            SavedFriend selected = savedFriends.SelectedItem as SavedFriend;
            if (joinAddress == null || friendStatus == null) return;
            joinAddress.Text = selected == null ? "" : selected.Address;
            joinPort.Text = selected == null ? "" : selected.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (selected != null)
            {
                friendNickname.Text = selected.Nickname;
                friendStatus.Text = "Joining is pinned to " + selected.Nickname + ". Paste their current host code; update the address if it changed.";
            }
            else if (friendsAvailable) friendStatus.Text = "No saved identity selected. A current host code is required, including when overriding the IP or port.";
            RefreshStateKeepingStatus();
        }

        private void SaveFriend(object sender, EventArgs args)
        {
            string identity; IPEndPoint endpoint;
            if (session == null || !session.TryPeerEndpoint(out identity, out endpoint)) return;
            try
            {
                friendStore.Upsert(new SavedFriend { PeerId = identity, Nickname = friendNickname.Text.Trim(), Address = endpoint.Address.ToString(), Port = endpoint.Port });
                LoadFriends(identity); RefreshStateKeepingStatus();
                friendStatus.Text = "Partner saved. Their advertised hosting port is remembered; a fresh host code is still required.";
            }
            catch (Exception error) { friendStatus.Text = "Could not save friend: " + error.Message; }
        }

        private void RemoveFriend(object sender, EventArgs args)
        {
            SavedFriend selected = savedFriends.SelectedItem as SavedFriend;
            if (selected == null || session != null) return;
            try { friendStore.Remove(selected.PeerId); LoadFriends(null); RefreshStateKeepingStatus(); }
            catch (Exception error) { friendStatus.Text = "Could not remove friend: " + error.Message; }
        }
        private static string FriendlyError(Exception error)
        {
            if (error is OperationCanceledException || error is ObjectDisposedException) return "Pairing canceled.";
            if (error is SocketException || error is TimeoutException) return "Cannot reach the pairing lobby. Check the address, LAN/VPN, port, and firewall.";
            return error.Message;
        }
        private void Disconnect(object sender, EventArgs args)
        {
            if (runtimeBridge != null) { runtimeBridge.Dispose(); runtimeBridge = null; }
            PairSession old = session; session = null;
            if (old != null) old.Dispose();
            pairCode.Clear(); RefreshState();
            sessionStatus.Text = "Disconnected. The pairing listener and connection are closed.";
        }
        private void CopyCode(object sender, EventArgs args)
        {
            try { Clipboard.SetText(pairCode.Text); sessionStatus.Text = "Code copied. Share it privately with your partner."; }
            catch (System.Runtime.InteropServices.ExternalException) { sessionStatus.Text = "Clipboard is busy. Select and copy the code manually."; }
        }
        private void Play(object sender, EventArgs args)
        {
            if (multiplayer.Checked || session != null || game != null) return;
            string error = GameLaunch.Validate(gameRoot.Text.Trim());
            if (error != null) { gameStatus.Text = error; return; }
            Process[] existing = Process.GetProcessesByName("destiny2");
            bool alreadyRunning = existing.Length > 0;
            foreach (Process process in existing) process.Dispose();
            if (alreadyRunning) { gameStatus.Text = "Destiny 2 is already running. Close it before starting another game."; return; }
            try
            {
                SavePath();
                Process launched = Process.Start(GameLaunch.CreateStartInfo(gameRoot.Text.Trim()));
                if (launched == null) throw new InvalidOperationException("Destiny 2 did not start.");
                game = launched;
                launched.EnableRaisingEvents = true;
                launched.Exited += delegate { Dispatch(delegate { if (game == launched) { game.Dispose(); game = null; RefreshState(); } }); };
                RefreshState();
                if (launched.HasExited) { launched.Dispose(); game = null; RefreshState(); }
            }
            catch (Exception ex) { if (game != null) { game.Dispose(); game = null; } gameStatus.Text = "Could not launch Destiny 2: " + ex.Message; }
        }
        private void Dispatch(Action action)
        {
            if (closing || IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke(action); } catch (InvalidOperationException) { }
        }
        internal void PreparePreview()
        {
            multiplayer.Checked = true;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            Location = new Point(-32000, -32000);
            Show();
            PerformLayout();
            Application.DoEvents();
        }

        internal static void RunUiSmokeTests(Action<bool, string> check)
        {
            using (LauncherForm form = new LauncherForm())
            {
                form.gameRoot.Text = Path.GetTempPath();
                check(form.gameRoot.Enabled && form.browse.Enabled && !form.host.Enabled && !form.join.Enabled, "Solo mode allows folder selection and locks pairing actions");
                form.multiplayer.Checked = true;
                check(!form.gameRoot.Enabled && !form.browse.Enabled, "Multiplayer locks the game folder");
                check(form.host.Enabled && form.join.Enabled && form.pairCode.Enabled, "Multiplayer enables Host, Join, and code entry");
                check(!form.play.Enabled && form.play.Text == "Gameplay unavailable", "Unimplemented MP gameplay cannot be launched");
                check(!form.disconnect.Enabled && !form.copy.Enabled, "Idle lobby cannot disconnect or copy an empty code");
                check(form.joinAddress.Enabled && form.joinPort.Enabled && !form.saveFriend.Enabled && !form.friendNickname.Enabled,
                    "Manual endpoint override is available only in MP and saving requires authentication");
                SavedFriend fixture = new SavedFriend { PeerId = PairSession.NewPeerId(), Nickname = "UI fixture", Address = "25.12.34.56", Port = 30979 };
                form.savedFriends.Items.Add(fixture); form.savedFriends.SelectedItem = fixture;
                check(form.joinAddress.Text == fixture.Address && form.joinPort.Text == "30979" && form.savedFriends.SelectedItem == fixture,
                    "Saved friend selection prefills its endpoint and retains its identity pin");
                form.savedFriends.SelectedIndex = 0;
                check(form.joinAddress.Text == "" && form.joinPort.Text == "", "Clearing saved friend selection restores current-code destination defaults");
                form.multiplayer.Checked = false;
                check(form.gameRoot.Enabled && form.browse.Enabled && !form.pairCode.Enabled && !form.host.Enabled && !form.join.Enabled,
                    "Switching back to solo restores folder selection and locks pairing");
                check(!form.play.Enabled, "Invalid game installation cannot be launched");
                check(!form.joinAddress.Enabled && !form.joinPort.Enabled && !form.savedFriends.Enabled && !form.saveFriend.Enabled,
                    "Solo locks saved-friend and endpoint controls");
            }
        }
    }

    internal sealed class DarkButton : Button
    {
        internal DarkButton() { SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true); }
        protected override void OnPaint(PaintEventArgs args)
        {
            args.Graphics.Clear(BackColor);
            using (Pen border = new Pen(Enabled ? FlatAppearance.BorderColor : Color.FromArgb(58, 68, 83)))
                args.Graphics.DrawRectangle(border, 0, 0, Width - 1, Height - 1);
            TextRenderer.DrawText(args.Graphics, Text, Font, ClientRectangle, Enabled ? ForeColor : Color.FromArgb(125, 139, 158),
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
            if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(args.Graphics, Rectangle.Inflate(ClientRectangle, -4, -4));
        }
        protected override void OnEnabledChanged(EventArgs args) { base.OnEnabledChanged(args); Invalidate(); }
    }

    internal static class LauncherSelfTests
    {
        private static System.Text.StringBuilder results;
        internal static string Run()
        {
            results = new System.Text.StringBuilder();
            Check(GameLaunch.Validate("") != null, "empty path rejected");
            Check(GameLaunch.Validate(Path.GetTempPath()) != null, "non-game folder rejected");
            Check(GameLaunch.ValidateLocalSettings("{}") == null, "default local settings");
            Check(GameLaunch.ValidateLocalSettings("{\"client\":{\"external_server\":{\"enabled\":false}}}") == null, "local settings");
            Check(GameLaunch.ValidateLocalSettings("{\"client\":{\"external_server\":{\"enabled\":true}}}") != null, "external settings blocked");
            Check(GameLaunch.ValidateLocalSettings("{\"client\":{\"external_server\":{\"enabled\":\"false\"}}}") != null, "invalid boolean rejected");
            Check(GameLaunch.ValidateLocalSettings("[") != null, "invalid JSON rejected");
            string previous = Environment.GetEnvironmentVariable("DAWN_SESSION_TOKEN");
            string priorCompanion = Environment.GetEnvironmentVariable("DAWN_COMPANION_NONCE");
            try
            {
                Environment.SetEnvironmentVariable("DAWN_SESSION_TOKEN", "parent-test-value");
                Environment.SetEnvironmentVariable("DAWN_COMPANION_NONCE", "stale-parent-companion");
                ProcessStartInfo info = GameLaunch.CreateStartInfo(Path.GetTempPath());
                Check(!info.UseShellExecute && !info.EnvironmentVariables.ContainsKey("DAWN_SESSION_TOKEN"), "child environment isolated");
                Check(!info.EnvironmentVariables.ContainsKey("DAWN_COMPANION_NONCE"), "solo launch cannot inherit a stale native companion");
                Check(info.EnvironmentVariables["DAWN_SESSION_MODE"] == "solo", "solo launch mode is explicit");
                Check(info.EnvironmentVariables["DAWN_FOREST_BASELINE"] == "1", "solo launch matches the existing forest baseline launcher");
                Check(Environment.GetEnvironmentVariable("DAWN_SESSION_TOKEN") == "parent-test-value", "parent environment unchanged");
            }
            finally { Environment.SetEnvironmentVariable("DAWN_SESSION_TOKEN", previous); Environment.SetEnvironmentVariable("DAWN_COMPANION_NONCE", priorCompanion); }
            RunLayoutTests();
            LauncherForm.RunUiSmokeTests(Check);
            return results.ToString();
        }

        private static void RunLayoutTests()
        {
            string root = Path.Combine(Path.GetTempPath(), "MultiDawn-Launcher-" + Guid.NewGuid().ToString("N"));
            string game = Path.Combine(root, "expectedOutput", "Destiny 2 Dawn");
            string build = Path.Combine(root, "build", "launcher");
            Directory.CreateDirectory(game);
            Directory.CreateDirectory(build);
            try
            {
                File.WriteAllText(Path.Combine(game, "destiny2.exe"), "detection-only fixture");
                Check(GameLaunch.DetectGameRoot(build) == game, "source build detects the separate expectedOutput game folder");
                Check(GameLaunch.DetectGameRoot(game) == game, "portable launcher detects a game beside the EXE");
                File.Copy(typeof(GameLaunch).Assembly.Location, Path.Combine(root, "steam_api64.dll"));
                Check(GameLaunch.ValidateRuntime(root, null).Contains("non-Dawn Steam DLL"), "a non-Dawn root DLL cannot shadow a legacy installation");
                File.Delete(Path.Combine(root, "steam_api64.dll"));
                Check(GameLaunch.ValidateRuntime(root, null).Contains("bin/x64/steam_api64.dll"), "legacy installs still require the bin/x64 Dawn runtime");
            }
            finally
            {
                File.Delete(Path.Combine(root, "steam_api64.dll"));
                File.Delete(Path.Combine(game, "destiny2.exe"));
                Directory.Delete(game);
                Directory.Delete(Path.Combine(root, "expectedOutput"));
                Directory.Delete(build);
                Directory.Delete(Path.Combine(root, "build"));
                Directory.Delete(root);
            }
        }
        private static void Check(bool passed, string message)
        {
            if (!passed) throw new Exception("Launcher test failed: " + message);
            results.AppendLine("PASS: " + message);
        }
    }
}
