using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>
/// Security overview: the six posture cards (tampering, protection, detection,
/// encryption, firewall, remote access), then certificates, CVEs and threat detections.
/// </summary>
public sealed class SecurityTab : DeviceTab
{
    public override string Id => "security";
    public override string Label => "Security";
    public override string Glyph => "";
    public override Accent Accent => Accent.Red;
    public override string Description => "Security status and compliance";

    private sealed record CertRow(string Name, string Issuer, string Thumbprint, string Status, Tone StatusTone, string From, string Expires, string Store, string Key, bool SelfSigned, bool OsRoot, bool Expired, bool Expiring);
    private sealed record CveRow(string Cve, string Url, string OsVersion, string PatchedIn, string Status, Tone StatusTone, string Installed, string Source, Tone SourceTone, bool Unpatched, bool Exploited);
    private sealed record DetectionRow(string Threat, string Severity, Tone SeverityTone, string Category, string Status, Tone StatusTone, string Source, string Detected, string ThreatId, string Path, string Process, string User, string Action, string Details, string EventId)
    {
        public bool HasDetails => Path.Length > 0 || Process.Length > 0 || User.Length > 0 || Details.Length > 0 || ThreatId.Length > 0;
    }

    private string _certFilter = "all";
    private string _storeFilter = "all";
    private bool _selfSignedOnly;
    private bool _showOsRoots;
    private string _certSearch = "";
    private string _cveFilter = "all";

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("security") || s.Security is null) return ModuleMissing("security");
        var sec = s.Security;
        var page = new StackPanel();
        void Add(UIElement e, double top = 24) { if (e is FrameworkElement fe && page.Children.Count > 0) fe.Margin = new Thickness(0, top, 0, 0); page.Children.Add(e); }

        UIElement? right = null;
        var lastScan = sec.Antivirus?.LastScan ?? sec.LastSecurityScan;
        if (lastScan is not null)
        {
            var p = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
            p.Children.Add(Ui.Caption("Last Scan"));
            var v = Ui.Text(Format.ShortDateTime(lastScan)); v.FontSize = 15; v.FontWeight = FontWeights.SemiBold; v.TextAlignment = TextAlignment.Right;
            p.Children.Add(v);
            right = p;
        }
        Add(Ui.TabHeader("Security Overview", "Windows protection and compliance status", Glyph, Accent, right), 0);

        var grid = Ui.CardGrid(360, 20);
        grid.Children.Add(TamperingCard(sec));
        grid.Children.Add(ProtectionCard(sec));
        grid.Children.Add(DetectionCard(sec));
        grid.Children.Add(EncryptionCard(sec));
        grid.Children.Add(FirewallCard(sec));
        grid.Children.Add(RemoteAccessCard(sec));
        Add(grid, 0);

        var certHost = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
        void RenderCerts() => certHost.Content = CertificatesCard(sec, RenderCerts);
        RenderCerts();
        Add(certHost);

        var cveHost = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
        void RenderCves() => cveHost.Content = CveCard(sec, RenderCves);
        RenderCves();
        Add(cveHost);

        Add(DetectionsCard(sec));
        return page;
    }

    // ── Posture cards ────────────────────────────────────────────────

    private static Border PostureCard(string glyph, string title, StackPanel body)
    {
        var head = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
        var tile = new Border { Width = 32, Height = 32, CornerRadius = new CornerRadius(8), Background = Ui.Brush("SubtleFillBrush"), Child = Ui.Icon(glyph, 15, Ui.Brush("TextSecondaryBrush")), Margin = new Thickness(0, 0, 10, 0) };
        ((FrameworkElement)tile.Child).HorizontalAlignment = HorizontalAlignment.Center;
        head.Children.Add(tile);
        var t = Ui.SectionHeader(title); t.VerticalAlignment = VerticalAlignment.Center;
        head.Children.Add(t);
        var root = new StackPanel();
        root.Children.Add(head);
        root.Children.Add(body);
        return Ui.Card(root, new Thickness(20, 16, 20, 16));
    }

    private static TextBlock Heading(string text)
    {
        var t = Ui.Eyebrow(text);
        t.Margin = new Thickness(0, 6, 0, 4);
        return t;
    }

    private static Grid Status(string label, bool? enabled, string on = "Enabled", string off = "Disabled", bool neutral = false, bool danger = false)
    {
        if (enabled is null) return Ui.Row(label, Ui.Status("Unknown", Tone.Neutral));
        var tone = enabled.Value ? (neutral ? Tone.Neutral : Tone.Success) : (danger ? Tone.Error : Tone.Neutral);
        return Ui.Row(label, Ui.Status(enabled.Value ? on : off, tone));
    }

    private static Grid Value(string label, string? value, bool mono = false) => Ui.Row(label, Format.OrUnknown(value), mono: mono, semibold: false);

    private static Border TamperingCard(SecurityData sec)
    {
        var body = new StackPanel();
        var tpm = sec.Tpm;
        body.Children.Add(Heading("Trusted Platform Module"));
        body.Children.Add(Status("Present", tpm?.IsPresent));
        body.Children.Add(Status("Enabled", tpm?.IsEnabled));
        body.Children.Add(Status("Activated", tpm?.IsActivated));
        body.Children.Add(Value("Version", tpm?.Version));
        body.Children.Add(Value("Manufacturer", tpm?.Manufacturer));
        if (sec.TamperProtection?.IsTamperProtected is { } tp)
            body.Children.Add(Status("Tamper Protection", tp));

        body.Children.Add(Ui.Divider());
        var sb = sec.SecureBoot;
        body.Children.Add(Status("Secure Boot", sb?.IsEnabled, danger: true));
        if (sb?.DbCertificates is { Count: > 0 } db)
            body.Children.Add(Ui.Collapsible($"Secure Boot DB ({db.Count})", Ui.List(db.Select(c => Ui.ListItem(DeviceSnapshot.FirstNonEmpty(c.CommonName, c.Subject) ?? "Unknown", c.Thumbprint is { Length: > 8 } t ? t[..8] + "…" : c.Thumbprint)))));
        if (sb?.KekCertificates is { Count: > 0 } kek)
            body.Children.Add(Ui.Collapsible($"Key Exchange Keys ({kek.Count})", Ui.List(kek.Select(c => Ui.ListItem(DeviceSnapshot.FirstNonEmpty(c.CommonName, c.Subject) ?? "Unknown", c.Thumbprint is { Length: > 8 } t ? t[..8] + "…" : c.Thumbprint)))));

        var fw = sec.FirmwarePassword;
        if (fw is not null && (!string.IsNullOrWhiteSpace(fw.StatusDisplay) || fw.AdminPasswordSet is not null))
        {
            body.Children.Add(Ui.Divider());
            bool? set = fw.StatusDisplay == "Set" ? true : fw.StatusDisplay == "Not Set" ? false : null;
            body.Children.Add(Status("Firmware Password", set, fw.StatusDisplay ?? "Set", fw.StatusDisplay ?? "Unknown", danger: fw.StatusDisplay == "Not Set"));
            if (fw.AdminPasswordSet is not null) body.Children.Add(Status("Admin / Supervisor", fw.AdminPasswordSet, "Set", "Not Set", danger: true));
            if (fw.PowerOnPasswordSet is not null) body.Children.Add(Status("Power-on Password", fw.PowerOnPasswordSet, "Set", "Not Set", danger: true));
            if (fw.HddPasswordSet is not null) body.Children.Add(Status("HDD Password", fw.HddPasswordSet, "Set", "Not Set", danger: true));
            if (!string.IsNullOrWhiteSpace(fw.Source)) body.Children.Add(Value("Source", fw.Source));
        }
        return PostureCard("", "Tampering", body);
    }

    private static Border ProtectionCard(SecurityData sec)
    {
        var body = new StackPanel();
        var dg = sec.DeviceGuard;
        body.Children.Add(Heading("Built-in Defenses"));
        if (dg?.SmartAppControlAvailable == true)
            body.Children.Add(Ui.Row("Smart App Control", Ui.Status(Format.OrUnknown(dg.SmartAppControlState), dg.SmartAppControlState == "On" ? Tone.Success : Tone.Neutral)));
        if (dg?.CoreIsolationStatus != "Not supported")
            body.Children.Add(Ui.Row("Core Isolation", Ui.Status(DeviceSnapshot.FirstNonEmpty(dg?.CoreIsolationStatus) ?? (dg?.CoreIsolationEnabled == true ? "Enabled" : "Disabled"), dg?.CoreIsolationEnabled == true ? Tone.Success : Tone.Neutral)));
        if (dg is not null && dg.MemoryIntegrityStatus != "Not supported")
            body.Children.Add(Ui.Row("Memory Integrity (HVCI)", Ui.Status(dg.MemoryIntegrityEnabled ? "Enabled" : DeviceSnapshot.FirstNonEmpty(dg.MemoryIntegrityStatus) ?? "Disabled", dg.MemoryIntegrityEnabled ? Tone.Success : Tone.Neutral)));
        if (dg is not null) body.Children.Add(Status("Kernel DMA Protection", dg.KernelDmaProtectionEnabled));

        body.Children.Add(Ui.Divider());
        body.Children.Add(Ui.Row("VBS (Virtualization-based Security)", Ui.Status(dg?.VbsEnabled == true ? DeviceSnapshot.FirstNonEmpty(dg.VbsStatus) ?? "Running" : DeviceSnapshot.FirstNonEmpty(dg?.VbsStatus) ?? "Not configured", dg?.VbsEnabled == true ? Tone.Success : Tone.Neutral)));
        if (dg is not null && !dg.VbsEnabled) body.Children.Add(Status("VBS Hardware Support", dg.VbsSupported, "Supported", "Not supported"));
        if (dg?.VbsServices is { Count: > 0 } svcs) body.Children.Add(Value("VBS Services", string.Join(", ", svcs)));

        body.Children.Add(Ui.Divider());
        var ep = dg?.ExploitProtection;
        body.Children.Add(Ui.Row("Exploit Protection", Ui.Status(DeviceSnapshot.FirstNonEmpty(ep?.SystemStatus) ?? "Enabled", ep?.SystemStatus is "Configured" or null ? Tone.Success : Tone.Neutral)));
        if (ep is not null)
        {
            body.Children.Add(Status("DEP", ep.DepEnabled));
            body.Children.Add(Status("ASLR", ep.AslrEnabled));
            body.Children.Add(Status("CFG", ep.CfgEnabled));
        }

        var lsa = sec.LsaProtection;
        if (lsa is not null && (lsa.Enabled is not null || !string.IsNullOrWhiteSpace(lsa.Mode)))
        {
            body.Children.Add(Ui.Divider());
            body.Children.Add(Status("LSA Protection", lsa.Enabled == true, lsa.Mode == "PPLBoot" ? "Enabled (UEFI Lock)" : "Enabled", "Disabled"));
        }
        if (sec.AsrRules is { Count: > 0 } rules)
        {
            var block = rules.Count(r => r.State == "Block");
            var audit = rules.Count(r => r.State == "Audit");
            var warn = rules.Count(r => r.State == "Warn");
            var summary = $"{block}/{rules.Count} Block" + (audit > 0 ? $", {audit} Audit" : "") + (warn > 0 ? $", {warn} Warn" : "");
            body.Children.Add(Ui.Collapsible($"Attack Surface Reduction  {summary}", Ui.List(rules.Select(r => Ui.ListItem(r.Name ?? r.Id ?? "", null, r.State, r.State switch { "Block" => Tone.Success, "Audit" => Tone.Warning, "Warn" => Tone.Orange, _ => Tone.Neutral })))));
        }
        var al = sec.AppLocker;
        if (al is not null && (al.WdacEnabled || al.PolicyConfigured || !string.IsNullOrWhiteSpace(al.EffectivePolicySummary)))
        {
            body.Children.Add(Ui.Row("App Control (WDAC)", Ui.Status(al.WdacEnabled ? (al.WdacAuditMode ? "Audit Mode" : "Enforced") : "Off", al.WdacEnabled ? (al.WdacAuditMode ? Tone.Warning : Tone.Success) : Tone.Neutral)));
            body.Children.Add(Value("AppLocker", al.PolicyConfigured ? DeviceSnapshot.FirstNonEmpty(al.EffectivePolicySummary) ?? "Configured" : "Not Configured"));
        }
        if (!string.IsNullOrWhiteSpace(sec.SmartScreen?.WindowsState)) body.Children.Add(Value("SmartScreen", sec.SmartScreen.WindowsState));
        return PostureCard("", "Protection", body);
    }

    private static Border DetectionCard(SecurityData sec)
    {
        var body = new StackPanel();
        var av = sec.Antivirus;
        body.Children.Add(Heading(DeviceSnapshot.FirstNonEmpty(av?.Name) ?? "Windows Security"));
        body.Children.Add(Status("Real-time Protection", av?.IsEnabled));
        body.Children.Add(Value("Version", av?.Version));
        body.Children.Add(Ui.Row("Definitions", Ui.Status(av?.IsUpToDate == true ? "Up to date" : "Needs update", av?.IsUpToDate == true ? Tone.Success : Tone.Warning)));
        body.Children.Add(Value("Last Update", av?.LastUpdate is null ? "Unknown" : Format.ShortDateTime(av.LastUpdate)));
        body.Children.Add(Value("Last Scan", (av?.LastScan is null ? "Unknown" : Format.ShortDateTime(av.LastScan)) + (string.IsNullOrWhiteSpace(av?.ScanType) ? "" : $" ({av.ScanType})")));
        var dv = sec.DefenderVersions;
        if (!string.IsNullOrWhiteSpace(dv?.AmEngineVersion))
        {
            body.Children.Add(Ui.Divider());
            body.Children.Add(Value("Engine Version", dv.AmEngineVersion, mono: true));
            if (!string.IsNullOrWhiteSpace(dv.AmProductVersion)) body.Children.Add(Value("Platform Version", dv.AmProductVersion, mono: true));
            if (!string.IsNullOrWhiteSpace(dv.AntivirusSignatureVersion)) body.Children.Add(Value("Signatures", dv.AntivirusSignatureVersion, mono: true));
        }
        var ex = sec.DefenderExclusions;
        if (ex is not null)
        {
            var all = (ex.Paths ?? []).Concat(ex.Processes ?? []).Concat(ex.Extensions ?? []).Concat(ex.IpAddresses ?? []).ToList();
            var count = ex.TotalCount > 0 ? ex.TotalCount : all.Count;
            if (count > 0)
                body.Children.Add(Ui.Collapsible($"Defender Exclusions  {count}", Ui.List(all.Select(e => Ui.ListItem(e)))));
        }
        if (sec.EdrProducts is { Count: > 0 } edr)
        {
            body.Children.Add(Ui.Divider());
            foreach (var e in edr)
                body.Children.Add(Ui.Row(DeviceSnapshot.FirstNonEmpty(e.Name, e.Vendor) ?? "EDR", Ui.Status(e.ServiceRunning ? "Running" : "Stopped", e.ServiceRunning ? Tone.Success : Tone.Neutral)));
        }
        if (sec.AuditPolicy?.Categories is { Count: > 0 } cats)
        {
            var audited = cats.Count(c => !string.IsNullOrWhiteSpace(c.Setting) && c.Setting != "No Auditing");
            body.Children.Add(Ui.Collapsible($"Audit Policy  {audited}/{cats.Count} audited", Ui.List(cats.Select(c => Ui.ListItem(c.Subcategory ?? "", c.Category, value: Format.OrDash(c.Setting))))));
        }
        return PostureCard("", "Detection", body);
    }

    private static Border EncryptionCard(SecurityData sec)
    {
        var body = new StackPanel();
        var bl = sec.Encryption?.BitLocker;
        body.Children.Add(Heading("BitLocker Drive Encryption"));
        body.Children.Add(Value("Drives", bl?.EncryptedDrives is { Count: > 0 } d ? string.Join(", ", d) : "None encrypted"));
        body.Children.Add(Value("Method", DeviceSnapshot.FirstNonEmpty(sec.Encryption?.EncryptedVolumes?.FirstOrDefault()?.EncryptionMethod) ?? "XTS-AES"));
        body.Children.Add(Ui.Row("Status", Ui.Status(DeviceSnapshot.FirstNonEmpty(bl?.Status) ?? (bl?.IsEnabled == true ? "Enabled" : "Disabled"), bl?.IsEnabled == true ? Tone.Success : Tone.Error)));
        if (bl is not null && (bl.RecoveryKeysEscrowed || bl.RecoveryKeys is { Count: > 0 }))
        {
            body.Children.Add(Ui.Divider());
            body.Children.Add(Status("Recovery Keys Escrowed", bl.RecoveryKeysEscrowed, "Escrowed", "Not Escrowed", danger: true));
            if (!string.IsNullOrWhiteSpace(bl.EscrowLocation)) body.Children.Add(Value("Escrow Location", bl.EscrowLocation));
            if (bl.LastEscrowDate is not null) body.Children.Add(Value("Last Escrow", Format.ShortDateTime(bl.LastEscrowDate)));
            foreach (var key in bl.RecoveryKeys ?? [])
                body.Children.Add(Ui.Row($"{key.DriveLetter} {string.Join(", ", key.KeyProtectors ?? [])}".Trim(), Ui.Status(key.IsEscrowed ? "Escrowed" : "Not Escrowed", key.IsEscrowed ? Tone.Success : Tone.Error)));
        }
        foreach (var vol in sec.Encryption?.EncryptedVolumes ?? [])
            if (vol.EncryptionPercentage is > 0 and < 100) body.Children.Add(Value($"{vol.DriveLetter} encryption", $"{Format.Percent(vol.EncryptionPercentage)} ({vol.Status})"));
        return PostureCard("", "Encryption", body);
    }

    private static Border FirewallCard(SecurityData sec)
    {
        var body = new StackPanel();
        var fw = sec.Firewall;
        body.Children.Add(Heading("Windows Firewall"));
        body.Children.Add(Ui.Row("State", Ui.Status(DeviceSnapshot.FirstNonEmpty(fw?.StatusDisplay) ?? (fw?.IsEnabled == true ? "Enabled" : "Disabled"), fw?.IsEnabled == true ? Tone.Success : Tone.Error)));
        body.Children.Add(Value("Profile", DeviceSnapshot.FirstNonEmpty(fw?.Profile) ?? "Domain/Private/Public"));
        if (fw?.Profiles is { Count: > 0 } profiles)
        {
            body.Children.Add(Ui.Divider());
            foreach (var p in profiles)
                body.Children.Add(Ui.Row(p.Name ?? "Profile", Ui.Status(p.Enabled ? $"On · in {p.DefaultInboundAction ?? "?"} / out {p.DefaultOutboundAction ?? "?"}" : "Off", p.Enabled ? Tone.Success : Tone.Error)));
        }
        var rules = fw?.Rules ?? [];
        if (rules.Count > 0)
        {
            body.Children.Add(Value("Inbound Rules", rules.Count(r => r.Enabled && string.Equals(r.Direction, "Inbound", StringComparison.OrdinalIgnoreCase)).ToString()));
            body.Children.Add(Value("Outbound Rules", rules.Count(r => r.Enabled && string.Equals(r.Direction, "Outbound", StringComparison.OrdinalIgnoreCase)).ToString()));
        }
        else
        {
            body.Children.Add(Value("Inbound Rules", "Active"));
            body.Children.Add(Value("Outbound Rules", "Active"));
        }
        return PostureCard("", "Firewall", body);
    }

    private static Border RemoteAccessCard(SecurityData sec)
    {
        var body = new StackPanel();
        var rdp = sec.Rdp;
        body.Children.Add(Status("Remote Desktop (RDP)", rdp?.IsEnabled));
        body.Children.Add(Value("RDP Port", rdp?.Port > 0 ? rdp.Port.ToString() : "3389"));
        body.Children.Add(Status("Network Level Auth", rdp?.NlaEnabled));
        body.Children.Add(Ui.Divider());
        var ssh = sec.SecureShell;
        body.Children.Add(Status("OpenSSH Installed", ssh?.IsInstalled));
        body.Children.Add(Status("Secure Shell Service", ssh?.IsServiceRunning));
        body.Children.Add(Status("Secure Shell Firewall Rule", ssh?.IsFirewallRulePresent));
        if (ssh?.IsInstalled == true)
        {
            body.Children.Add(Status("Public Key Auth Configured", ssh.IsConfigured));
            body.Children.Add(Status("Authorized Key Deployed", ssh.IsKeyDeployed));
            body.Children.Add(Status("Permissions Correct", ssh.ArePermissionsCorrect));
        }
        return PostureCard("", "Remote Access", body);
    }

    // ── Certificates ─────────────────────────────────────────────────

    private UIElement CertificatesCard(SecurityData sec, Action rerender)
    {
        var certs = (sec.Certificates ?? []).Select(c =>
        {
            var status = DeviceSnapshot.FirstNonEmpty(c.Status) ?? (c.IsExpired ? "Expired" : c.IsExpiringSoon ? "ExpiringSoon" : "Valid");
            var expired = status == "Expired" || c.IsExpired;
            var expiring = status == "ExpiringSoon" || c.IsExpiringSoon;
            var store = c.StoreLocation is "LocalMachine" or "System" ? "System" : "User";
            var name = DeviceSnapshot.FirstNonEmpty(c.CommonName) ?? (c.Subject ?? "").Split(',')[0].Replace("CN=", "", StringComparison.OrdinalIgnoreCase).Trim();
            return new CertRow(name.Length > 0 ? name : "—", c.Issuer ?? "", c.Thumbprint ?? "",
                expired ? "Expired" : expiring ? (c.DaysUntilExpiry > 0 ? $"{c.DaysUntilExpiry}d" : "Expiring") : "Valid",
                expired ? Tone.Error : expiring ? Tone.Warning : Tone.Success,
                c.NotBefore is null ? "—" : Format.ShortDate(c.NotBefore), c.NotAfter is null ? "—" : Format.ShortDate(c.NotAfter),
                store, string.IsNullOrWhiteSpace(c.StoreName) ? store : $"{store} · {c.StoreName}", c.IsSelfSigned, c.IsOsTrustedRoot, expired, expiring);
        }).ToList();

        var summary = sec.CertificateSummary;
        var osRootExpired = summary?.OsRootExpiredCount > 0 ? summary.OsRootExpiredCount : certs.Count(c => c.OsRoot && c.Expired);
        var visible = _showOsRoots ? certs : certs.Where(c => !(c.OsRoot && c.Expired)).ToList();
        var expiredCount = visible.Count(c => c.Expired);
        var expiringCount = visible.Count(c => c.Expiring);
        var validCount = visible.Count(c => !c.Expired && !c.Expiring);
        var selfSignedCount = visible.Count(c => c.SelfSigned);
        var stores = visible.Select(c => c.Store).Distinct().OrderBy(x => x).ToList();

        var filtered = visible.Where(c =>
        {
            if (_certFilter == "expired" && !c.Expired) return false;
            if (_certFilter == "expiringsoon" && !c.Expiring) return false;
            if (_certFilter == "valid" && (c.Expired || c.Expiring)) return false;
            if (_storeFilter != "all" && c.Store != _storeFilter) return false;
            if (_selfSignedOnly && !c.SelfSigned) return false;
            var q = _certSearch.Trim();
            return q.Length == 0 || c.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || c.Issuer.Contains(q, StringComparison.OrdinalIgnoreCase) || c.Thumbprint.Contains(q, StringComparison.OrdinalIgnoreCase);
        }).OrderBy(c => c.Store).ThenBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();

        var controls = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        void Toggle(string label, bool active, Tone tone, Action onClick)
        {
            var pill = Ui.Pill(label, tone);
            pill.Cursor = Cursors.Hand; pill.Margin = new Thickness(0, 0, 6, 0); pill.BorderThickness = new Thickness(2);
            pill.BorderBrush = active ? Ui.StatusBrush(tone) : System.Windows.Media.Brushes.Transparent;
            pill.MouseLeftButtonUp += (_, _) => { onClick(); rerender(); };
            controls.Children.Add(pill);
        }
        if (stores.Count > 1)
            foreach (var store in stores)
                Toggle($"{store} ({visible.Count(c => c.Store == store)})", _storeFilter == store, Tone.Info, () => _storeFilter = _storeFilter == store ? "all" : store);
        Toggle($"Valid ({validCount})", _certFilter == "valid", Tone.Success, () => _certFilter = _certFilter == "valid" ? "all" : "valid");
        Toggle($"Expiring Soon ({expiringCount})", _certFilter == "expiringsoon", Tone.Warning, () => _certFilter = _certFilter == "expiringsoon" ? "all" : "expiringsoon");
        Toggle($"Expired ({expiredCount})", _certFilter == "expired", Tone.Error, () => _certFilter = _certFilter == "expired" ? "all" : "expired");
        Toggle($"Self-signed ({selfSignedCount})", _selfSignedOnly, Tone.Info, () => _selfSignedOnly = !_selfSignedOnly);
        if (osRootExpired > 0)
            Toggle($"{(_showOsRoots ? "Hide" : "Show")} expired OS roots ({osRootExpired})", _showOsRoots, Tone.Neutral, () => _showOsRoots = !_showOsRoots);
        if (_certFilter != "all" || _storeFilter != "all" || _selfSignedOnly || _showOsRoots || _certSearch.Trim().Length > 0)
        {
            var clear = new Button { Content = "Clear Filters", Padding = new Thickness(8, 2, 8, 2), FontSize = 11.5, Margin = new Thickness(0, 0, 6, 0) };
            clear.Click += (_, _) => { _certFilter = "all"; _storeFilter = "all"; _selfSignedOnly = false; _showOsRoots = false; _certSearch = ""; rerender(); };
            controls.Children.Add(clear);
        }
        controls.Children.Add(new SearchBox("Search certificates...", q => { _certSearch = q; rerender(); }) { Text = _certSearch });

        var subtitle = $"{visible.Count} certificates" + (!_showOsRoots && osRootExpired > 0 ? $" ({osRootExpired} expired OS roots hidden)" : "");
        UIElement body;
        if (certs.Count == 0) body = Ui.EmptyState("No certificates collected. Certificate data will appear after the next collection.", "");
        else if (filtered.Count == 0) body = Ui.EmptyState("No certificates match the selected filters", "");
        else body = Table.Build(filtered,
            Col.Text("Name / Issuer", "Name", star: true, sub: "Issuer"),
            Col.Text("Thumbprint", "Thumbprint", 190, mono: true),
            Col.Pill("Status", "Status", "StatusTone", 110),
            Col.Text("Valid From", "From", 120),
            Col.Text("Expires", "Expires", 120),
            Col.Text("Store", "Key", 170));
        return Ui.TableCard("Certificates", subtitle, body, controls);
    }

    // ── CVEs ─────────────────────────────────────────────────────────

    private UIElement CveCard(SecurityData sec, Action rerender)
    {
        var rows = new List<CveRow>();
        foreach (var c in sec.SecurityCves ?? [])
        {
            if (string.IsNullOrWhiteSpace(c.Cve)) continue;
            var status = DeviceSnapshot.FirstNonEmpty(c.Status) ?? "Unpatched";
            var isExploited = c.ActivelyExploited;
            rows.Add(new CveRow(c.Cve, DeviceSnapshot.FirstNonEmpty(c.Url) ?? (c.Cve.StartsWith("CVE-") ? $"https://msrc.microsoft.com/update-guide/vulnerability/{c.Cve}" : ""),
                Format.OrDash(c.OsVersion), DeviceSnapshot.FirstNonEmpty(c.KbArticle, c.PatchedVersion) ?? "—",
                status == "Patched" ? "Patched" : isExploited ? "Exploited" : "Unpatched", status == "Patched" ? Tone.Success : isExploited ? Tone.Error : Tone.Warning,
                c.InstalledDate is null ? "—" : Format.ShortDate(c.InstalledDate), "MSRC", Tone.Info, status != "Patched", isExploited));
        }
        if (rows.Count == 0)
            foreach (var u in sec.SecurityUpdates ?? [])
                rows.Add(new CveRow(u.Id ?? u.Title ?? "", "", "—", u.Title ?? "—", u.Status ?? "Unpatched", Tone.Warning, u.InstallDate is null ? "—" : Format.ShortDate(u.InstallDate), "MSRC", Tone.Info, true, false));

        var unpatched = rows.Where(r => r.Unpatched).ToList();
        var patched = rows.Where(r => !r.Unpatched).ToList();
        var exploited = unpatched.Count(r => r.Exploited);
        var total = sec.SecurityReleaseInfo?.UniqueCvesCount > 0 ? sec.SecurityReleaseInfo.UniqueCvesCount : rows.Count;

        var shown = _cveFilter == "unpatched" ? unpatched : _cveFilter == "patched" ? patched : rows;
        shown = shown.OrderBy(r => r.Unpatched ? 0 : 1).ThenBy(r => r.Exploited ? 0 : 1).ThenBy(r => r.Cve).ToList();

        var badges = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        if (sec.PendingReboot?.Required == true) { var b = Ui.Pill("Reboot Required", Tone.Warning); b.Margin = new Thickness(0, 0, 6, 0); badges.Children.Add(b); }
        if (exploited > 0) { var b = Ui.Pill($"{exploited} Actively Exploited", Tone.Error); b.Margin = new Thickness(0, 0, 6, 0); badges.Children.Add(b); }
        if (rows.Count > 0) { var b = Ui.Pill($"{total} total CVEs"); b.Margin = new Thickness(0, 0, 6, 0); badges.Children.Add(b); }
        if (patched.Count > 0 && unpatched.Count > 0)
        {
            foreach (var (key, label, tone) in new[] { ("all", $"All ({rows.Count})", Tone.Neutral), ("unpatched", $"Unpatched ({unpatched.Count})", Tone.Error), ("patched", $"Patched ({patched.Count})", Tone.Success) })
            {
                var pill = Ui.Pill(label, tone);
                pill.Cursor = Cursors.Hand; pill.Margin = new Thickness(0, 0, 6, 0); pill.BorderThickness = new Thickness(2);
                pill.BorderBrush = _cveFilter == key ? Ui.StatusBrush(tone) : System.Windows.Media.Brushes.Transparent;
                pill.MouseLeftButtonUp += (_, _) => { _cveFilter = _cveFilter == key && key != "all" ? "all" : key; rerender(); };
                badges.Children.Add(pill);
            }
        }

        var subtitle = "Windows Security Updates • " + (unpatched.Count > 0 ? $"{unpatched.Count} unpatched" : "All patched") + (patched.Count > 0 ? $" • {patched.Count} patched" : "");
        if (sec.SecurityReleaseInfo is { } rel && (!string.IsNullOrWhiteSpace(rel.OsBuild) || rel.ReleaseDate is not null))
            subtitle += $" • Build {Format.OrDash(rel.OsBuild)}" + (rel.ReleaseDate is null ? "" : $" released {Format.ShortDate(rel.ReleaseDate)}");
        UIElement body = shown.Count == 0
            ? Ui.EmptyState(_cveFilter == "patched" ? "No patched CVEs found" : "No unpatched vulnerabilities. This device has all available security updates installed.", "")
            : Table.Build(shown,
                Col.Link("CVE ID", "Cve", "Url", 170),
                Col.Text("OS Version", "OsVersion", 140),
                Col.Text("Patched In", "PatchedIn", 140),
                Col.Pill("Status", "Status", "StatusTone", 110),
                Col.Text("Installed", "Installed", 120),
                Col.Pill("Source", "Source", "SourceTone", 90));
        return Ui.TableCard("Common Vulnerabilities and Exposures", subtitle, body, badges);
    }

    // ── Detections ───────────────────────────────────────────────────

    private static UIElement DetectionsCard(SecurityData sec)
    {
        var detections = sec.Detections ?? [];
        var summary = sec.DetectionSummary;
        var rows = detections.Select(d => new DetectionRow(
            DeviceSnapshot.FirstNonEmpty(d.ThreatName) ?? "Unknown Threat",
            Format.OrUnknown(d.Severity), d.Severity?.ToLowerInvariant() switch { "severe" => Tone.Error, "high" => Tone.Orange, "moderate" => Tone.Warning, "low" => Tone.Info, _ => Tone.Neutral },
            Format.OrDash(d.Category), Format.OrUnknown(d.Status),
            d.Status?.ToLowerInvariant() switch { "cleaned" or "removed" or "quarantined" or "blocked" or "remediated" => Tone.Success, "allowed" or "missed" or "remediationfailed" => Tone.Error, _ => Tone.Warning },
            Format.OrUnknown(d.Source), d.DetectedAt is null ? "—" : Format.ShortDateTime(d.DetectedAt),
            d.ThreatId ?? "", d.FilePath ?? "", d.ProcessName ?? "", d.User ?? "", d.ActionTaken ?? "", d.Description ?? "", d.EventId > 0 ? d.EventId.ToString() : "")).ToList();

        var hasActive = summary?.HasActiveThreats == true;
        var subtitle = rows.Count > 0 ? $"{Format.Plural(rows.Count, "detection")} from AV/EDR products (last 30 days)" : "No threats detected in the last 30 days";
        var badges = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        if (rows.Count > 0 && summary is not null)
        {
            void B(string text, Tone tone) { var p = Ui.Pill(text, tone); p.Margin = new Thickness(0, 0, 6, 0); badges.Children.Add(p); }
            B($"{(summary.TotalDetections30d > 0 ? summary.TotalDetections30d : rows.Count)} total", hasActive ? Tone.Error : Tone.Neutral);
            if (summary.TotalBlocked30d > 0) B($"{summary.TotalBlocked30d} blocked", Tone.Success);
            if (summary.TotalCleaned30d > 0) B($"{summary.TotalCleaned30d} cleaned", Tone.Success);
            if (summary.TotalAllowed30d > 0) B($"{summary.TotalAllowed30d} allowed", Tone.Error);
        }

        UIElement body;
        if (rows.Count == 0) body = Ui.EmptyState("No Threats Detected. No malware, PUA, or security alerts in the last 30 days.", "");
        else
        {
            var grid = Table.Build(rows,
                Col.Text("Threat", "Threat", star: true),
                Col.Pill("Severity", "Severity", "SeverityTone", 100),
                Col.Text("Category", "Category", 130),
                Col.Pill("Status", "Status", "StatusTone", 120),
                Col.Text("Source", "Source", 140),
                Col.Text("Detected", "Detected", 150));
            grid.RowDetailsVisibilityMode = DataGridRowDetailsVisibilityMode.VisibleWhenSelected;
            grid.RowDetailsTemplate = DetailsTemplate();
            body = grid;
        }
        return Ui.TableCard("Threat Detections", subtitle, body, badges);
    }

    /// <summary>Selected-row details for a detection: rule id, path, process, user, action, details, event id.</summary>
    private static DataTemplate DetailsTemplate()
    {
        var panel = new FrameworkElementFactory(typeof(StackPanel));
        panel.SetValue(FrameworkElement.MarginProperty, new Thickness(20, 6, 20, 12));
        foreach (var (label, path) in new[] { ("Rule ID", "ThreatId"), ("Path", "Path"), ("Process", "Process"), ("User", "User"), ("Action", "Action"), ("Details", "Details"), ("Event ID", "EventId") })
        {
            var row = new FrameworkElementFactory(typeof(StackPanel));
            row.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
            row.SetBinding(UIElement.VisibilityProperty, new System.Windows.Data.Binding(path) { Converter = (System.Windows.Data.IValueConverter)Ui.Res("StringToVisibility") });
            var l = new FrameworkElementFactory(typeof(TextBlock));
            l.SetValue(TextBlock.TextProperty, label);
            l.SetValue(FrameworkElement.WidthProperty, 90.0);
            l.SetValue(TextBlock.FontSizeProperty, 11.5);
            l.SetValue(TextBlock.ForegroundProperty, Ui.Brush("TextSecondaryBrush"));
            row.AppendChild(l);
            var v = new FrameworkElementFactory(typeof(TextBlock));
            v.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding(path));
            v.SetValue(TextBlock.FontSizeProperty, 11.5);
            v.SetValue(TextBlock.TextWrappingProperty, TextWrapping.Wrap);
            v.SetValue(TextBlock.ForegroundProperty, Ui.Brush("TextPrimaryBrush"));
            v.SetValue(TextBlock.FontFamilyProperty, (System.Windows.Media.FontFamily)Ui.Res("MonoFont"));
            row.AppendChild(v);
            panel.AppendChild(row);
        }
        return new DataTemplate { VisualTree = panel };
    }
}
