using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>
/// Identity and users: the users, authentication and domains/tokens cards, then the
/// user accounts, active sessions, login history and session history tables.
/// </summary>
public sealed class IdentityTab : DeviceTab
{
    public override string Id => "identity";
    public override string Label => "Identity";
    public override string Glyph => "";
    public override Accent Accent => Accent.Indigo;
    public override string Description => "User accounts, sessions, and identity management";

    private static readonly string[] HiddenAccounts = ["wdagutilityaccount", "administrator", "defaultaccount", "guest"];

    private sealed record SessionRow(string User, string Type, string Host, string LoginTime, string LogonType, string State, Tone StateTone, string Pid);
    private sealed record HistoryRow(string User, string Event, Tone EventTone, string Time, string Duration, string LogonType, string Source);
    private sealed record SessionHistoryRow(string User, string Event, Tone EventTone, string Start, string End, string Duration, string Source);

    private string _table = "users";
    private string _userSearch = "";
    private bool _adminsOnly;
    private readonly HashSet<string> _expandedUsers = new(StringComparer.OrdinalIgnoreCase);

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("identity") || s.Identity is null) return ModuleMissing("identity");
        var id = s.Identity;
        var page = new StackPanel();
        void Add(UIElement e, double top = 24) { if (e is FrameworkElement fe && page.Children.Count > 0) fe.Margin = new Thickness(0, top, 0, 0); page.Children.Add(e); }

        var users = id.Users ?? [];
        var groups = id.Groups ?? [];
        var sessions = (id.LoggedInUsers ?? []).Where(u => !string.IsNullOrWhiteSpace(u.Username)).ToList();
        var loggedIn = sessions.Select(u => u.Username).Distinct(StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Cross-reference the Administrators group so domain and Entra admins are flagged too.
        var adminGroup = groups.FirstOrDefault(g => string.Equals(g.Name, "Administrators", StringComparison.OrdinalIgnoreCase) || g.Sid == "S-1-5-32-544");
        var adminNames = (adminGroup?.Members ?? []).Select(ShortName).Where(n => !n.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        bool IsAdmin(UserAccount u) => u.IsAdmin || adminNames.Contains(u.Username);
        List<string> Memberships(UserAccount u)
        {
            if (u.GroupMemberships is { Count: > 0 }) return u.GroupMemberships;
            return groups.Where(g => (g.Members ?? []).Any(m => string.Equals(ShortName(m), u.Username, StringComparison.OrdinalIgnoreCase))).Select(g => g.Name ?? "").Where(n => n.Length > 0).ToList();
        }

        var countBadge = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
        countBadge.Children.Add(Ui.Caption("User Accounts"));
        var count = Ui.Text(users.Count.ToString()); count.FontSize = 22; count.FontWeight = FontWeights.Bold; count.TextAlignment = TextAlignment.Right;
        countBadge.Children.Add(count);
        Add(Ui.TabHeader("Identity & Users", "Windows user accounts and sessions", Glyph, Accent, countBadge), 0);

        var summary = id.Summary;
        var grid = Ui.CardGrid(340, 20);
        grid.Children.Add(UsersCard(summary, users, IsAdmin));
        grid.Children.Add(AuthenticationCard(id, summary));
        grid.Children.Add(DomainsCard(s, id));
        Add(grid, 0);

        // Table tabs
        var host = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
        var visibleUsers = users.Where(u => !HiddenAccounts.Contains((u.Username ?? "").ToLowerInvariant())).ToList();
        void Render()
        {
            var options = new List<(string, string)>
            {
                ("users", $"User Accounts ({visibleUsers.Count})"),
                ("sessions", $"Active Sessions ({sessions.Count})"),
                ("history", $"Login History ({id.LoginHistory?.Count ?? 0})"),
            };
            if (id.SessionHistory is { Count: > 0 }) options.Add(("sessionHistory", $"Session History ({id.SessionHistory.Count})"));
            var panel = new StackPanel();
            var seg = Ui.Segmented(options, _table, key => { _table = key; Render(); });
            seg.Margin = new Thickness(0, 0, 0, 14);
            panel.Children.Add(seg);
            panel.Children.Add(_table switch
            {
                "sessions" => SessionsTable(sessions),
                "history" => HistoryTable(id.LoginHistory ?? []),
                "sessionHistory" => SessionHistoryTable(id),
                _ => UsersTable(visibleUsers, loggedIn, IsAdmin, Memberships, Render),
            });
            host.Content = panel;
        }
        Render();
        Add(host);
        return page;
    }

    private static string ShortName(string member)
    {
        var idx = member.LastIndexOf('\\');
        return (idx >= 0 ? member[(idx + 1)..] : member).Trim();
    }

    // ── Cards ────────────────────────────────────────────────────────

    private static Border CardShell(string glyph, string title, StackPanel body)
    {
        var head = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
        head.Children.Add(Ui.Icon(glyph, 16, Ui.Brush("TextSecondaryBrush")));
        var t = Ui.SectionHeader(title); t.Margin = new Thickness(8, 0, 0, 0); t.VerticalAlignment = VerticalAlignment.Center;
        head.Children.Add(t);
        var root = new StackPanel();
        root.Children.Add(head);
        root.Children.Add(body);
        return Ui.Card(root, new Thickness(20, 16, 20, 16));
    }

    private static Grid Detail(string label, string? value, Tone? tone = null)
        => Ui.Row(label, tone is null ? (UIElement)Value(value) : Ui.Status(Format.OrUnknown(value), tone.Value));

    private static TextBlock Value(string? value)
    {
        var t = Ui.Text(Format.OrUnknown(value)); t.Margin = new Thickness(0); t.FontWeight = FontWeights.Medium; t.TextAlignment = TextAlignment.Right; t.TextTrimming = TextTrimming.CharacterEllipsis; t.TextWrapping = TextWrapping.NoWrap; t.MaxWidth = 220; t.ToolTip = value;
        return t;
    }

    private static Border UsersCard(IdentitySummary? summary, List<UserAccount> users, Func<UserAccount, bool> isAdmin)
    {
        var total = summary?.TotalUsers > 0 ? summary.TotalUsers : users.Count;
        var admins = Math.Max(summary?.AdminUsers ?? 0, users.Count(isAdmin));
        var disabled = summary?.DisabledUsers > 0 ? summary.DisabledUsers : users.Count(u => u.IsDisabled);
        var body = new StackPanel();
        body.Children.Add(Detail("Total Users", total.ToString()));
        body.Children.Add(Detail("Admin Users", admins.ToString(), admins > 0 ? Tone.Warning : Tone.Success));
        body.Children.Add(Detail("Disabled", disabled.ToString(), disabled > 0 ? Tone.Neutral : Tone.Success));
        body.Children.Add(Detail("Local", (summary?.LocalUsers > 0 ? summary.LocalUsers : users.Count(u => u.IsLocal)).ToString()));
        body.Children.Add(Detail("Domain", (summary?.DomainUsers > 0 ? summary.DomainUsers : users.Count(u => !u.IsLocal)).ToString()));
        if (summary is not null) body.Children.Add(Detail("Currently Logged In", summary.CurrentlyLoggedIn.ToString()));
        return CardShell("", "Users", body);
    }

    private static Border AuthenticationCard(IdentityData id, IdentitySummary? summary)
    {
        var body = new StackPanel();
        var hello = id.WindowsHello;
        if (hello is not null)
        {
            var status = hello.StatusDisplay ?? "";
            var state = status.Contains("Enabled", StringComparison.OrdinalIgnoreCase) && !status.Contains("Partially", StringComparison.OrdinalIgnoreCase) ? "Enabled"
                : status.Contains("Partially", StringComparison.OrdinalIgnoreCase) ? "Partial" : "Disabled";
            body.Children.Add(Detail("Windows Hello", state, state == "Enabled" ? Tone.Success : state == "Partial" ? Tone.Warning : Tone.Neutral));
            if (hello.CredentialProviders is { } cp)
            {
                body.Children.Add(Detail("PIN", Format.EnabledDisabled(cp.PinEnabled), cp.PinEnabled ? Tone.Success : Tone.Neutral));
                body.Children.Add(Detail("Fingerprint", Format.EnabledDisabled(cp.FingerprintEnabled), cp.FingerprintEnabled ? Tone.Success : Tone.Neutral));
                body.Children.Add(Detail("Face Recognition", Format.EnabledDisabled(cp.FaceRecognitionEnabled), cp.FaceRecognitionEnabled ? Tone.Success : Tone.Neutral));
                if (cp.SmartCardEnabled) body.Children.Add(Detail("Smart Card", "Enabled", Tone.Success));
            }
            if (hello.CredentialGuard is { } cg) body.Children.Add(Detail("Credential Guard", Format.EnabledDisabled(cg.IsEnabled), cg.IsEnabled ? Tone.Success : Tone.Neutral));
            if (hello.BiometricService is { } bio && bio.Devices is { Count: > 0 })
                body.Children.Add(Detail("Biometric Devices", string.Join(", ", bio.Devices.Select(d => DeviceSnapshot.FirstNonEmpty(d.DeviceType, d.Model) ?? "Device"))));
        }
        else body.Children.Add(Detail("Windows Hello", "Not configured", Tone.Neutral));

        var tpm = id.TpmOwnership;
        if (tpm is not null && (tpm.IsOwned is not null || tpm.IsReady is not null))
            body.Children.Add(Detail("TPM", tpm.IsReady == true ? "Owned & Ready" : tpm.IsOwned == true ? "Owned" : "Not Owned", tpm.IsReady == true ? Tone.Success : tpm.IsOwned == true ? Tone.Warning : Tone.Neutral));
        var uac = id.Uac;
        if (!string.IsNullOrWhiteSpace(uac?.Level))
        {
            var label = uac.Level switch
            {
                "NeverNotify" => "Never Notify", "Disabled" => "Disabled", "NotifyChangesNoDim" => "Notify (no dim)",
                "NotifyChangesSecure" => "Notify on changes", "AlwaysNotify" => "Always Notify", _ => uac.Level,
            };
            body.Children.Add(Detail("UAC", label, uac.Level is "NeverNotify" or "Disabled" ? Tone.Error : uac.Level == "NotifyChangesNoDim" ? Tone.Warning : Tone.Success));
        }

        var pw = id.PasswordPolicy;
        var laps = id.Laps;
        var auto = id.AutoLogin;
        if (summary is not null || pw is not null || laps is not null || auto is not null)
        {
            body.Children.Add(Ui.Divider());
            var h = Ui.Eyebrow("Login Security"); h.Margin = new Thickness(0, 0, 0, 4);
            body.Children.Add(h);
            if (summary is not null)
            {
                var failed = summary.FailedLoginsLast7Days;
                body.Children.Add(Detail("Failed Logins (7d)", failed.ToString(), failed > 10 ? Tone.Error : failed > 5 ? Tone.Warning : Tone.Success));
            }
            if (pw is not null)
            {
                if (pw.MinPasswordLength is { } min) body.Children.Add(Detail("Min Password Length", min.ToString(), min == 0 ? Tone.Warning : min >= 8 ? Tone.Success : Tone.Neutral));
                if (pw.MaxPasswordAgeDays is { } max) body.Children.Add(Detail("Max Password Age", max == 0 ? "Never expires" : $"{max} days"));
                if (pw.LockoutThreshold is { } lt) body.Children.Add(Detail("Lockout Threshold", lt == 0 ? "No lockout" : $"{lt} attempts", lt == 0 ? Tone.Warning : Tone.Neutral));
                if (pw.ComplexityRequired is { } cx) body.Children.Add(Detail("Complexity", cx ? "Required" : "Not Required", cx ? Tone.Success : Tone.Neutral));
            }
            if (laps is not null)
                body.Children.Add(Detail("LAPS", laps.WindowsLapsConfigured ? "Windows LAPS" + (string.IsNullOrWhiteSpace(laps.BackupDirectory) ? "" : $" ({laps.BackupDirectory})") : laps.LegacyLapsInstalled ? "Legacy LAPS" : "Not Configured",
                    laps.WindowsLapsConfigured || laps.LegacyLapsInstalled ? Tone.Success : Tone.Neutral));
            if (auto is not null)
            {
                body.Children.Add(Detail("Auto Admin Logon", Format.EnabledDisabled(auto.AutoAdminLogon), auto.AutoAdminLogon ? Tone.Error : Tone.Success));
                if (auto.HasDefaultPassword) body.Children.Add(Detail("Stored Password", "Present", Tone.Error));
            }
        }
        return CardShell("", "Authentication", body);
    }

    private static Border DomainsCard(DeviceSnapshot s, IdentityData id)
    {
        var body = new StackPanel();
        var ds = id.DirectoryServices;
        var entra = ds?.EntraId;
        var ad = ds?.ActiveDirectory;
        var mgmt = s.Management;
        var entraJoined = entra?.IsEntraJoined ?? mgmt?.DeviceState?.EntraJoined ?? false;
        var domainJoined = ad?.IsDomainJoined ?? mgmt?.DeviceState?.DomainJoined ?? false;
        var registered = entra?.IsEntraRegistered ?? mgmt?.DeviceState?.EnterpriseJoined ?? false;
        var type = entraJoined && domainJoined ? "Hybrid Entra Join" : entraJoined ? "Entra Joined" : domainJoined ? "Domain Joined" : "Standalone";
        body.Children.Add(Detail("Type", type, entraJoined ? Tone.Success : Tone.Neutral));
        var domain = DeviceSnapshot.FirstNonEmpty(ad?.DomainName, id.DomainTrust?.DomainName);
        if (domainJoined && !string.IsNullOrWhiteSpace(domain)) body.Children.Add(Detail("Domain", domain));
        if (!entraJoined && !domainJoined && !string.IsNullOrWhiteSpace(ds?.Workgroup) && !ds.Workgroup.Equals("WORKGROUP", StringComparison.OrdinalIgnoreCase)) body.Children.Add(Detail("Workgroup", ds.Workgroup));
        var tenant = DeviceSnapshot.FirstNonEmpty(entra?.TenantName, mgmt?.TenantDetails?.TenantName);
        if (!string.IsNullOrWhiteSpace(tenant)) body.Children.Add(Detail("Tenant", tenant));
        if (!string.IsNullOrWhiteSpace(entra?.DeviceId)) body.Children.Add(Detail("Device ID", entra.DeviceId));
        if (!string.IsNullOrWhiteSpace(entra?.DeviceAuthStatus)) body.Children.Add(Detail("Device Auth", entra.DeviceAuthStatus, entra.DeviceAuthStatus == "SUCCESS" ? Tone.Success : Tone.Warning));
        if (registered && !entraJoined) body.Children.Add(Detail("Registration", "Registered (BYOD)", Tone.Neutral));
        if (!string.IsNullOrWhiteSpace(mgmt?.MdmEnrollment?.Provider)) body.Children.Add(Detail("MDM", mgmt.MdmEnrollment.Provider));
        if (entra?.JoinDate is not null) body.Children.Add(Detail("Joined", Format.ShortDate(entra.JoinDate)));

        var sso = id.SsoState;
        if (sso is not null)
        {
            body.Children.Add(Ui.Divider());
            body.Children.Add(Detail("Entra PRT", sso.EntraPrt ? "Active" : "Not Present", sso.EntraPrt ? Tone.Success : Tone.Warning));
            if (sso.EntraPrtExpiryTime is not null) body.Children.Add(Detail("PRT Expiry", Format.ShortDate(sso.EntraPrtExpiryTime)));
            body.Children.Add(Detail("Cloud TGT", sso.CloudTgt ? "Present" : "Not Present", sso.CloudTgt ? Tone.Success : Tone.Neutral));
            body.Children.Add(Detail("On-Prem TGT", sso.OnPremTgt ? "Present" : "Not Present", sso.OnPremTgt ? Tone.Success : Tone.Neutral));
        }
        var trust = id.DomainTrust;
        if (trust is not null && !string.IsNullOrWhiteSpace(trust.TrustStatus) && trust.TrustStatus != "Not Applicable")
        {
            body.Children.Add(Ui.Divider());
            body.Children.Add(Detail("Domain Trust", trust.TrustStatus, trust.TrustStatus == "Healthy" ? Tone.Success : trust.TrustStatus == "Broken" ? Tone.Error : Tone.Warning));
            if (!string.IsNullOrWhiteSpace(trust.DomainController) && trust.DomainController != "Unknown") body.Children.Add(Detail("DC", trust.DomainController));
        }
        var hello = id.WindowsHello;
        if (hello?.NgcKeyStorage?.IsConfigured == true)
        {
            body.Children.Add(Ui.Divider());
            body.Children.Add(Detail("NGC Key Storage", "Configured", Tone.Success));
            var providers = hello.NgcKeyStorage.Providers ?? [];
            if (providers.Count > 0)
                body.Children.Add(Detail("Providers", string.Join(", ", providers.Take(2).Select(p => DeviceSnapshot.FirstNonEmpty(p.Name, p.Type) ?? "")) + (providers.Count > 2 ? $" +{providers.Count - 2} more" : "")));
        }
        if (hello?.WebAuthN?.IsEnabled == true) body.Children.Add(Detail("WebAuthN / FIDO2", "Enabled", Tone.Success));
        if (body.Children.Count == 0) body.Children.Add(Detail("Status", "No data", Tone.Neutral));
        return CardShell("", "Domains & Tokens", body);
    }

    // ── Tables ───────────────────────────────────────────────────────

    private UIElement UsersTable(List<UserAccount> users, HashSet<string> loggedIn, Func<UserAccount, bool> isAdmin, Func<UserAccount, List<string>> memberships, Action rerender)
    {
        var q = _userSearch.Trim();
        var rows = users.Where(u => (q.Length == 0 || (u.Username ?? "").Contains(q, StringComparison.OrdinalIgnoreCase) || (u.FullName ?? "").Contains(q, StringComparison.OrdinalIgnoreCase)) && (!_adminsOnly || isAdmin(u)))
            .OrderByDescending(u => loggedIn.Contains(u.Username ?? "") ? 1 : 0)
            .ThenByDescending(u => u.LastLogon ?? DateTime.MinValue)
            .ThenBy(u => u.Username, StringComparer.OrdinalIgnoreCase).ToList();

        var controls = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        var admins = Ui.Pill("Admins", Tone.Warning);
        admins.Cursor = Cursors.Hand; admins.BorderThickness = new Thickness(2); admins.BorderBrush = _adminsOnly ? Ui.StatusBrush(Tone.Warning) : System.Windows.Media.Brushes.Transparent;
        admins.MouseLeftButtonUp += (_, _) => { _adminsOnly = !_adminsOnly; rerender(); };
        controls.Children.Add(admins);
        controls.Children.Add(new SearchBox("Search users...", s => { _userSearch = s; rerender(); }) { Text = _userSearch });

        var header = new Grid { Margin = new Thickness(20, 8, 20, 8) };
        foreach (var (h, w) in new[] { ("Display Name", 1.2), ("Admin", 0), ("Session", 0), ("Username", 1.0), ("Last Login", 0) })
            header.ColumnDefinitions.Add(new ColumnDefinition { Width = w > 0 ? new GridLength(w, GridUnitType.Star) : new GridLength(w == 0 && h == "Last Login" ? 170 : 100) });
        var i = 0;
        foreach (var h in new[] { "Display Name", "Admin", "Session", "Username", "Last Login" })
        {
            var t = new TextBlock { Text = h.ToUpperInvariant(), FontSize = 10.5, FontWeight = FontWeights.SemiBold, Foreground = Ui.Brush("TextSecondaryBrush") };
            Grid.SetColumn(t, i++); header.Children.Add(t);
        }
        var list = new StackPanel();
        list.Children.Add(new Border { Background = Ui.Brush("SubtleFillBrush"), BorderBrush = Ui.Brush("DividerBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = header });
        if (rows.Count == 0) list.Children.Add(Ui.EmptyState("No users found matching your criteria"));
        foreach (var u in rows)
        {
            var name = u.Username ?? "";
            var expanded = _expandedUsers.Contains(name);
            var g = new Grid { Margin = new Thickness(20, 9, 20, 9) };
            foreach (var col in header.ColumnDefinitions) g.ColumnDefinitions.Add(new ColumnDefinition { Width = col.Width });
            var dn = Ui.Text(Format.OrDash(u.FullName)); dn.Margin = new Thickness(0); dn.FontWeight = FontWeights.Medium; dn.TextTrimming = TextTrimming.CharacterEllipsis; dn.TextWrapping = TextWrapping.NoWrap;
            g.Children.Add(dn);
            var adminCell = isAdmin(u) ? Ui.Pill("Admin", Tone.Warning) : (UIElement)Ui.Caption("—");
            Grid.SetColumn(adminCell, 1); g.Children.Add(adminCell);
            var session = loggedIn.Contains(name) ? Ui.Pill("Active", Tone.Success) : (UIElement)Ui.Caption("—");
            Grid.SetColumn(session, 2); g.Children.Add(session);
            var un = new StackPanel { Orientation = Orientation.Horizontal };
            var unText = Ui.Mono(name); unText.Margin = new Thickness(0); unText.TextTrimming = TextTrimming.CharacterEllipsis; unText.TextWrapping = TextWrapping.NoWrap;
            un.Children.Add(unText);
            if (u.IsDisabled) { var d = Ui.Pill("Disabled", Tone.Neutral, 10.5); d.Margin = new Thickness(6, 0, 0, 0); un.Children.Add(d); }
            if (u.IsLockout) { var d = Ui.Pill("Locked", Tone.Error, 10.5); d.Margin = new Thickness(6, 0, 0, 0); un.Children.Add(d); }
            Grid.SetColumn(un, 3); g.Children.Add(un);
            var ll = new StackPanel { Orientation = Orientation.Horizontal };
            ll.Children.Add(Ui.Caption(u.LastLogon is null ? "Never" : Format.ShortDateTime(u.LastLogon)));
            var chevron = Ui.Icon(expanded ? "" : "", 10, Ui.Brush("TextSecondaryBrush")); chevron.Margin = new Thickness(8, 0, 0, 0);
            ll.Children.Add(chevron);
            Grid.SetColumn(ll, 4); g.Children.Add(ll);

            var row = new Border { Child = g, Cursor = Cursors.Hand, Background = System.Windows.Media.Brushes.Transparent };
            row.MouseLeftButtonUp += (_, _) => { if (!_expandedUsers.Remove(name)) _expandedUsers.Add(name); rerender(); };
            row.MouseEnter += (_, _) => row.Background = Ui.Brush("SubtleFillBrush");
            row.MouseLeave += (_, _) => row.Background = System.Windows.Media.Brushes.Transparent;
            var stack = new StackPanel();
            stack.Children.Add(row);
            if (expanded)
            {
                var account = new StackPanel();
                account.Children.Add(Ui.Eyebrow("Account Details"));
                account.Children.Add(Ui.Row("Username", name, mono: true, semibold: false));
                if (!string.IsNullOrWhiteSpace(u.Sid)) account.Children.Add(Ui.Row("SID", u.Sid, mono: true, semibold: false));
                if (!string.IsNullOrWhiteSpace(u.FullName)) account.Children.Add(Ui.Row("Full Name", u.FullName, semibold: false));
                if (!string.IsNullOrWhiteSpace(u.UserPrincipalName)) account.Children.Add(Ui.Row("UPN", u.UserPrincipalName, semibold: false));
                if (!string.IsNullOrWhiteSpace(u.HomeDirectory)) account.Children.Add(Ui.Row("Home", u.HomeDirectory, mono: true, semibold: false));
                if (!string.IsNullOrWhiteSpace(u.AccountType)) account.Children.Add(Ui.Row("Type", u.AccountType, semibold: false));
                if (!string.IsNullOrWhiteSpace(u.Description)) account.Children.Add(Ui.Row("Description", u.Description, semibold: false));
                var login = new StackPanel();
                login.Children.Add(Ui.Eyebrow("Login & Security"));
                login.Children.Add(Ui.Row("Last Login", u.LastLogon is null ? "Never" : Format.ShortDateTime(u.LastLogon), semibold: false));
                login.Children.Add(Ui.Row("Status", Ui.Status(u.IsDisabled ? "Disabled" : "Active", u.IsDisabled ? Tone.Neutral : Tone.Success)));
                login.Children.Add(Ui.Row("Admin", Ui.Status(isAdmin(u) ? "Yes" : "No", isAdmin(u) ? Tone.Warning : Tone.Neutral)));
                login.Children.Add(Ui.Row("Scope", u.IsLocal ? "Local" : "Domain / Entra", semibold: false));
                if (u.PasswordLastSet is not null) login.Children.Add(Ui.Row("Password Set", Format.ShortDateTime(u.PasswordLastSet), semibold: false));
                if (u.PasswordNeverExpires) login.Children.Add(Ui.Row("Password Expires", Ui.Status("Never", Tone.Warning)));
                if (u.AccountExpires is not null) login.Children.Add(Ui.Row("Account Expires", Format.ShortDate(u.AccountExpires), semibold: false));
                if (u.FailedLoginCount > 0) login.Children.Add(Ui.Row("Failed Logins", Ui.Status(u.FailedLoginCount.ToString(), Tone.Warning)));
                if (u.CreatedAt is not null) login.Children.Add(Ui.Row("Created", Format.ShortDate(u.CreatedAt), semibold: false));
                var groupsPanel = new StackPanel();
                groupsPanel.Children.Add(Ui.Eyebrow("Group Membership"));
                var members = memberships(u);
                if (members.Count == 0) groupsPanel.Children.Add(Ui.Caption("No group memberships"));
                else groupsPanel.Children.Add(Ui.Wrap(6, members.Select(m => (UIElement)Ui.Pill(m, Tone.Neutral, 11)).ToArray()));
                var details = Ui.Columns(3, 20, account, login, groupsPanel);
                stack.Children.Add(new Border { Padding = new Thickness(20, 4, 20, 16), Background = Ui.Brush("SubtleFillBrush"), Child = details });
            }
            list.Children.Add(new Border { BorderBrush = Ui.Brush("DividerBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = stack });
        }
        return Ui.TableCard("User Accounts", $"{rows.Count} of {users.Count} accounts", list, controls);
    }

    private static UIElement SessionsTable(List<LoggedInUser> sessions)
    {
        var rows = sessions.Select(x => new SessionRow(
            string.IsNullOrWhiteSpace(x.Domain) ? x.Username ?? "" : $"{x.Domain}\\{x.Username}", Format.OrDash(x.SessionType), DeviceSnapshot.FirstNonEmpty(x.Host) ?? "localhost",
            x.LoginTime is null ? "—" : Format.ShortDateTime(x.LoginTime), Format.OrDash(x.LogonType),
            Format.OrDash(x.SessionState), x.IsActive || string.Equals(x.SessionState, "Active", StringComparison.OrdinalIgnoreCase) ? Tone.Success : Tone.Neutral,
            x.Pid is { } pid ? pid.ToString() : x.SessionId > 0 ? $"session {x.SessionId}" : "—")).ToList();
        return Table.Card("Active Sessions", "Currently logged-in user sessions", rows, null, "No active sessions",
            Col.Text("User", "User", star: true, mono: true), Col.Text("Type", "Type", 110), Col.Text("Host", "Host", 140), Col.Text("Login Time", "LoginTime", 160), Col.Text("Logon Type", "LogonType", 130), Col.Pill("State", "State", "StateTone", 100), Col.Text("PID", "Pid", 90));
    }

    private static UIElement HistoryTable(List<LoginHistoryEntry> history)
    {
        var rows = history.OrderByDescending(e => e.Timestamp).Select(e =>
        {
            var kind = e.EventType ?? (e.Success ? "Logon" : "Failed");
            var tone = kind.Equals("Failed", StringComparison.OrdinalIgnoreCase) || !e.Success && kind.Equals("Logon", StringComparison.OrdinalIgnoreCase) ? Tone.Error
                : kind.Equals("Logoff", StringComparison.OrdinalIgnoreCase) ? Tone.Neutral : Tone.Success;
            return new HistoryRow(e.Username ?? "", kind, tone, e.Timestamp == default ? "—" : Format.ShortDateTime(e.Timestamp), Format.OrDash(e.Duration), Format.OrDash(e.LogonType), DeviceSnapshot.FirstNonEmpty(e.SourceIp, e.Source) ?? "—");
        }).ToList();
        return Table.Card("Login History", "Recent authentication events", rows, null, "No login history available",
            Col.Text("User", "User", star: true, mono: true), Col.Pill("Event", "Event", "EventTone", 100), Col.Text("Time", "Time", 160), Col.Text("Duration", "Duration", 110), Col.Text("Type", "LogonType", 120), Col.Text("Source", "Source", 150));
    }

    private static UIElement SessionHistoryTable(IdentityData id)
    {
        var panel = new StackPanel();
        if (id.SessionSummary is { } ss)
        {
            static string Mins(double m) => m > 60 ? $"{m / 60:F1}h" : $"{Math.Round(m)}m";
            var stats = Ui.Columns(4, 12,
                Ui.Metric(ss.TotalSessions.ToString(), "Total Sessions"),
                Ui.Metric(ss.UniqueUsers.ToString(), "Unique Users"),
                Ui.Metric(Mins(ss.AvgSessionMinutes), "Avg Duration"),
                Ui.Metric(Mins(ss.MedianSessionMinutes), "Median Duration"));
            panel.Children.Add(stats);
            if (ss.SessionsByHour is { Count: > 0 })
            {
                var peaks = Ui.Wrap(6, ss.SessionsByHour.OrderByDescending(kv => kv.Value).Take(5).Select(kv => (UIElement)Ui.Pill($"{kv.Key}:00 ({kv.Value})", Tone.Info)).ToArray());
                var box = new StackPanel { Margin = new Thickness(0, 12, 0, 0) };
                box.Children.Add(Ui.Eyebrow("Peak Hours"));
                peaks.Margin = new Thickness(0, 4, 0, 0);
                box.Children.Add(peaks);
                panel.Children.Add(Ui.Card(box, new Thickness(20, 12, 20, 8)));
            }
            panel.Children[^1].SetValue(FrameworkElement.MarginProperty, new Thickness(0, panel.Children.Count > 1 ? 12 : 0, 0, 16));
        }
        var rows = (id.SessionHistory ?? []).OrderByDescending(e => e.Timestamp).Select(e =>
        {
            var kind = e.EventType ?? "Logon";
            var tone = kind is "Logoff" or "Disconnect" ? Tone.Neutral : kind == "Active" ? Tone.Success : kind == "Reconnect" ? Tone.Info : Tone.Success;
            var duration = !string.IsNullOrWhiteSpace(e.Duration) ? e.Duration : e.DurationMinutes > 60 ? $"{e.DurationMinutes / 60:F1}h" : e.DurationMinutes > 0 ? $"{Math.Round(e.DurationMinutes)}m" : "—";
            return new SessionHistoryRow(e.Username ?? "", kind, tone, e.Timestamp == default ? "—" : Format.ShortDateTime(e.Timestamp), e.EndTime is null ? (kind == "Active" ? "Active" : "—") : Format.ShortDateTime(e.EndTime), duration, Format.OrDash(e.SourceAddress));
        }).ToList();
        panel.Children.Add(Table.Card("Session History", "Terminal Services session events", rows, null, "No session history available",
            Col.Text("User", "User", star: true, mono: true), Col.Pill("Event", "Event", "EventTone", 110), Col.Text("Start", "Start", 160), Col.Text("End", "End", 160), Col.Text("Duration", "Duration", 100), Col.Text("Source", "Source", 150)));
        return panel;
    }
}
