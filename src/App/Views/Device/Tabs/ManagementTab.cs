using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Tabs;

/// <summary>
/// Device Management Service: enrollment, Autopilot, device details, domain trust,
/// the Entra device certificate, the management-tool log roots, and the
/// configuration profiles (policy branches) with their payloads.
/// </summary>
public sealed class ManagementTab : DeviceTab
{
    public override string Id => "management";
    public override string Label => "Management";
    public override string Glyph => "";
    public override Accent Accent => Accent.Yellow;
    public override string Description => "Device management, enrollment, and configuration profiles";

    private readonly HashSet<string> _expandedProfiles = new(StringComparer.OrdinalIgnoreCase);
    private string _profileSearch = "";
    private string? _activeLogTool;
    private readonly Dictionary<string, string> _selectedLogFile = new(StringComparer.OrdinalIgnoreCase);
    private string _logFilter = "";
    private bool _logsExpanded;

    protected override UIElement Build(DeviceSnapshot s)
    {
        if (!s.HasModule("management") || s.Management is null) return ModuleMissing("management", s);
        var m = s.Management;
        var page = new StackPanel();
        void Add(UIElement e, double top = 24) { if (e is FrameworkElement fe && page.Children.Count > 0) fe.Margin = new Thickness(0, top, 0, 0); page.Children.Add(e); }

        var enrollment = m.MdmEnrollment;
        var isEnrolled = enrollment?.IsEnrolled == true;
        var serverUrl = DeviceSnapshot.FirstNonEmpty(enrollment?.ServerUrl, enrollment?.ManagementUrl, m.TenantDetails?.MdmUrl);
        var provider = Widgets.ManagementWidget.DetectProvider(serverUrl) ?? DeviceSnapshot.FirstNonEmpty(enrollment?.Provider);

        UIElement? right = null;
        if (!string.IsNullOrWhiteSpace(provider))
        {
            var p = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right };
            p.Children.Add(Ui.Caption("Provider"));
            var v = Ui.Text(provider); v.FontSize = 16; v.FontWeight = FontWeights.SemiBold; v.TextAlignment = TextAlignment.Right;
            p.Children.Add(v);
            right = p;
        }
        Add(Ui.TabHeader("Device Management Service", "Enrollment, Policies, and Identity Status", Glyph, Accent, right), 0);

        // Top row: enrollment (60%) and certificate (40%)
        var layout = new Grid();
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(20) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
        layout.Children.Add(EnrollmentCard(s, m, isEnrolled, serverUrl));
        var cert = CertificateCard(m, isEnrolled);
        Grid.SetColumn(cert, 2);
        layout.Children.Add(cert);
        Add(layout, 0);

        // Management logs
        if (m.Logs?.Roots is { Count: > 0 })
        {
            var host = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
            void Render() => host.Content = LogsCard(m.Logs, Render);
            Render();
            Add(host);
        }

        // Configuration profiles
        var profiles = m.ConfigurationProfiles ?? [];
        if (profiles.Count > 0)
        {
            var host = new ContentControl { HorizontalContentAlignment = HorizontalAlignment.Stretch };
            void Render() => host.Content = ProfilesCard(profiles, Render);
            Render();
            Add(host);
        }

        // Policy inventory tables the web folds into the profiles section
        if (m.IntunePolicies is { Count: > 0 } intune)
        {
            var rows = intune.Select(p => new PolicyRow(DeviceSnapshot.FirstNonEmpty(p.PolicyName, p.PolicyId) ?? "", p.PolicyType ?? "", p.Platform ?? "", Format.OrDash(p.Status), p.Settings?.Count ?? 0, p.LastSync is null ? "—" : Format.RelativeTime(p.LastSync))).ToList();
            Add(Table.Card("Intune Policies", $"{Format.Plural(rows.Count, "policy").Replace("policys", "policies")} assigned by the MDM channel", rows, null, "",
                Col.Text("Policy", "Name", star: true), Col.Text("Type", "Type", 160), Col.Text("Platform", "Platform", 110), Col.Text("Status", "Status", 110), Col.Text("Settings", "SettingCount", 80), Col.Text("Last Sync", "LastSync", 130)));
        }
        if (m.CompliancePolicies is { Count: > 0 } compliance)
        {
            var rows = compliance.Select(p => new ComplianceRow(DeviceSnapshot.FirstNonEmpty(p.PolicyName, p.PolicyId) ?? "", p.ComplianceType ?? "", Format.OrDash(p.RequiredValue), Format.OrDash(p.CurrentValue),
                p.IsCompliant ? "Compliant" : "Non-compliant", p.IsCompliant ? Tone.Success : Tone.Error, p.LastEvaluated is null ? "—" : Format.RelativeTime(p.LastEvaluated))).ToList();
            Add(Table.Card("Compliance Policies", "Security and health requirements evaluated on this device", rows, null, "",
                Col.Text("Policy", "Name", star: true), Col.Text("Type", "Type", 140), Col.Text("Required", "Required", 140), Col.Text("Current", "Current", 140), Col.Pill("Status", "Status", "StatusTone", 130), Col.Text("Evaluated", "Evaluated", 120)));
        }
        if (m.ManagedApps is { Count: > 0 } apps)
        {
            var rows = apps.Select(a => new ManagedAppRow(a.Name ?? "", a.Version ?? "", a.AppType ?? "", Format.OrDash(a.InstallState), a.InstallState?.ToLowerInvariant() is "installed" or "success" ? Tone.Success : a.InstallState?.ToLowerInvariant() is "failed" or "error" ? Tone.Error : Tone.Neutral,
                Format.OrDash(a.TargetType), a.LastInstallAttempt is null ? "—" : Format.RelativeTime(a.LastInstallAttempt))).ToList();
            Add(Table.Card("Managed Apps", "Apps deployed via MDM", rows, null, "",
                Col.Text("App", "Name", star: true), Col.Text("Version", "Version", 120), Col.Text("Type", "Type", 120), Col.Pill("State", "State", "StateTone", 120), Col.Text("Target", "Target", 100), Col.Text("Last Attempt", "LastAttempt", 130)));
        }
        return page;
    }

    private sealed record PolicyRow(string Name, string Type, string Platform, string Status, int SettingCount, string LastSync);
    private sealed record ComplianceRow(string Name, string Type, string Required, string Current, string Status, Tone StatusTone, string Evaluated);
    private sealed record ManagedAppRow(string Name, string Version, string Type, string State, Tone StateTone, string Target, string LastAttempt);

    // ── Enrollment ───────────────────────────────────────────────────

    private static Border EnrollmentCard(DeviceSnapshot s, ManagementData m, bool isEnrolled, string? serverUrl)
    {
        var body = new StackPanel();
        body.Children.Add(Ui.SectionHeader("Enrollment"));
        body.Children.Add(Ui.Spacer(6));
        body.Children.Add(Ui.Row("Enrollment Status", Ui.Pill(isEnrolled ? "Enrolled" : "Not Enrolled", isEnrolled ? Tone.Success : Tone.Error)));
        var type = Widgets.ManagementWidget.EnrollmentType(m) ?? m.DeviceState?.Status;
        if (!string.IsNullOrWhiteSpace(type))
            body.Children.Add(Ui.Row("Enrollment Type", Ui.Pill(type, type == "Domain Joined" ? Tone.Warning : Tone.Success)));
        var auth = m.DeviceDetails?.DeviceAuthStatus;
        if (!string.IsNullOrWhiteSpace(auth))
            body.Children.Add(Ui.Row("Device Authentication", Ui.Pill(auth == "SUCCESS" ? "Success" : auth, auth == "SUCCESS" ? Tone.Success : Tone.Error)));

        var ap = m.AutopilotConfig;
        if (isEnrolled && ap is not null && (ap.Activated || ap.Registered || ap.CloudAssigned || !string.IsNullOrWhiteSpace(ap.ProfileName) || !string.IsNullOrWhiteSpace(ap.Status)))
        {
            body.Children.Add(Ui.Spacer(14));
            body.Children.Add(Ui.SectionHeader("Windows Autopilot"));
            body.Children.Add(Ui.Spacer(6));
            body.Children.Add(Ui.Columns(2, 16,
                Ui.VStack(
                    Ui.Row("Registered", Ui.Pill(Format.YesNo(ap.Registered), ap.Registered ? Tone.Success : Tone.Neutral)),
                    Ui.Row("Activated", Ui.Pill(Format.YesNo(ap.Activated), ap.Activated ? Tone.Success : Tone.Neutral))),
                Ui.VStack(
                    Ui.Row("Cloud Assigned", Ui.Pill(Format.YesNo(ap.CloudAssigned), ap.CloudAssigned ? Tone.Success : Tone.Neutral)),
                    !string.IsNullOrWhiteSpace(ap.Status) ? Ui.Row("Status", Ui.Pill(ap.Status, ap.Status.Contains("Complete", StringComparison.OrdinalIgnoreCase) ? Tone.Success : Tone.Warning)) : Ui.Spacer(0))));
            var details = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
            if (!string.IsNullOrWhiteSpace(ap.ProfileName)) details.Children.Add(Ui.Row("Profile", ap.ProfileName, semibold: false));
            if (!string.IsNullOrWhiteSpace(ap.TenantDomain)) details.Children.Add(Ui.Row("Tenant", ap.TenantDomain, semibold: false));
            if (!string.IsNullOrWhiteSpace(ap.TenantId)) details.Children.Add(Ui.Row("Tenant ID", CopyValue(ap.TenantId)));
            if (!string.IsNullOrWhiteSpace(ap.DeploymentMode)) details.Children.Add(Ui.Row("Mode", ap.DeploymentMode, semibold: false));
            if (!string.IsNullOrWhiteSpace(ap.StatusDetail)) details.Children.Add(Ui.Row("Detail", ap.StatusDetail, semibold: false));
            if (!string.IsNullOrWhiteSpace(ap.PolicyDate)) details.Children.Add(Ui.Row("Policy Date", ap.PolicyDate, semibold: false));
            if (ap.ForcedEnrollment) details.Children.Add(Ui.Row("Forced Enrollment", Ui.Pill("Yes", Tone.Info)));
            if (details.Children.Count > 0) body.Children.Add(details);
        }

        var dd = m.DeviceDetails;
        var enrolledBy = StripTenant(m.MdmEnrollment?.UserPrincipalName);
        var primaryUser = StripTenant(dd?.PrimaryUser);
        var showPrimary = !string.IsNullOrWhiteSpace(primaryUser) && !string.Equals(primaryUser, enrolledBy, StringComparison.OrdinalIgnoreCase);
        if (isEnrolled && (dd is not null || m.LastSync is not null) && (!string.IsNullOrWhiteSpace(dd?.ManagementName) || showPrimary || !string.IsNullOrWhiteSpace(enrolledBy) || !string.IsNullOrWhiteSpace(dd?.IntuneDeviceId) || !string.IsNullOrWhiteSpace(dd?.EntraObjectId) || m.LastSync is not null))
        {
            body.Children.Add(Ui.Spacer(14));
            body.Children.Add(Ui.SectionHeader("Device Details"));
            body.Children.Add(Ui.Spacer(6));
            if (!string.IsNullOrWhiteSpace(dd?.ManagementName)) body.Children.Add(Ui.Row("Management Name", dd.ManagementName, semibold: false));
            if (showPrimary) body.Children.Add(Ui.Row("Primary User", CopyValue(primaryUser!)));
            if (!string.IsNullOrWhiteSpace(enrolledBy)) body.Children.Add(Ui.Row("Enrolled By", CopyValue(enrolledBy)));
            if (!string.IsNullOrWhiteSpace(dd?.IntuneDeviceId)) body.Children.Add(Ui.Row("Intune ID", CopyValue(dd.IntuneDeviceId, mono: true)));
            if (!string.IsNullOrWhiteSpace(dd?.EntraObjectId)) body.Children.Add(Ui.Row("Object ID", CopyValue(dd.EntraObjectId, mono: true)));
            if (!string.IsNullOrWhiteSpace(dd?.DeviceId)) body.Children.Add(Ui.Row("Device ID", CopyValue(dd.DeviceId, mono: true)));
            if (m.LastSync is not null) body.Children.Add(Ui.Row("Last Sync", Format.ShortDateTime(m.LastSync), semibold: false));
            if (!string.IsNullOrWhiteSpace(m.OwnershipType)) body.Children.Add(Ui.Row("Ownership", m.OwnershipType, semibold: false));
        }

        var trust = s.Identity?.DomainTrust;
        if (type == "Domain Joined" && trust is not null && (!string.IsNullOrWhiteSpace(trust.DomainName) || !string.IsNullOrWhiteSpace(trust.TrustStatus)))
        {
            body.Children.Add(Ui.Spacer(14));
            body.Children.Add(Ui.SectionHeader("Domain Trust Status"));
            body.Children.Add(Ui.Spacer(6));
            body.Children.Add(Ui.Row("Secure Channel", Ui.Pill(trust.SecureChannelValid ? "Valid" : "Invalid", trust.SecureChannelValid ? Tone.Success : Tone.Error)));
            if (!string.IsNullOrWhiteSpace(trust.DomainName)) body.Children.Add(Ui.Row("Domain", trust.DomainName, semibold: false));
            if (!string.IsNullOrWhiteSpace(trust.DomainController)) body.Children.Add(Ui.Row("Domain Controller", trust.DomainController, semibold: false));
            if (!string.IsNullOrWhiteSpace(trust.TrustStatus)) body.Children.Add(Ui.Row("Trust Status", Ui.Pill(trust.TrustStatus, trust.TrustStatus is "Healthy" or "Success" or "Trusted" ? Tone.Success : Tone.Error)));
            if (trust.MachinePasswordAgeDays is { } age) body.Children.Add(Ui.Row("Password Age", Ui.Status($"{age} days", age > 30 ? Tone.Warning : Tone.Neutral)));
            if (trust.LastChecked is not null) body.Children.Add(Ui.Row("Last Checked", Format.ShortDate(trust.LastChecked), semibold: false));
            if (!string.IsNullOrWhiteSpace(trust.ErrorMessage)) body.Children.Add(Ui.Status(trust.ErrorMessage, Tone.Error, 12, FontWeights.Normal));
        }

        var ss = s.Identity?.SsoState;
        if (ss is not null && (ss.EntraPrt || ss.EnterprisePrt || ss.OnPremTgt || ss.CloudTgt))
        {
            body.Children.Add(Ui.Spacer(14));
            body.Children.Add(Ui.SectionHeader("Single Sign-On State"));
            body.Children.Add(Ui.Spacer(6));
            body.Children.Add(Ui.Row("Entra PRT", Ui.Pill(ss.EntraPrt ? "Present" : "Absent", ss.EntraPrt ? Tone.Success : Tone.Neutral)));
            if (ss.EntraPrtExpiryTime is not null) body.Children.Add(Ui.Row("PRT Expires", Format.ShortDateTime(ss.EntraPrtExpiryTime), semibold: false));
            if (ss.EntraPrtUpdateTime is not null) body.Children.Add(Ui.Row("PRT Updated", Format.RelativeTime(ss.EntraPrtUpdateTime), semibold: false));
            body.Children.Add(Ui.Row("Enterprise PRT", Ui.Pill(ss.EnterprisePrt ? "Present" : "Absent", ss.EnterprisePrt ? Tone.Success : Tone.Neutral)));
            body.Children.Add(Ui.Row("On-prem TGT", Ui.Pill(ss.OnPremTgt ? "Present" : "Absent", ss.OnPremTgt ? Tone.Success : Tone.Neutral)));
            body.Children.Add(Ui.Row("Cloud TGT", Ui.Pill(ss.CloudTgt ? "Present" : "Absent", ss.CloudTgt ? Tone.Success : Tone.Neutral)));
        }

        if (!string.IsNullOrWhiteSpace(m.MdmEnrollment?.ManagementUrl))
        {
            body.Children.Add(Ui.Spacer(14));
            body.Children.Add(Ui.Stat("Management URL", m.MdmEnrollment.ManagementUrl, mono: true, copy: true, truncate: true));
        }
        else if (!string.IsNullOrWhiteSpace(serverUrl))
        {
            body.Children.Add(Ui.Spacer(14));
            body.Children.Add(Ui.Stat("Server URL", serverUrl, mono: true, copy: true, truncate: true));
        }
        return Ui.Card(body, new Thickness(20, 16, 20, 18));
    }

    private static FrameworkElement CopyValue(string value, bool mono = false)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        var t = mono ? Ui.Mono(value) : Ui.Text(value);
        t.Margin = new Thickness(0); t.FontWeight = FontWeights.SemiBold; t.TextTrimming = TextTrimming.CharacterEllipsis; t.TextWrapping = TextWrapping.NoWrap; t.MaxWidth = 280; t.ToolTip = value;
        panel.Children.Add(t);
        panel.Children.Add(Ui.CopyButton(value));
        return panel;
    }

    /// <summary>Windows reports the enrolling account as user@domain@tenant-guid; the tenant is shown elsewhere.</summary>
    private static string? StripTenant(string? upn)
    {
        if (string.IsNullOrWhiteSpace(upn)) return upn;
        var m = Regex.Match(upn, @"^(.+)@[0-9a-fA-F-]{36}$");
        return m.Success ? m.Groups[1].Value : upn;
    }

    // ── Certificate ──────────────────────────────────────────────────

    private static Border CertificateCard(ManagementData m, bool isEnrolled)
    {
        var tenant = DeviceSnapshot.FirstNonEmpty(m.TenantDetails?.TenantName);
        var dd = m.DeviceDetails;
        var profileCount = m.ConfigurationProfiles?.Count ?? 0;
        var complianceCount = m.CompliancePolicies?.Count ?? 0;
        var appCount = m.ManagedApps?.Count ?? 0;
        var body = new StackPanel();

        if (isEnrolled && !string.IsNullOrWhiteSpace(tenant))
        {
            var head = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
            var tile = new Border { Width = 40, Height = 40, CornerRadius = new CornerRadius(8), Background = Ui.Brush("IconYellowBackground"), Child = Ui.Icon("", 18, Ui.Brush("IconYellowForeground")), Margin = new Thickness(0, 0, 12, 0) };
            ((FrameworkElement)tile.Child).HorizontalAlignment = HorizontalAlignment.Center;
            head.Children.Add(tile);
            var titles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            titles.Children.Add(Ui.Text("Certificate", "TitleTextStyle"));
            titles.Children.Add(Ui.Text("Entra ID authentication credential", "SubtitleTextStyle"));
            head.Children.Add(titles);
            body.Children.Add(head);

            body.Children.Add(Ui.Stat("Organization", tenant));
            body.Children.Add(Ui.Spacer(10));
            var validity = dd?.DeviceCertificateValidity;
            if (!string.IsNullOrWhiteSpace(validity))
            {
                var (label, tone) = CertificateValidity(validity);
                var st = Ui.Stat("Valid Until", label);
                if (st is StackPanel sp && sp.Children.Count > 1 && sp.Children[1] is TextBlock vt) vt.Foreground = Ui.StatusBrush(tone);
                body.Children.Add(st);
                body.Children.Add(Ui.Spacer(10));
            }
            if (!string.IsNullOrWhiteSpace(dd?.Thumbprint)) { body.Children.Add(Ui.Stat("Thumbprint", dd.Thumbprint, mono: true, copy: true, truncate: true)); body.Children.Add(Ui.Spacer(10)); }
            if (!string.IsNullOrWhiteSpace(dd?.KeyContainerId)) { body.Children.Add(Ui.Stat("Key Container ID", dd.KeyContainerId, mono: true, copy: true, truncate: true)); body.Children.Add(Ui.Spacer(10)); }
            if (!string.IsNullOrWhiteSpace(dd?.KeyProvider)) { body.Children.Add(Ui.Stat("Key Provider", dd.KeyProvider)); body.Children.Add(Ui.Spacer(10)); }
            if (dd is not null) body.Children.Add(Ui.Row("TPM Protected", Ui.Pill(Format.YesNo(dd.TmpProtected), dd.TmpProtected ? Tone.Success : Tone.Warning)));
            if (!string.IsNullOrWhiteSpace(m.TenantDetails?.TenantId)) { body.Children.Add(Ui.Spacer(6)); body.Children.Add(Ui.Stat("Tenant ID", m.TenantDetails.TenantId, mono: true, copy: true, truncate: true)); }
            body.Children.Add(Ui.Divider());
            body.Children.Add(Ui.Row("Configuration Profiles", profileCount.ToString()));
            if (complianceCount > 0) body.Children.Add(Ui.Row("Compliance Policies", complianceCount.ToString()));
            if (appCount > 0) body.Children.Add(Ui.Row("Managed Apps", appCount.ToString()));
        }
        else
        {
            body.Children.Add(Ui.SectionHeader("Management Resources"));
            body.Children.Add(Ui.Spacer(10));
            body.Children.Add(Ui.Columns(3, 10,
                Ui.Metric(profileCount.ToString(), "Configuration Profiles"),
                Ui.Metric(complianceCount.ToString(), "Compliance Policies"),
                Ui.Metric(appCount.ToString(), "Managed Apps")));
            body.Children.Add(Ui.Spacer(10));
            body.Children.Add(complianceCount > 0
                ? Ui.Row("Compliance Policies", Ui.Pill($"{complianceCount} applied", Tone.Success))
                : Ui.Row("Compliance", Ui.Pill("No policies applied", Tone.Neutral)));
            if (!isEnrolled) body.Children.Add(Ui.Caption("This device is not enrolled in an MDM service."));
        }
        return Ui.Card(body, new Thickness(20, 16, 20, 18));
    }

    /// <summary>"[ 2025-03-25 22:47:56.000 UTC -- 2035-03-25 23:17:56.000 UTC ]" to its end date and a tone by remaining days.</summary>
    private static (string Label, Tone Tone) CertificateValidity(string validity)
    {
        var m = Regex.Match(validity, @"--\s*(\d{4}-\d{2}-\d{2})");
        if (!m.Success || !DateTime.TryParse(m.Groups[1].Value, out var end)) return ("Unknown", Tone.Neutral);
        var days = (end - DateTime.Now).TotalDays;
        return (Format.ShortDate(end), days < 0 ? Tone.Error : days < 30 ? Tone.Warning : Tone.Success);
    }

    // ── Logs ─────────────────────────────────────────────────────────

    private static readonly Dictionary<string, string> ProductNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["installs"] = "Cimian", ["bootstrap"] = "BootstrapMate", ["reports"] = "ReportMate", ["state"] = "StartSet",
        ["encryption"] = "Crypt Escrow", ["users"] = "ManageUsers", ["utilities"] = "Utilities",
    };

    private static string ProductName(LogRoot root)
    {
        if (ProductNames.TryGetValue(root.Tool ?? "", out var name)) return name;
        var stripped = Regex.Replace(root.Name ?? "", "^Managed\\s*", "", RegexOptions.IgnoreCase).Trim();
        return stripped.Length > 0 ? stripped : Format.Capitalize(root.Tool);
    }

    private UIElement LogsCard(ManagementLogs logs, Action rerender)
    {
        var roots = logs.Roots ?? [];
        var totalErrors = roots.Sum(r => r.ErrorCount);
        var totalWarnings = roots.Sum(r => r.WarningCount);
        _activeLogTool ??= roots[0].Tool;
        var active = roots.FirstOrDefault(r => r.Tool == _activeLogTool) ?? roots[0];

        var header = new Grid { Margin = new Thickness(20, 12, 20, 12), Cursor = Cursors.Hand, Background = System.Windows.Media.Brushes.Transparent };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var left = new StackPanel { Orientation = Orientation.Horizontal };
        left.Children.Add(Ui.Icon(_logsExpanded ? "" : "", 11, Ui.Brush("TextSecondaryBrush")));
        var title = Ui.Text("Management Logs", "TitleTextStyle"); title.Margin = new Thickness(10, 0, 0, 0);
        left.Children.Add(title);
        if (!_logsExpanded)
            foreach (var r in roots)
            {
                var chip = Ui.Pill(ProductName(r), r.ErrorCount > 0 ? Tone.Error : r.WarningCount > 0 ? Tone.Warning : Tone.Neutral);
                chip.Margin = new Thickness(8, 0, 0, 0);
                left.Children.Add(chip);
            }
        header.Children.Add(left);
        var rightPanel = new StackPanel { Orientation = Orientation.Horizontal };
        if (totalErrors > 0) { var p = Ui.Pill($"{totalErrors} errors", Tone.Error); p.Margin = new Thickness(6, 0, 0, 0); rightPanel.Children.Add(p); }
        if (totalWarnings > 0) { var p = Ui.Pill($"{totalWarnings} warnings", Tone.Warning); p.Margin = new Thickness(6, 0, 0, 0); rightPanel.Children.Add(p); }
        Grid.SetColumn(rightPanel, 1);
        header.Children.Add(rightPanel);
        header.MouseLeftButtonUp += (_, _) => { _logsExpanded = !_logsExpanded; rerender(); };

        var root = new StackPanel();
        root.Children.Add(header);
        if (!_logsExpanded) return new Border { Style = (Style)Ui.Res("CardStyle"), Child = root };

        root.Children.Add(new Border { Height = 1, Background = Ui.Brush("DividerBrush") });
        var body = new StackPanel { Margin = new Thickness(20, 14, 20, 18) };

        // Tool tabs
        var tabs = new WrapPanel();
        foreach (var r in roots)
        {
            var isActive = r.Tool == active.Tool;
            var content = new StackPanel { Orientation = Orientation.Horizontal };
            content.Children.Add(new TextBlock { Text = ProductName(r), FontSize = 12.5, FontWeight = FontWeights.Medium, VerticalAlignment = VerticalAlignment.Center,
                Foreground = isActive ? Ui.Brush("CardBackgroundBrush") : Ui.Brush("TextPrimaryBrush") });
            if (r.ErrorCount > 0) { var p = Ui.Pill(r.ErrorCount.ToString(), Tone.Error, 10.5); p.Margin = new Thickness(6, 0, 0, 0); content.Children.Add(p); }
            if (r.WarningCount > 0) { var p = Ui.Pill(r.WarningCount.ToString(), Tone.Warning, 10.5); p.Margin = new Thickness(6, 0, 0, 0); content.Children.Add(p); }
            var tab = new Border
            {
                Padding = new Thickness(12, 5, 12, 5), CornerRadius = new CornerRadius(6), Margin = new Thickness(0, 0, 8, 8), Cursor = Cursors.Hand,
                Background = isActive ? Ui.Brush("TextPrimaryBrush") : Ui.Brush("CardBackgroundBrush"),
                BorderBrush = isActive ? Ui.Brush("TextPrimaryBrush") : Ui.Brush("CardBorderBrush"), BorderThickness = new Thickness(1), Child = content,
            };
            var tool = r.Tool;
            tab.MouseLeftButtonUp += (_, _) => { _activeLogTool = tool; _logFilter = ""; rerender(); };
            tabs.Children.Add(tab);
        }
        body.Children.Add(tabs);

        // Root facts
        var facts = Ui.Columns(4, 12,
            Ui.Stat("Path", active.Path, mono: true, copy: true, truncate: true),
            Ui.Stat("Files", $"{(active.FileCount > 0 ? active.FileCount : active.Files?.Count ?? 0)}" + (active.TotalBytes > 0 ? $" · {Format.Bytes(active.TotalBytes, 1)}" : "")),
            Ui.Stat("Last written", string.IsNullOrWhiteSpace(active.NewestModified) ? "Unknown" : Format.ShortDateTime(active.NewestModified)),
            active.LatestSession is { } ls ? LatestSession(ls) : Ui.Stat("Latest run", "—"));
        facts.Margin = new Thickness(0, 4, 0, 14);
        body.Children.Add(facts);

        // Picker + viewer
        var tails = active.Tails ?? [];
        var files = active.Files ?? [];
        var layout = new Grid();
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(280) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(16) });
        layout.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var currentFile = _selectedLogFile.TryGetValue(active.Tool ?? "", out var chosen) && tails.Any(t => t.File == chosen) ? chosen : tails.FirstOrDefault()?.File;
        var picker = new StackPanel();
        picker.Children.Add(Ui.Eyebrow("Logs"));
        foreach (var t in tails)
        {
            var entry = files.FirstOrDefault(f => f.Path == t.File);
            var isCurrent = t.File == currentFile;
            var item = new StackPanel();
            var name = Ui.Mono(t.File); name.Margin = new Thickness(0); name.TextTrimming = TextTrimming.CharacterEllipsis; name.TextWrapping = TextWrapping.NoWrap; name.FontWeight = isCurrent ? FontWeights.SemiBold : FontWeights.Normal;
            item.Children.Add(name);
            item.Children.Add(Ui.Caption((entry is null ? "" : Format.Bytes(entry.Bytes, 1)) + (entry?.Modified is { Length: > 0 } mod ? $" · {Format.ShortDateTime(mod)}" : "")));
            var row = new Border { Padding = new Thickness(8, 6, 8, 6), CornerRadius = new CornerRadius(6), Cursor = Cursors.Hand, Child = item, Background = isCurrent ? Ui.Brush("SubtleFillBrush") : System.Windows.Media.Brushes.Transparent };
            var file = t.File;
            row.MouseLeftButtonUp += (_, _) => { _selectedLogFile[active.Tool ?? ""] = file; _logFilter = ""; rerender(); };
            picker.Children.Add(row);
        }
        var others = files.Where(f => tails.All(t => t.File != f.Path)).ToList();
        if (others.Count > 0)
            picker.Children.Add(Ui.Collapsible($"{others.Count} more files", Ui.List(others.Select(f => Ui.ListItem(f.Path, (Format.Bytes(f.Bytes, 1) + (string.IsNullOrWhiteSpace(f.Modified) ? "" : $" · {Format.ShortDateTime(f.Modified)}")))))));
        layout.Children.Add(picker);

        var tail = tails.FirstOrDefault(t => t.File == currentFile);
        var lines = tail?.Lines ?? [];
        var viewer = new StackPanel();
        var toolbar = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        toolbar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        toolbar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        toolbar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var search = new SearchBox("Filter lines", q => { _logFilter = q; rerender(); }) { Text = _logFilter, Margin = new Thickness(0) };
        toolbar.Children.Add(search);
        var visible = string.IsNullOrWhiteSpace(_logFilter) ? lines : lines.Where(l => l.Contains(_logFilter, StringComparison.OrdinalIgnoreCase)).ToList();
        var meta = Ui.Caption((currentFile ?? "") + (lines.Count > 0 ? $"   {(string.IsNullOrWhiteSpace(_logFilter) ? $"last {lines.Count} lines" : $"{visible.Count} of {lines.Count} lines")}{(tail?.Truncated == true ? ", truncated" : "")}" : ""));
        meta.VerticalAlignment = VerticalAlignment.Center; meta.Margin = new Thickness(12, 0, 12, 0); meta.TextTrimming = TextTrimming.CharacterEllipsis; meta.TextWrapping = TextWrapping.NoWrap;
        Grid.SetColumn(meta, 1);
        toolbar.Children.Add(meta);
        var copy = Ui.CopyButton(string.Join("\n", lines));
        Grid.SetColumn(copy, 2);
        toolbar.Children.Add(copy);
        viewer.Children.Add(toolbar);
        viewer.Children.Add(LogViewer(currentFile, lines, visible));
        Grid.SetColumn(viewer, 2);
        layout.Children.Add(viewer);
        body.Children.Add(layout);
        root.Children.Add(body);
        return new Border { Style = (Style)Ui.Res("CardStyle"), Child = root };
    }

    private static FrameworkElement LatestSession(LogSessionSummary ls)
    {
        var panel = new StackPanel();
        panel.Children.Add(Ui.Label("Latest run"));
        var row = new WrapPanel { Margin = new Thickness(0, 4, 0, 0) };
        var status = (ls.Status ?? "unknown").ToLowerInvariant();
        var tone = status is "completed" or "success" or "succeeded" ? Tone.Success : status is "running" or "in_progress" ? Tone.Info
            : status.Contains("partial") || status.Contains("warn") ? Tone.Warning : status.Contains("fail") || status.Contains("error") || status == "abandoned" ? Tone.Error : Tone.Neutral;
        void Add(UIElement e) { if (e is FrameworkElement fe) fe.Margin = new Thickness(0, 0, 6, 4); row.Children.Add(e); }
        Add(Ui.Pill(ls.Status ?? "unknown", tone));
        if (!string.IsNullOrWhiteSpace(ls.SessionId)) Add(Ui.Caption(ls.SessionId));
        if (!string.IsNullOrWhiteSpace(ls.RunType)) Add(Ui.Caption(ls.RunType));
        if (ls.DurationSeconds is { } d) Add(Ui.Caption(Format.Duration(d)));
        if (ls.Errors is > 0) Add(Ui.Pill($"{ls.Errors} errors", Tone.Error, 10.5));
        if (ls.Warnings is > 0) Add(Ui.Pill($"{ls.Warnings} warnings", Tone.Warning, 10.5));
        panel.Children.Add(row);
        return panel;
    }

    private static readonly Regex ErrorLine = new(@"\b(ERROR|ERR|FAULT|CRITICAL|FATAL)\b", RegexOptions.Compiled);
    private static readonly Regex WarningLine = new(@"\b(WARN|WARNING|WRN)\b", RegexOptions.Compiled);

    private static UIElement LogViewer(string? file, List<string> lines, List<string> visible)
    {
        if (lines.Count == 0) return Ui.EmptyState("No log lines reported");
        var isJsonl = file?.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase) == true;
        var isJson = file?.EndsWith(".json", StringComparison.OrdinalIgnoreCase) == true;
        var box = new Border { Background = Ui.Brush("SubtleFillBrush"), CornerRadius = new CornerRadius(8), Padding = new Thickness(10), MaxHeight = 520 };
        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };

        if (isJson && visible.Count == lines.Count)
        {
            try
            {
                var doc = JsonDocument.Parse(string.Join("\n", lines));
                var pretty = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
                var pre = Ui.Mono(pretty); pre.FontSize = 11.5;
                scroll.Content = pre;
                box.Child = scroll;
                return box;
            }
            catch { }
        }

        var panel = new StackPanel();
        foreach (var line in visible)
        {
            if (isJsonl && line.TrimStart().StartsWith('{'))
            {
                try
                {
                    var obj = JsonDocument.Parse(line).RootElement;
                    string? First(params string[] keys) { foreach (var k in keys) if (obj.TryGetProperty(k, out var v) && v.ValueKind is JsonValueKind.String or JsonValueKind.Number) return v.ToString(); return null; }
                    var level = First("level", "severity");
                    var tone = LevelTone(level);
                    var summary = new WrapPanel();
                    void Chip(string? text, Tone t, bool mono = false)
                    {
                        if (string.IsNullOrWhiteSpace(text)) return;
                        var tb = mono ? Ui.Mono(text) : Ui.Caption(text);
                        tb.Margin = new Thickness(0, 0, 8, 0); tb.FontSize = 11.5;
                        if (t != Tone.Neutral) tb.Foreground = Ui.StatusBrush(t);
                        summary.Children.Add(tb);
                    }
                    var ts = Format.ParseDate(First("timestamp", "time", "ts", "date"));
                    Chip(ts is null ? First("timestamp", "time", "ts", "date") : ts.Value.ToLocalTime().ToString("HH:mm:ss"), Tone.Neutral, mono: true);
                    if (level is not null) summary.Children.Add(Ui.Pill(level, tone, 10.5));
                    Chip(First("event_type", "eventType", "type", "event")?.Replace('_', ' '), Tone.Neutral);
                    var item = First("package_name", "packageName", "item_name", "itemName", "name", "display_name");
                    var version = First("package_version", "packageVersion", "target_version", "version");
                    Chip(item is null ? null : version is null ? item : $"{item} {version}", Tone.Neutral);
                    Chip(First("message", "msg", "status_reason", "error"), tone);
                    var pre = Ui.Mono(JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true })); pre.FontSize = 11;
                    var exp = new Expander { Header = summary, Content = pre, Margin = new Thickness(0, 1, 0, 1), Foreground = Ui.Brush("TextPrimaryBrush") };
                    panel.Children.Add(exp);
                    continue;
                }
                catch { }
            }
            var tb2 = Ui.Mono(line.Length == 0 ? " " : line);
            tb2.FontSize = 11.5; tb2.Margin = new Thickness(0);
            if (ErrorLine.IsMatch(line)) tb2.Foreground = Ui.StatusBrush(Tone.Error);
            else if (WarningLine.IsMatch(line)) tb2.Foreground = Ui.StatusBrush(Tone.Warning);
            panel.Children.Add(tb2);
        }
        scroll.Content = panel;
        box.Child = scroll;
        return box;
    }

    private static Tone LevelTone(string? level)
    {
        var l = (level ?? "").ToUpperInvariant();
        if (l.StartsWith("ERR") || l is "FAULT" or "CRITICAL" or "FATAL") return Tone.Error;
        if (l.StartsWith("WARN") || l == "WRN") return Tone.Warning;
        return Tone.Neutral;
    }

    // ── Configuration profiles ───────────────────────────────────────

    private UIElement ProfilesCard(List<ConfigurationProfile> profiles, Action rerender)
    {
        var entries = profiles.Select((p, i) =>
        {
            var identifier = DeviceSnapshot.FirstNonEmpty(p.Identifier, p.Uuid, p.ProfileName, p.Name) ?? $"profile-{i}";
            return (Profile: p, Identifier: identifier,
                Name: DeviceSnapshot.FirstNonEmpty(p.ProfileName, p.Name) ?? identifier,
                Organization: DeviceSnapshot.FirstNonEmpty(p.Organization, p.Source, p.Category) ?? "Unknown Organization",
                Scope: string.Equals(p.Type, "User", StringComparison.OrdinalIgnoreCase) ? "User Level" : "System Level",
                Payloads: p.Payloads ?? [],
                PayloadCount: p.PayloadCount > 0 ? p.PayloadCount : p.Payloads?.Count ?? 0);
        }).ToList();
        var userScoped = entries.Count(e => e.Scope == "User Level");
        var q = _profileSearch.Trim();
        var filtered = q.Length == 0 ? entries : entries.Where(e => e.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || e.Identifier.Contains(q, StringComparison.OrdinalIgnoreCase) || e.Organization.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();

        var subtitle = $"Management profiles applied to this device ({filtered.Count} of {entries.Count} profiles" + (userScoped > 0 ? $", {entries.Count - userScoped} system level, {userScoped} user level" : "") + ")";
        var search = new SearchBox("Search profiles...", s => { _profileSearch = s; rerender(); }) { Text = _profileSearch };
        var list = new StackPanel();
        if (filtered.Count == 0) list.Children.Add(Ui.EmptyState($"No profiles match \"{q}\"."));
        foreach (var e in filtered)
        {
            var expanded = _expandedProfiles.Contains(e.Identifier);
            var row = new Grid { Margin = new Thickness(20, 10, 20, 10) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var chevron = Ui.Icon(expanded ? "" : "", 10, Ui.Brush("TextSecondaryBrush")); chevron.Margin = new Thickness(0, 0, 12, 0);
            row.Children.Add(chevron);
            var titles = new StackPanel();
            var name = Ui.Text(e.Name); name.FontWeight = FontWeights.Medium; name.Margin = new Thickness(0);
            titles.Children.Add(name);
            titles.Children.Add(Ui.Caption(e.Organization));
            Grid.SetColumn(titles, 1);
            row.Children.Add(titles);
            var badges = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            if (e.PayloadCount > 0) { var b = Ui.Pill(Format.Plural(e.PayloadCount, "payload"), Tone.Info); b.Margin = new Thickness(0, 0, 6, 0); badges.Children.Add(b); }
            badges.Children.Add(Ui.Pill(e.Scope, Tone.Neutral));
            if (!string.IsNullOrWhiteSpace(e.Profile.Status) && e.Profile.Status != "Applied") { var b = Ui.Pill(e.Profile.Status, Tone.Warning); b.Margin = new Thickness(6, 0, 0, 0); badges.Children.Add(b); }
            Grid.SetColumn(badges, 2);
            row.Children.Add(badges);
            var header = new Border { Child = row, Cursor = Cursors.Hand, Background = System.Windows.Media.Brushes.Transparent };
            var id = e.Identifier;
            header.MouseLeftButtonUp += (_, _) => { if (!_expandedProfiles.Remove(id)) _expandedProfiles.Add(id); rerender(); };
            header.MouseEnter += (_, _) => header.Background = Ui.Brush("SubtleFillBrush");
            header.MouseLeave += (_, _) => header.Background = System.Windows.Media.Brushes.Transparent;
            var stack = new StackPanel();
            stack.Children.Add(header);
            if (expanded) stack.Children.Add(ProfileDetails(e.Profile, e.Identifier, e.Payloads));
            list.Children.Add(new Border { BorderBrush = Ui.Brush("DividerBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = stack });
        }
        return Ui.TableCard("Configuration Profiles", subtitle, list, search);
    }

    private static Border ProfileDetails(ConfigurationProfile p, string identifier, List<ProfilePayload> payloads)
    {
        var body = new StackPanel();
        var meta = Ui.Columns(3, 16,
            Ui.Stat("Identifier", identifier, mono: true, copy: true, truncate: true),
            !string.IsNullOrWhiteSpace(p.Uuid) && p.Uuid != identifier ? Ui.Stat("UUID", p.Uuid, mono: true, copy: true, truncate: true) : null,
            p.InstallDate is not null ? Ui.Stat("Installed", Format.ShortDate(p.InstallDate)) : (p.LastModified is not null ? Ui.Stat("Modified", Format.ShortDate(p.LastModified)) : null));
        body.Children.Add(meta);
        if (!string.IsNullOrWhiteSpace(p.Description)) { var d = Ui.Stat("Description", p.Description); d.Margin = new Thickness(0, 10, 0, 0); body.Children.Add(d); }
        if (payloads.Count > 0)
        {
            var label = Ui.Label("Payloads"); label.Margin = new Thickness(0, 12, 0, 6);
            body.Children.Add(label);
            foreach (var payload in payloads)
            {
                var card = new StackPanel();
                var head = new StackPanel { Orientation = Orientation.Horizontal };
                var n = Ui.Text(DeviceSnapshot.FirstNonEmpty(payload.DisplayName, payload.Type) ?? "Unknown Payload"); n.FontWeight = FontWeights.Medium; n.Margin = new Thickness(0);
                head.Children.Add(n);
                if (!string.IsNullOrWhiteSpace(payload.Type)) { var t = Ui.Caption(payload.Type); t.Margin = new Thickness(8, 0, 0, 0); t.VerticalAlignment = VerticalAlignment.Center; head.Children.Add(t); }
                card.Children.Add(head);
                if (!string.IsNullOrWhiteSpace(payload.Identifier) && payload.Identifier != payload.DisplayName) card.Children.Add(Ui.Caption(payload.Identifier));
                if (payload.Settings is { Count: > 0 })
                {
                    var table = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
                    foreach (var (key, value) in payload.Settings.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
                    {
                        var r = new Grid();
                        r.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                        r.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.4, GridUnitType.Star) });
                        var k = Ui.Mono(key); k.FontSize = 11.5; k.Margin = new Thickness(0);
                        r.Children.Add(k);
                        UIElement v;
                        if (value is bool b || (value is JsonElement { ValueKind: JsonValueKind.True or JsonValueKind.False } je && (b = je.ValueKind == JsonValueKind.True) == b))
                            v = Ui.Pill(b ? "Yes" : "No", b ? Tone.Success : Tone.Neutral, 10.5);
                        else
                        {
                            var text = value is JsonElement { ValueKind: JsonValueKind.Object or JsonValueKind.Array } jo ? JsonSerializer.Serialize(jo, new JsonSerializerOptions { WriteIndented = true }) : Format.Str(value) ?? "";
                            var tv = Ui.Mono(text); tv.FontSize = 11.5; tv.Margin = new Thickness(0);
                            v = tv;
                        }
                        Grid.SetColumn(v, 1);
                        r.Children.Add(v);
                        table.Children.Add(new Border { Padding = new Thickness(0, 4, 0, 4), BorderBrush = Ui.Brush("DividerBrush"), BorderThickness = new Thickness(0, 0, 0, 1), Child = r });
                    }
                    card.Children.Add(table);
                }
                body.Children.Add(new Border { Background = Ui.Brush("SubtleFillBrush"), CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 10, 12, 10), Margin = new Thickness(0, 0, 0, 8), Child = card });
            }
        }
        return new Border { Padding = new Thickness(52, 0, 20, 16), Child = body };
    }
}
