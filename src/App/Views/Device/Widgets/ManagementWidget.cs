using System.Windows;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.App.Views.Device.Widgets;

/// <summary>MDM enrollment status, join type, Autopilot, server and device identifiers.</summary>
public static class ManagementWidget
{
    public static UIElement Build(DeviceSnapshot s)
    {
        var m = s.Management;
        if (m is null)
            return Ui.StatBlock("Management", "Device Management Service", "", Accent.Yellow, Ui.EmptyState("Management information not available"));

        var enrollment = m.MdmEnrollment;
        var isEnrolled = enrollment?.IsEnrolled == true;
        var serverUrl = DeviceSnapshot.FirstNonEmpty(enrollment?.ServerUrl, enrollment?.ManagementUrl, m.TenantDetails?.MdmUrl);
        var provider = DeviceSnapshot.FirstNonEmpty(enrollment?.Provider) ?? DetectProvider(serverUrl);
        var enrollmentType = EnrollmentType(m);

        var body = new System.Windows.Controls.StackPanel();
        if (!string.IsNullOrWhiteSpace(provider))
        {
            var providerRow = Ui.Row("Provider", provider, semibold: true);
            providerRow.Margin = new Thickness(0, 0, 0, 8);
            body.Children.Add(providerRow);
        }
        body.Children.Add(Ui.StatusBadge("Enrollment", isEnrolled ? "Enrolled" : "Not Enrolled", isEnrolled ? Tone.Success : Tone.Error));
        if (enrollmentType is not null)
            body.Children.Add(Ui.StatusBadge("Enrollment Type", enrollmentType,
                enrollmentType.Contains("Entra Joined") ? Tone.Success : Tone.Info));
        if (m.AutopilotConfig is not null && (m.AutopilotConfig.Activated || m.AutopilotConfig.Registered || !string.IsNullOrWhiteSpace(m.AutopilotConfig.ProfileName)))
            body.Children.Add(Ui.StatusBadge("Autopilot Activated", Format.YesNo(m.AutopilotConfig.Activated),
                m.AutopilotConfig.Activated ? Tone.Success : Tone.Info));

        if (isEnrolled)
        {
            if (!string.IsNullOrWhiteSpace(serverUrl))
            {
                var stat = Ui.Stat("Server", HostOf(serverUrl), copy: true);
                stat.Margin = new Thickness(0, 10, 0, 0);
                body.Children.Add(stat);
            }
            var validity = m.DeviceDetails?.DeviceCertificateValidity;
            if (!string.IsNullOrWhiteSpace(validity))
            {
                var stat = Ui.Stat("Certificate Validity", validity);
                stat.Margin = new Thickness(0, 10, 0, 0);
                body.Children.Add(stat);
            }

            var isIntune = provider?.Contains("Intune", StringComparison.OrdinalIgnoreCase) == true;
            var ids = new System.Windows.Controls.StackPanel { Margin = new Thickness(0, 12, 0, 0) };
            void Id(string label, string? value)
            {
                if (string.IsNullOrWhiteSpace(value)) return;
                var st = Ui.Stat(label, value, mono: true, copy: true, truncate: true);
                st.Margin = new Thickness(0, 0, 0, 8);
                ids.Children.Add(st);
            }
            if (!isIntune) Id("Hardware UUID", s.DeviceId);
            if (isIntune) Id("Intune UUID", m.DeviceDetails?.IntuneDeviceId);
            else Id("Object ID", m.DeviceDetails?.EntraObjectId);
            if (ids.Children.Count > 0) body.Children.Add(ids);
        }

        return Ui.StatBlock("Management", "Device Management Service", "", Accent.Yellow, body);
    }

    public static string? EnrollmentType(ManagementData m)
    {
        var raw = m.MdmEnrollment?.EnrollmentMethod;
        if (!string.IsNullOrWhiteSpace(raw))
        {
            if (raw == "Hybrid Entra Join") return "Domain Joined";
            if (raw == "Entra Join") return "Entra Joined";
            return raw;
        }
        var state = m.DeviceState;
        if (state is null) return null;
        if (state.EntraJoined && state.DomainJoined) return "Domain Joined";
        if (state.EntraJoined) return "Entra Joined";
        if (state.DomainJoined) return "Domain Joined";
        if (m.UserState?.WorkplaceJoined == true) return "Workplace Joined";
        return null;
    }

    public static string? DetectProvider(string? serverUrl)
    {
        if (string.IsNullOrWhiteSpace(serverUrl)) return null;
        var url = serverUrl.ToLowerInvariant();
        if (url.Contains("manage.microsoft.com") || url.Contains("intune")) return "Microsoft Intune";
        if (url.Contains("jamf")) return "Jamf Pro";
        if (url.Contains("airwatch.com") || url.Contains("workspaceone")) return "Workspace ONE";
        if (url.Contains("meraki")) return "Cisco Meraki";
        if (url.Contains("maas360")) return "MaaS360";
        if (url.Contains("mobileiron") || url.Contains("ivanti")) return "Ivanti";
        return null;
    }

    public static string HostOf(string url)
    {
        var trimmed = url.Trim();
        var idx = trimmed.IndexOf("://", StringComparison.Ordinal);
        if (idx >= 0) trimmed = trimmed[(idx + 3)..];
        var slash = trimmed.IndexOf('/');
        return slash >= 0 ? trimmed[..slash] : trimmed;
    }
}
