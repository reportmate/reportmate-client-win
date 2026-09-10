namespace ReportMate.App.Services;

/// <summary>
/// Device liveness, derived the way the web app derives it.
/// </summary>
/// <remarks>
/// The API sends its own <c>status</c> field (online / idle / offline), but the web
/// dashboard and device list ignore it and recompute from <c>lastSeen</c> — the fleet
/// status widget, the status pills and the Selections status dimension all use the
/// derived bucket. Reading the API's field instead would put different numbers on the
/// native app than the web shows for the same fleet, so this mirrors
/// <c>calculateDeviceStatus</c> exactly, thresholds included.
/// </remarks>
public enum DeviceLiveness
{
    Active,
    Stale,
    Missing,
    Archived,
}

public static class DeviceStatus
{
    private const double ActiveThresholdHours = 24;
    private const double StaleThresholdHours = 168; // 7 days

    public static DeviceLiveness Calculate(DateTime? lastSeen, bool isArchived = false)
    {
        if (isArchived) return DeviceLiveness.Archived;
        if (lastSeen is null) return DeviceLiveness.Missing;

        var hours = (DateTime.UtcNow - lastSeen.Value.ToUniversalTime()).TotalHours;
        if (hours < ActiveThresholdHours) return DeviceLiveness.Active;
        if (hours < StaleThresholdHours) return DeviceLiveness.Stale;
        return DeviceLiveness.Missing;
    }

    public static DeviceLiveness Calculate(FleetDevice device) =>
        Calculate(device.LastSeen, device.Archived);

    public static string Label(DeviceLiveness liveness) => liveness switch
    {
        DeviceLiveness.Active => "Active",
        DeviceLiveness.Stale => "Stale",
        DeviceLiveness.Archived => "Archived",
        _ => "Missing",
    };
}
