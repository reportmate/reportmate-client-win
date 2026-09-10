using CommunityToolkit.Mvvm.ComponentModel;
using ReportMate.App.Services;

namespace ReportMate.App.ViewModels;

/// <summary>Header state for the device page; the tabs read the snapshot directly.</summary>
public partial class DeviceViewModel : ObservableObject
{
    [ObservableProperty] private DeviceSnapshot _snapshot = new();
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string? _error;

    public string DeviceName => Snapshot.DeviceName;
    public string SerialNumber => Snapshot.SerialNumber;
    public string AssetTag => Snapshot.AssetTag;
    public string ClientVersion => Snapshot.ClientVersion;
    public bool HasData => !Snapshot.IsEmpty;

    public string? IpAddress
    {
        get
        {
            var active = Snapshot.Network?.Interfaces?
                .FirstOrDefault(i => i.IsActive && i.IpAddresses is { Count: > 0 });
            var ipv4 = active?.IpAddresses?.FirstOrDefault(IsIpv4);
            return ipv4 ?? Snapshot.Network?.ActiveConnection?.IpAddress;
        }
    }

    public string LastSeenLabel => Snapshot.CollectedAt is null ? "never" : Format.RelativeTime(Snapshot.CollectedAt);

    /// <summary>Missing after 72 hours without a run, stale after 24, matching the web pills.</summary>
    public string? StatusPill
    {
        get
        {
            if (Snapshot.CollectedAt is null) return null;
            var hours = (DateTime.Now - Snapshot.CollectedAt.Value).TotalHours;
            return hours > 72 ? "Missing" : hours > 24 ? "Stale" : null;
        }
    }

    public async Task LoadAsync()
    {
        IsLoading = true;
        Error = null;
        try
        {
            Snapshot = await DeviceSnapshotStore.Instance.LoadAsync();
        }
        catch (Exception ex)
        {
            Error = ex.Message;
        }
        finally
        {
            IsLoading = false;
            OnPropertyChanged(string.Empty);
        }
    }

    public static bool IsIpv4(string ip)
        => System.Net.IPAddress.TryParse(ip, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
}
