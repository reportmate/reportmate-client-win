#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>The last Speedtest measurement and when this device may run the next one.</summary>
    public sealed class NetworkQualityState
    {
        public DateTimeOffset NextDue { get; set; }
        public NetworkQualityData? LastResult { get; set; }
    }

    /// <summary>
    /// Limits Speedtest to one attempt per device per day. Devices behind one public
    /// address share Ookla's rate limit, so each device's first attempt is placed at a
    /// stable offset within the day and later attempts follow 24 hours apart.
    /// </summary>
    public static class NetworkQualitySchedule
    {
        public static readonly TimeSpan Interval = TimeSpan.FromHours(24);

        public static TimeSpan FirstOffset(string deviceId)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(deviceId ?? string.Empty));
            var minutes = BitConverter.ToUInt32(hash, 0) % (uint)Interval.TotalMinutes;
            return TimeSpan.FromMinutes(minutes);
        }

        public static NetworkQualityState Initial(DateTimeOffset now, string deviceId) =>
            new() { NextDue = now + FirstOffset(deviceId) };

        /// <summary>A due date beyond one interval is invalid, for example after a clock change.</summary>
        public static bool IsDue(NetworkQualityState state, DateTimeOffset now) =>
            now >= state.NextDue || state.NextDue - now > Interval;

        public static NetworkQualityState? Load(string path)
        {
            try
            {
                return File.Exists(path)
                    ? JsonSerializer.Deserialize(File.ReadAllText(path), ReportMateJsonContext.Default.NetworkQualityState)
                    : null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                return null;
            }
        }

        public static void Save(string path, NetworkQualityState state)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(state, ReportMateJsonContext.Default.NetworkQualityState));
            File.Move(temp, path, overwrite: true);
        }

        public static bool IsRateLimited(string? error) =>
            error?.Contains("Limit reached", StringComparison.OrdinalIgnoreCase) == true;
    }
}
