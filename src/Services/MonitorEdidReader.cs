#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// One monitor's EDID, independent of which reader produced it.
    /// </summary>
    public sealed record MonitorEdid(
        string InstanceName,
        string Name,
        string Serial,
        string PnpCode,
        string ProductCode,
        int? Year,
        int? Week,
        bool Active,
        long? VideoOutputTechnology,
        string Resolution,
        double? DiagonalInches);

    /// <summary>
    /// Reads decoded EDID for every attached panel.
    ///
    /// Shared deliberately: the hardware module reports displays as assets, and the
    /// peripherals module needs the same serials to identify pen displays whose USB
    /// nodes publish no iSerialNumber. Two copies of this query would drift, and the
    /// serial is an identity key - it has to be the same string in both payloads.
    /// </summary>
    public interface IMonitorEdidReader
    {
        Task<List<MonitorEdid>> ReadAsync();
    }

    public class MonitorEdidReader : IMonitorEdidReader
    {
        private readonly ILogger<MonitorEdidReader> _logger;
        private readonly IWmiHelperService _wmiHelperService;

        public MonitorEdidReader(ILogger<MonitorEdidReader> logger, IWmiHelperService wmiHelperService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _wmiHelperService = wmiHelperService ?? throw new ArgumentNullException(nameof(wmiHelperService));
        }

        public const uint VideoOutputTechnologyInternal = 0x80000000;

        private static readonly Dictionary<long, string> VideoOutputTechnologyNames = new()
        {
            [0] = "VGA",
            [1] = "S-Video",
            [2] = "Composite",
            [3] = "Component",
            [4] = "DVI",
            [5] = "HDMI",
            [6] = "LVDS",
            [8] = "D-Jpn",
            [9] = "SDI",
            [10] = "DisplayPort",
            [11] = "DisplayPort (Embedded)",
            [12] = "UDI",
            [13] = "UDI (Embedded)",
            [14] = "SDTV Dongle",
            [15] = "Miracast",
            [VideoOutputTechnologyInternal] = "Internal",
        };

        // The three-letter PNP codes we can name. Anything outside this set still gets a
        // vendor id and is reported; it is simply left with the raw code as its
        // manufacturer rather than being invented a name.
        private static readonly Dictionary<string, string> PnpVendorNames = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ACR"] = "Acer", ["AOC"] = "AOC", ["APP"] = "Apple", ["AUS"] = "ASUS",
            ["BNQ"] = "BenQ", ["DEL"] = "Dell", ["ENC"] = "EIZO", ["GSM"] = "LG",
            ["HPN"] = "HP", ["HWP"] = "HP", ["IVM"] = "Iiyama", ["LEN"] = "Lenovo",
            ["LGD"] = "LG Display", ["MSI"] = "MSI", ["NEC"] = "NEC", ["PHL"] = "Philips",
            ["SAM"] = "Samsung", ["SEC"] = "Samsung", ["SHP"] = "Sharp",
            ["VSC"] = "ViewSonic", ["WAC"] = "Wacom",
        };

        /// <summary>
        /// Monitor EDID from root\wmi via PowerShell.
        ///
        /// Every source here is session independent, which is the whole point: the agent
        /// runs as SYSTEM in session 0, so the user32 display APIs enumerate nothing and
        /// System.Management reports WMI unavailable in the trimmed single-file build.
        /// Get-CimInstance against root\wmi answers correctly in that context.
        /// </summary>
        public async Task<List<MonitorEdid>> ReadAsync()
        {
            var monitors = new List<MonitorEdid>();

            // EDID strings are UInt16 arrays of ASCII codepoints, zero padded; decode them
            // here so the payload crossing the process boundary is already text.
            const string script = """
                function D($a){ if(-not $a){ return "" }; -join ($a | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) }
                $cp = @{}
                Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue |
                    ForEach-Object { $cp[$_.InstanceName] = $_.VideoOutputTechnology }
                $res = @{}
                Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorListedSupportedSourceModes -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $mode = $_.MonitorSourceModes[$_.PreferredMonitorSourceModeIndex]
                        if ($mode) { $res[$_.InstanceName] = "$($mode.HorizontalActivePixels) x $($mode.VerticalActivePixels)" }
                    }
                $size = @{}
                Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue |
                    ForEach-Object { $size[$_.InstanceName] = @($_.MaxHorizontalImageSize, $_.MaxVerticalImageSize) }
                $edid = @{}
                Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue | ForEach-Object {
                    $node = $_.InstanceName -replace '_\d+$', ''
                    $bytes = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Enum\$node\Device Parameters" -Name EDID -ErrorAction SilentlyContinue).EDID
                    if ($bytes) { $edid[$_.InstanceName] = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '') }
                }
                @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue | ForEach-Object {
                    $wh = $size[$_.InstanceName]
                    [PSCustomObject]@{
                        InstanceName = $_.InstanceName
                        Name         = (D $_.UserFriendlyName)
                        Serial       = (D $_.SerialNumberID)
                        Pnp          = (D $_.ManufacturerName)
                        Product      = (D $_.ProductCodeID)
                        Year         = $_.YearOfManufacture
                        Week         = $_.WeekOfManufacture
                        Active       = $_.Active
                        Vot          = $cp[$_.InstanceName]
                        Resolution   = $res[$_.InstanceName]
                        WidthCm      = if ($wh) { $wh[0] } else { $null }
                        HeightCm     = if ($wh) { $wh[1] } else { $null }
                        Edid         = $edid[$_.InstanceName]
                    }
                }) | ConvertTo-Json -Compress -Depth 3
                """;

            try
            {
                var output = await _wmiHelperService.ExecutePowerShellCommandAsync(script);
                if (string.IsNullOrWhiteSpace(output))
                {
                    return monitors;
                }

                var parsed = Newtonsoft.Json.JsonConvert.DeserializeObject(output);
                var items = parsed switch
                {
                    Newtonsoft.Json.Linq.JArray array => array,
                    Newtonsoft.Json.Linq.JObject single => new Newtonsoft.Json.Linq.JArray(single),
                    _ => new Newtonsoft.Json.Linq.JArray(),
                };

                foreach (var item in items.OfType<Newtonsoft.Json.Linq.JObject>())
                {
                    monitors.Add(new MonitorEdid(
                        (string?)item["InstanceName"] ?? string.Empty,
                        Clean((string?)item["Name"]),
                        ResolveSerial((string?)item["Edid"], (string?)item["Serial"]),
                        Clean((string?)item["Pnp"]),
                        Clean((string?)item["Product"]),
                        (int?)item["Year"],
                        (int?)item["Week"],
                        (bool?)item["Active"] ?? true,
                        NormalizeVideoOutputTechnology((long?)item["Vot"]),
                        (string?)item["Resolution"] ?? string.Empty,
                        DiagonalInchesFrom((double?)item["WidthCm"], (double?)item["HeightCm"])));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "PowerShell monitor EDID fallback failed");
            }

            return monitors;
        }

        /// The four 18-byte descriptor blocks of a 128-byte EDID.
        private static readonly int[] DescriptorOffsets = { 54, 72, 90, 108 };

        // 00 00 00 FF marks the descriptor that carries the display serial as text.
        private const byte DescriptorTagSerial = 0xFF;

        // Below this length a value is not an identity key - the server discards it, and
        // a fragment that looks like a serial is worse than none, because it collides
        // with every other panel of the same model.
        private const int MinimumUsableSerialLength = 5;

        /// <summary>
        /// The serial to report for one panel.
        ///
        /// WmiMonitorID.SerialNumberID is whatever the driver chose to surface, and for
        /// some panels that is the four-byte numeric serial from the EDID header rendered
        /// as a short decimal rather than the full text serial printed on the label. That
        /// fragment is not unique across a model, so keying an asset on it merges panels
        /// that are not the same monitor.
        ///
        /// The 0xFF descriptor is the authoritative text serial and is what the macOS
        /// client reads, so prefer it, and report nothing when the panel publishes none.
        /// SerialNumberID is used only when the raw EDID could not be read at all, and
        /// then only when it is long enough to be an identity key.
        /// </summary>
        public static string ResolveSerial(string? edidHex, string? wmiSerial)
        {
            var edid = ParseEdidHex(edidHex);
            if (edid is not null)
            {
                return SerialFromDescriptors(edid) ?? string.Empty;
            }

            var fallback = Clean(wmiSerial);
            return fallback.Length >= MinimumUsableSerialLength ? fallback : string.Empty;
        }

        /// <summary>
        /// The 0xFF descriptor's text, or null when the block does not carry one.
        /// </summary>
        public static string? SerialFromDescriptors(byte[]? edid)
        {
            if (edid is null || edid.Length < 128)
            {
                return null;
            }

            foreach (var offset in DescriptorOffsets)
            {
                // Bytes 0-2 zero are what distinguish a descriptor from a detailed timing
                // block, whose first two bytes are a non-zero pixel clock.
                if (edid[offset] != 0 || edid[offset + 1] != 0 || edid[offset + 2] != 0)
                {
                    continue;
                }

                if (edid[offset + 3] != DescriptorTagSerial)
                {
                    continue;
                }

                // 13 bytes of text, terminated with 0x0A when shorter and padded after.
                var text = new char[13];
                var length = 0;
                for (var i = 0; i < 13; i++)
                {
                    var value = edid[offset + 5 + i];
                    if (value is 0x0A or 0x00)
                    {
                        break;
                    }
                    text[length++] = (char)value;
                }

                var serial = Clean(new string(text, 0, length));
                return serial.Length > 0 ? serial : null;
            }

            return null;
        }

        /// <summary>
        /// Decode the hex the reader carries the raw EDID across in. Anything that is not
        /// a whole EDID block returns null, so the caller can tell "no raw EDID" from
        /// "raw EDID with no serial descriptor" - the two take different fallbacks.
        /// </summary>
        public static byte[]? ParseEdidHex(string? hex)
        {
            if (string.IsNullOrWhiteSpace(hex))
            {
                return null;
            }

            hex = hex.Trim();
            if (hex.Length % 2 != 0 || hex.Length < 256)
            {
                return null;
            }

            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                if (!byte.TryParse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i]))
                {
                    return null;
                }
            }

            return bytes;
        }

        /// <summary>
        /// Strip the padding EDID descriptor strings carry.
        ///
        /// A descriptor field is a fixed 13 bytes. Vendors that use the whole field leave
        /// it as-is, but a shorter value is terminated with 0x0A and padded - some vendors
        /// with 0x00, others with 0x20. The decode drops the nulls, so a space-padding
        /// vendor yields "ABC1234567  " where a null-padding one yields "ABC1234567".
        ///
        /// This is an identity key. The same panel arriving as two different strings
        /// creates two assets, so normalise here, at the one point both modules read
        /// through, rather than leaving each caller to remember.
        /// </summary>
        public static string Clean(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            // Control characters can appear mid-string (the 0x0A terminator), so trimming
            // the ends is not enough on its own.
            var stripped = new string(value.Where(c => !char.IsControl(c)).ToArray());
            return stripped.Trim();
        }

        /// <summary>
        /// Panel diagonal from the EDID physical dimensions, which are whole centimetres.
        /// That granularity is fine for a screen size but useless below about 10", so
        /// implausible values are dropped rather than reported as a suspiciously exact
        /// fraction of an inch.
        /// </summary>
        public static double? DiagonalInchesFrom(double? widthCm, double? heightCm)
        {
            if (widthCm is not > 0 || heightCm is not > 0)
            {
                return null;
            }

            var diagonal = Math.Sqrt((widthCm.Value * widthCm.Value) + (heightCm.Value * heightCm.Value)) / 2.54;
            return diagonal is >= 10 and <= 120 ? Math.Round(diagonal, 1) : null;
        }

        /// <summary>
        /// VideoOutputTechnology is declared uint32 but surfaces signed on some drivers,
        /// so the internal sentinel 0x80000000 arrives as int.MinValue.
        /// </summary>
        public static long? NormalizeVideoOutputTechnology(object? raw)
        {
            if (raw is null)
            {
                return null;
            }

            var value = Convert.ToInt64(raw, CultureInfo.InvariantCulture);
            return value == int.MinValue ? VideoOutputTechnologyInternal : value;
        }

        public static bool IsInternalVideoOutput(long technology) =>
            technology is VideoOutputTechnologyInternal or 6 or 11 or 13; // internal, LVDS, embedded DP, embedded UDI

        public static string VideoOutputTechnologyName(long technology) =>
            VideoOutputTechnologyNames.TryGetValue(technology, out var name) ? name : string.Empty;

        /// <summary>
        /// Resolve a three-letter PNP code to a vendor name, falling back to the code
        /// itself so an unknown vendor is still reported rather than invented.
        /// </summary>
        public static string ResolveVendorName(string pnpCode) =>
            PnpVendorNames.TryGetValue(pnpCode, out var vendorName) ? vendorName : pnpCode;

        /// <summary>
        /// Pack a three-letter PNP code into the 16-bit EDID manufacturer id as lowercase
        /// hex - five bits per letter, offset from 'A'-1, so "DEL" becomes 10ac. This is
        /// the one vendor field both clients fill in reliably, so inventory keys on it.
        /// </summary>
        public static string PackEdidVendorId(string pnpCode)
        {
            if (pnpCode.Length != 3)
            {
                return string.Empty;
            }

            var packed = 0;
            foreach (var letter in pnpCode.ToUpperInvariant())
            {
                if (letter is < 'A' or > 'Z')
                {
                    return string.Empty;
                }
                packed = (packed << 5) | (letter - 'A' + 1);
            }

            return packed.ToString("x", CultureInfo.InvariantCulture);
        }
    }
}
