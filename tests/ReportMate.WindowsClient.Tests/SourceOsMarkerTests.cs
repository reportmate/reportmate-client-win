#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// The OS install date moves for two unrelated reasons - the machine was wiped, or a
    /// feature update ran over it - and nothing else on the endpoint separates them. The
    /// "Source OS (Updated on &lt;date&gt;)" subkeys under HKLM\SYSTEM\Setup do: an upgrade
    /// writes one, a clean install carries none.
    ///
    /// The date is only ever present inside the key name, in whatever locale the machine
    /// was running at upgrade time, so these rows cover the formats that actually turn up
    /// rather than one canonical shape. The case that matters most is the empty one: no
    /// markers has to mean "never upgraded over", never "we failed to read it".
    /// </summary>
    public class SourceOsMarkerTests
    {
        private static Dictionary<string, object> Marker(string name)
            => new() { ["name"] = name, ["type"] = "subkey", ["path"] = $@"HKEY_LOCAL_MACHINE\SYSTEM\Setup\{name}" };

        [Fact]
        public void A_clean_install_carries_no_markers()
        {
            var result = SourceOsMarkers.Parse(new List<Dictionary<string, object>>());

            Assert.Equal(0, result.Count);
            Assert.Null(result.Newest);
        }

        [Fact]
        public void No_rows_at_all_is_not_an_upgrade()
        {
            var result = SourceOsMarkers.Parse(null);

            Assert.Equal(0, result.Count);
            Assert.Null(result.Newest);
        }

        [Fact]
        public void A_single_upgrade_is_dated_from_the_key_name()
        {
            var result = SourceOsMarkers.Parse(new[] { Marker("Source OS (Updated on 7/23/2024 09:12:33)") });

            Assert.Equal(1, result.Count);
            Assert.Equal(new DateTime(2024, 7, 23, 9, 12, 33), result.Newest);
            Assert.Equal(0, result.Undated);
        }

        [Fact]
        public void The_newest_upgrade_wins_regardless_of_enumeration_order()
        {
            var result = SourceOsMarkers.Parse(new[]
            {
                Marker("Source OS (Updated on 3/14/2023 22:05:01)"),
                Marker("Source OS (Updated on 7/23/2024 09:12:33)"),
                Marker("Source OS (Updated on 11/2/2023 08:00:00)"),
            });

            Assert.Equal(3, result.Count);
            Assert.Equal(new DateTime(2024, 7, 23, 9, 12, 33), result.Newest);
        }

        [Theory]
        [InlineData("Source OS (Updated on 7/23/2024 09:12:33)")]
        [InlineData("Source OS (Updated on 2024-07-23 09:12:33)")]
        [InlineData("Source OS (Updated on 07/23/2024 9:12:33 AM)")]
        public void The_locale_formats_that_turn_up_all_parse(string name)
        {
            var result = SourceOsMarkers.Parse(new[] { Marker(name) });

            Assert.Equal(1, result.Count);
            Assert.NotNull(result.Newest);
            Assert.Equal(new DateTime(2024, 7, 23), result.Newest!.Value.Date);
        }

        [Fact]
        public void An_undated_marker_still_counts_as_an_upgrade()
        {
            // Reporting this machine as never upgraded is the false negative the whole
            // signal exists to remove, so an unreadable date must not erase the marker.
            var result = SourceOsMarkers.Parse(new[]
            {
                Marker("Source OS"),
                Marker("Source OS (Updated on not-a-date)"),
            });

            Assert.Equal(2, result.Count);
            Assert.Equal(2, result.Undated);
            Assert.Null(result.Newest);
        }

        [Fact]
        public void A_dated_marker_survives_an_undated_sibling()
        {
            var result = SourceOsMarkers.Parse(new[]
            {
                Marker("Source OS (Updated on garbage)"),
                Marker("Source OS (Updated on 7/23/2024 09:12:33)"),
            });

            Assert.Equal(2, result.Count);
            Assert.Equal(1, result.Undated);
            Assert.Equal(new DateTime(2024, 7, 23, 9, 12, 33), result.Newest);
        }

        [Fact]
        public void Other_subkeys_under_Setup_are_ignored()
        {
            // HKLM\SYSTEM\Setup holds unrelated children; only Source OS means an upgrade.
            var result = SourceOsMarkers.Parse(new[]
            {
                Marker("Status"),
                Marker("AllowStart"),
                Marker("Upgrade"),
                Marker("Source OS (Updated on 7/23/2024 09:12:33)"),
            });

            Assert.Equal(1, result.Count);
            Assert.Equal(new DateTime(2024, 7, 23, 9, 12, 33), result.Newest);
        }

        [Fact]
        public void A_row_carrying_only_a_path_is_still_read()
        {
            var row = new Dictionary<string, object>
            {
                ["path"] = @"HKEY_LOCAL_MACHINE\SYSTEM\Setup\Source OS (Updated on 7/23/2024 09:12:33)",
            };

            var result = SourceOsMarkers.Parse(new[] { row });

            Assert.Equal(1, result.Count);
            Assert.Equal(new DateTime(2024, 7, 23, 9, 12, 33), result.Newest);
        }

        [Fact]
        public void A_machine_running_a_non_english_locale_still_parses_the_invariant_form()
        {
            var previous = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = new CultureInfo("de-DE");
                var result = SourceOsMarkers.Parse(new[] { Marker("Source OS (Updated on 2024-07-23 09:12:33)") });

                Assert.Equal(1, result.Count);
                Assert.Equal(new DateTime(2024, 7, 23, 9, 12, 33), result.Newest);
            }
            finally
            {
                CultureInfo.CurrentCulture = previous;
            }
        }
    }
}
