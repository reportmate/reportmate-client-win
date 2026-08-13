#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Usage;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// Name resolution decides the app_name on every usage_history row, and the
    /// server accumulates by that name, so a change here silently re-partitions
    /// fleet-wide usage. These tests run the real resolver over the hand-authored
    /// inventory in Fixtures and pin the name it produces for every executable
    /// path, so any change in attribution shows up as a failing assertion.
    /// </summary>
    public class UsageAppNameResolverTests
    {
        private static readonly List<InstalledApplication> Inventory = Fixtures.InstalledApplications();

        // Set REPORTMATE_REGEN_FIXTURES=1 to rewrite expected-resolutions.json from
        // current behaviour. Regenerating is an explicit, reviewable act: the diff
        // is the change in attribution.
        private static bool Regenerating =>
            Environment.GetEnvironmentVariable("REPORTMATE_REGEN_FIXTURES") == "1";

        [Fact]
        public void Fixture_inventory_keeps_the_shape_the_registry_actually_has()
        {
            // Most registry uninstall entries carry no InstallLocation. That is
            // the common case, not the edge case, and it is the reason the
            // tracker path cannot rely on prefix matching alone. An inventory
            // fixture that lost that property would stop testing anything.
            var withoutLocation = Inventory.Count(a => string.IsNullOrWhiteSpace(a.InstallLocation));
            Assert.True(withoutLocation > Inventory.Count / 2,
                $"expected most entries to have no InstallLocation, got {withoutLocation}/{Inventory.Count}");

            // Order is load-bearing: "Microsoft OneDrive" must precede
            // "Microsoft Edge" for the vendor-token collapse to reproduce.
            var names = Inventory.Select(a => a.Name).ToList();
            Assert.True(names.IndexOf("Microsoft OneDrive") < names.IndexOf("Microsoft Edge"),
                "the inventory fixture has been reordered; the pinned resolutions assume " +
                "Microsoft OneDrive appears before Microsoft Edge");

            // Fixtures are hand-authored. Nothing collected from a real endpoint
            // belongs in this repository.
            Assert.DoesNotContain(Inventory,
                a => (a.InstallLocation ?? string.Empty).Contains(@"C:\Users\", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void Resolution_matches_the_pinned_expectations()
        {
            var paths = Fixtures.ObservedExePaths();

            var actual = paths.Select(p =>
            {
                var app = UsageAppNameResolver.ResolveInstalledApp(p, Inventory);
                return new ResolutionCase
                {
                    ExePath = p,
                    SecurityLog = app?.Name,
                    Tracker = UsageAppNameResolver.ResolveTrackerAppName(p, Inventory)
                };
            }).ToList();

            if (Regenerating)
            {
                // Carry forward the human annotations; only the observed values move.
                var previous = SafeLoadExpected()
                    .ToDictionary(c => c.ExePath, StringComparer.OrdinalIgnoreCase);
                foreach (var c in actual)
                {
                    if (!previous.TryGetValue(c.ExePath, out var prev)) continue;

                    // A defect the resolver now gets right is not a defect. Left
                    // in place the annotation outlives its fix, and the fixture
                    // goes on advertising known-bad cases that are correct --
                    // which is what happened to all 28 of the 4353 annotations.
                    if (prev.Defect != null &&
                        string.Equals(prev.Should, c.SecurityLog, StringComparison.Ordinal))
                        continue;

                    c.Defect = prev.Defect;
                    c.Should = prev.Should;
                }
                Fixtures.Write("expected-resolutions.json", actual);
                return;
            }

            var expected = Fixtures.ExpectedResolutions()
                .ToDictionary(c => c.ExePath, StringComparer.OrdinalIgnoreCase);

            var drift = new List<string>();
            foreach (var c in actual)
            {
                if (!expected.TryGetValue(c.ExePath, out var e))
                {
                    drift.Add($"{c.ExePath}: not pinned (add it to expected-resolutions.json)");
                    continue;
                }
                if (!string.Equals(e.SecurityLog, c.SecurityLog, StringComparison.Ordinal))
                    drift.Add($"{c.ExePath}: securityLog {Show(e.SecurityLog)} -> {Show(c.SecurityLog)}");
                if (!string.Equals(e.Tracker, c.Tracker, StringComparison.Ordinal))
                    drift.Add($"{c.ExePath}: tracker {Show(e.Tracker)} -> {Show(c.Tracker)}");
            }

            Assert.True(drift.Count == 0,
                "app_name attribution changed for " + drift.Count + " executable(s). Every line below is a " +
                "different name on future usage_history rows. If the change is intended, review each one and " +
                "regenerate with REPORTMATE_REGEN_FIXTURES=1.\n  " + string.Join("\n  ", drift));
        }

        /// <summary>
        /// The property that matters most: for one executable and one inventory,
        /// both collection paths must produce the same name. When they disagree,
        /// the same application arrives at the server as two rows, one carrying
        /// total_seconds and the other foreground and active seconds.
        ///
        /// They disagree widely today, so the disagreement set itself is pinned.
        /// Fixing work item 4353 should shrink this list; nothing else should
        /// change it.
        /// </summary>
        [Fact]
        public void Both_paths_agree_except_for_the_pinned_disagreements()
        {
            var expected = Fixtures.ExpectedResolutions();

            var pinnedDisagreements = expected
                .Where(c => !string.Equals(c.SecurityLog ?? string.Empty, c.Tracker, StringComparison.Ordinal))
                .Select(c => c.ExePath)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var live = Fixtures.ObservedExePaths()
                .Where(p =>
                {
                    var sec = UsageAppNameResolver.ResolveInstalledApp(p, Inventory)?.Name ?? string.Empty;
                    var trk = UsageAppNameResolver.ResolveTrackerAppName(p, Inventory);
                    return !string.Equals(sec, trk, StringComparison.Ordinal);
                })
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var newlySplit = live.Except(pinnedDisagreements).OrderBy(p => p).ToList();
            var nowAgreeing = pinnedDisagreements.Except(live).OrderBy(p => p).ToList();

            Assert.True(newlySplit.Count == 0,
                "these executables now resolve to different names on the two paths, which splits them into two " +
                "usage_history rows:\n  " + string.Join("\n  ", newlySplit));

            Assert.True(nowAgreeing.Count == 0,
                "these executables no longer disagree, which is the intended direction. Regenerate the fixture " +
                "with REPORTMATE_REGEN_FIXTURES=1 to record it:\n  " + string.Join("\n  ", nowAgreeing));
        }

        /// <summary>
        /// Appx packages register an InstallLocation that is an exact, versioned
        /// directory, so whenever the inventory covers one the tracker path must
        /// resolve through that prefix rather than falling back to the filename.
        ///
        /// The Security Log path is not held to this: its fuzzy predicate reaches
        /// an unrelated entry first for most of these, which is precisely the
        /// defect recorded against each of them in the fixture.
        /// </summary>
        [Fact]
        public void Appx_packages_resolve_by_install_location_on_the_tracker_path()
        {
            var appx = Fixtures.ObservedExePaths()
                .Where(p => p.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase))
                .ToList();

            Assert.NotEmpty(appx);

            foreach (var path in appx)
            {
                // A package on disk but absent from the inventory has no right
                // answer, so only assert where the inventory actually covers it.
                var covering = Inventory
                    .Where(a => !string.IsNullOrWhiteSpace(a.InstallLocation))
                    .Where(a => IsPathPrefix(a.InstallLocation, path))
                    .Select(a => a.Name)
                    .ToList();

                if (covering.Count == 0) continue;

                Assert.Contains(UsageAppNameResolver.ResolveTrackerAppName(path, Inventory), covering);
            }
        }

        private static bool IsPathPrefix(string installLocation, string exePath)
        {
            var loc = installLocation.Replace('/', '\\').TrimEnd('\\');
            var exe = exePath.Replace('/', '\\').TrimEnd('\\');
            return loc.Length > 0
                   && exe.StartsWith(loc, StringComparison.OrdinalIgnoreCase)
                   && (exe.Length == loc.Length || exe[loc.Length] == '\\');
        }

        /// <summary>
        /// An empty or whitespace path must never produce a name, on either path.
        /// </summary>
        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void Blank_paths_resolve_to_nothing(string path)
        {
            Assert.Null(UsageAppNameResolver.ResolveInstalledApp(path, Inventory));
            Assert.Equal(string.Empty, UsageAppNameResolver.ResolveTrackerAppName(path, Inventory));
        }

        /// <summary>
        /// InstallLocation matching must respect directory boundaries. Without
        /// that check "C:\Program Files\Krita" would claim
        /// "C:\Program Files\KritaOther\x.exe".
        /// </summary>
        [Fact]
        public void Tracker_install_location_match_respects_directory_boundaries()
        {
            var inventory = new List<InstalledApplication>
            {
                new() { Name = "Sibling Product", InstallLocation = @"C:\Program Files\Widget" }
            };

            Assert.Equal("Sibling Product",
                UsageAppNameResolver.ResolveTrackerAppName(@"C:\Program Files\Widget\widget.exe", inventory));

            // Same prefix as a string, different directory -- must fall back to the filename.
            Assert.Equal("other",
                UsageAppNameResolver.ResolveTrackerAppName(@"C:\Program Files\WidgetWorks\other.exe", inventory));
        }

        /// <summary>
        /// When install locations nest, the longest one wins, so an executable
        /// belonging to a bundled sub-product is not attributed to its parent.
        /// </summary>
        [Fact]
        public void Tracker_prefers_the_longest_install_location()
        {
            var inventory = new List<InstalledApplication>
            {
                new() { Name = "Parent Suite", InstallLocation = @"C:\Program Files\Suite" },
                new() { Name = "Bundled Tool", InstallLocation = @"C:\Program Files\Suite\Tool" }
            };

            Assert.Equal("Bundled Tool",
                UsageAppNameResolver.ResolveTrackerAppName(@"C:\Program Files\Suite\Tool\tool.exe", inventory));
        }

        /// <summary>
        /// Unmatched executables keep the filename rather than being dropped,
        /// which is the behaviour difference that produces "chrome" alongside
        /// "Google Chrome".
        /// </summary>
        [Fact]
        public void Tracker_falls_back_to_the_executable_filename()
        {
            Assert.Equal("nothing-installed",
                UsageAppNameResolver.ResolveTrackerAppName(
                    @"C:\Some\Unknown\nothing-installed.exe",
                    new List<InstalledApplication>()));
        }

        private static List<ResolutionCase> SafeLoadExpected()
        {
            try { return Fixtures.ExpectedResolutions(); }
            catch (System.IO.FileNotFoundException) { return new List<ResolutionCase>(); }
        }

        private static string Show(string? s) => s is null ? "(dropped)" : $"\"{s}\"";
    }
}
