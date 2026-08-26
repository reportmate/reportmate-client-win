#nullable enable
using System.Collections.Generic;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// Cimian gives the collector no single authoritative "what this run did" list the
    /// way Munki's ManagedInstallReport.plist does, so a run is reconstructed from
    /// events.jsonl, sessions.json counters and items.json. When those disagree the
    /// collector falls back to items.json, and the mixed-action branch used to abandon
    /// the item names it had already resolved and emit a bare count instead — which on
    /// a one-item run rendered as "1 packages installed or updated" while the same
    /// dashboard showed Macs naming their package and version.
    ///
    /// The rule these tests pin down: a run that touched exactly one package always
    /// names it, whichever verb applies, and the count form is never reached with a
    /// count of one. Package names and versions below are hand-authored.
    /// </summary>
    public class InstallEventMessageTests
    {
        private static List<InstallsModuleProcessor.InstallEventItem> Items(
            params (string Name, string? Version)[] items)
        {
            var list = new List<InstallsModuleProcessor.InstallEventItem>();
            foreach (var (name, version) in items)
                list.Add(new InstallsModuleProcessor.InstallEventItem(name, version));
            return list;
        }

        [Theory]
        [InlineData("installed", "ExampleEditor 4.2.1.0 installed")]
        [InlineData("updated", "ExampleEditor 4.2.1.0 updated")]
        [InlineData("removed", "ExampleEditor 4.2.1.0 removed")]
        // The mixed-action fallback: the run's counters said both an install and an
        // update happened, so no single verb is correct — but the name is still known.
        [InlineData("installed or updated", "ExampleEditor 4.2.1.0 installed or updated")]
        public void A_single_package_is_named_whichever_verb_applies(string verb, string expected)
        {
            var message = InstallsModuleProcessor.FormatActionMessage(
                Items(("ExampleEditor", "4.2.1.0")), verb, "packages");

            Assert.Equal(expected, message);
        }

        [Fact]
        public void A_single_package_with_no_version_is_still_named()
        {
            var message = InstallsModuleProcessor.FormatActionMessage(
                Items(("ExampleEditor", "")), "installed or updated", "packages");

            Assert.Equal("ExampleEditor installed or updated", message);
        }

        [Fact]
        public void The_count_form_is_never_reached_with_a_count_of_one()
        {
            // "1 packages installed or updated" was the reported symptom. Any single-item
            // run must take the naming branch, so the plural noun can't appear at all.
            var message = InstallsModuleProcessor.FormatActionMessage(
                Items(("ExampleEditor", "4.2.1.0")), "installed or updated", "packages");

            Assert.DoesNotContain("packages", message);
            Assert.DoesNotContain("1 ", message);
        }

        [Fact]
        public void Several_packages_fall_back_to_a_count()
        {
            var message = InstallsModuleProcessor.FormatActionMessage(
                Items(("ExampleEditor", "4.2.1.0"),
                      ("ExampleViewer", "1.0.0.0"),
                      ("ExampleRuntime", "9.9.9.9")),
                "installed", "packages");

            Assert.Equal("3 packages installed", message);
        }
    }
}
