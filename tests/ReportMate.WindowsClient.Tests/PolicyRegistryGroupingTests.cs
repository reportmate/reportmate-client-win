#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// Policy collection decides what the fleet can prove about itself. The design this
    /// replaced enumerated products by hand - Chrome and Edge had queries, nothing else did -
    /// so every other managed product reported as "no policies applied" while its policies
    /// were in fact applied. That failure is silent by construction: absence of data looks
    /// identical to absence of policy.
    ///
    /// These rows are hand-authored, not captured from any machine. Paths follow each
    /// vendor's publicly documented policy location. The Firefox row is deliberately one
    /// level deeper than the Chrome row, because that difference is exactly what a
    /// copy-the-Chrome-query approach gets wrong.
    /// </summary>
    public class PolicyRegistryGroupingTests
    {
        private const string Hklm = "HKEY_LOCAL_MACHINE";

        private static readonly PolicyRegistryGrouping.PolicyRoot[] Roots =
        {
            new("policy_registry_machine",         "Group Policy", "Device"),
            new("policy_registry_machine_wow6432", "Group Policy", "Device"),
            new("policy_registry_mdm_current",     "MDM",          "Device"),
            new("policy_registry_user",            "Group Policy", "User"),
        };

        private static Dictionary<string, object> Row(string path, string name, string data, string type = "REG_DWORD")
            => new() { ["path"] = path, ["name"] = name, ["data"] = data, ["type"] = type };

        private static PolicyRegistryGrouping.Result GroupFixture(
            IEnumerable<Dictionary<string, object>>? machine = null,
            IEnumerable<Dictionary<string, object>>? wow = null,
            IEnumerable<Dictionary<string, object>>? mdm = null,
            IEnumerable<Dictionary<string, object>>? user = null)
        {
            var results = new Dictionary<string, List<Dictionary<string, object>>>
            {
                ["policy_registry_machine"] = (machine ?? Enumerable.Empty<Dictionary<string, object>>()).ToList(),
                ["policy_registry_machine_wow6432"] = (wow ?? Enumerable.Empty<Dictionary<string, object>>()).ToList(),
                ["policy_registry_mdm_current"] = (mdm ?? Enumerable.Empty<Dictionary<string, object>>()).ToList(),
                ["policy_registry_user"] = (user ?? Enumerable.Empty<Dictionary<string, object>>()).ToList(),
            };
            return PolicyRegistryGrouping.Group(Roots, results, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        }

        [Fact]
        public void Every_vendor_is_collected_including_ones_no_query_was_ever_written_for()
        {
            var result = GroupFixture(machine: new[]
            {
                Row($@"{Hklm}\SOFTWARE\Policies\Google\Chrome\IncognitoModeAvailability", "IncognitoModeAvailability", "2"),
                Row($@"{Hklm}\SOFTWARE\Policies\Microsoft\Edge\InPrivateModeAvailability", "InPrivateModeAvailability", "2"),
                Row($@"{Hklm}\SOFTWARE\Policies\Mozilla\Firefox\Preferences\browser.privatebrowsing.autostart", "browser.privatebrowsing.autostart", "1"),
                Row($@"{Hklm}\SOFTWARE\Policies\Adobe\APIP\Enabled", "Enabled", "0"),
                Row($@"{Hklm}\SOFTWARE\Policies\Cimian\InstallerTimeout", "InstallerTimeout", "2400", "REG_SZ"),
            });

            var vendors = result.ConfigurationProfiles.Select(p => p.Organization).ToHashSet();
            Assert.Equal(new[] { "Adobe", "Cimian", "Google", "Microsoft", "Mozilla" }, vendors.OrderBy(v => v));

            // The whole point: no vendor is special-cased, so every value survives collection.
            Assert.Equal(5, result.RegistryPolicies.Count);
        }

        [Fact]
        public void A_policy_nested_deeper_than_its_vendor_key_is_still_collected()
        {
            // Firefox stores preferences one level below where Chrome stores policies. A query
            // written by analogy to Chrome returns nothing here and reports success doing it.
            var result = GroupFixture(machine: new[]
            {
                Row($@"{Hklm}\SOFTWARE\Policies\Mozilla\Firefox\Preferences\browser.privatebrowsing.autostart", "browser.privatebrowsing.autostart", "1"),
            });

            var profile = Assert.Single(result.ConfigurationProfiles);
            Assert.Equal(@"Mozilla\Firefox\Preferences", profile.ProfileName);
            Assert.Equal("Mozilla", profile.Organization);
            Assert.Equal("Mozilla Firefox", profile.Category);
            Assert.Equal("1", profile.Payloads.Single().Settings["browser.privatebrowsing.autostart"]);
        }

        [Fact]
        public void All_keys_under_one_branch_group_into_a_single_profile()
        {
            var result = GroupFixture(machine: new[]
            {
                Row($@"{Hklm}\SOFTWARE\Policies\Google\Chrome\IncognitoModeAvailability", "IncognitoModeAvailability", "2"),
                Row($@"{Hklm}\SOFTWARE\Policies\Google\Chrome\BrowserSignin", "BrowserSignin", "0"),
                Row($@"{Hklm}\SOFTWARE\Policies\Google\Chrome\HomepageLocation", "HomepageLocation", "https://ecuad.ca", "REG_SZ"),
            });

            var profile = Assert.Single(result.ConfigurationProfiles);
            var payload = Assert.Single(profile.Payloads);
            Assert.Equal(3, payload.Settings.Count);
            Assert.Equal("https://ecuad.ca", payload.Settings["HomepageLocation"]);
            Assert.Equal(3, profile.AppliedSettings.Count);
            Assert.Equal(1, profile.PayloadCount);
        }

        [Fact]
        public void The_same_policy_in_the_32bit_view_does_not_duplicate_the_profile()
        {
            var chrome = Row($@"{Hklm}\SOFTWARE\Policies\Google\Chrome\IncognitoModeAvailability", "IncognitoModeAvailability", "2");
            var chrome32 = Row($@"{Hklm}\SOFTWARE\WOW6432Node\Policies\Google\Chrome\IncognitoModeAvailability", "IncognitoModeAvailability", "2");

            var result = GroupFixture(machine: new[] { chrome }, wow: new[] { chrome32 });

            Assert.Single(result.ConfigurationProfiles);
            Assert.Single(result.RegistryPolicies);
        }

        [Fact]
        public void Csp_policies_are_grouped_by_the_area_windows_uses()
        {
            var result = GroupFixture(mdm: new[]
            {
                Row($@"{Hklm}\SOFTWARE\Microsoft\PolicyManager\current\device\Browser\AllowSmartScreen", "AllowSmartScreen", "1"),
                Row($@"{Hklm}\SOFTWARE\Microsoft\PolicyManager\current\device\Defender\AllowRealtimeMonitoring", "AllowRealtimeMonitoring", "1"),
            });

            Assert.Equal(new[] { "Browser", "Defender" },
                result.ConfigurationProfiles.Select(p => p.Category).OrderBy(c => c));
            Assert.All(result.ConfigurationProfiles, p => Assert.Equal("MDM", p.Source));
        }

        [Fact]
        public void Profiles_carry_the_identity_fields_the_frontend_reads()
        {
            // The shared reader takes profileName first and falls back to displayName; a profile
            // missing both renders as "Unknown Profile", which is how Windows policies used to
            // appear next to correctly-named macOS ones.
            var result = GroupFixture(machine: new[]
            {
                Row($@"{Hklm}\SOFTWARE\Policies\Google\Chrome\IncognitoModeAvailability", "IncognitoModeAvailability", "2"),
            });

            var profile = Assert.Single(result.ConfigurationProfiles);
            Assert.False(string.IsNullOrWhiteSpace(profile.ProfileName));
            Assert.False(string.IsNullOrWhiteSpace(profile.Uuid));
            Assert.Equal(profile.Identifier, profile.Uuid);
            Assert.Equal("Device", profile.Type);
            Assert.NotEmpty(profile.Payloads);
        }

        [Fact]
        public void Rows_without_a_value_name_are_skipped_rather_than_forming_empty_profiles()
        {
            var result = GroupFixture(machine: new[]
            {
                Row($@"{Hklm}\SOFTWARE\Policies\Google\Chrome", "", ""),
                Row("", "Orphan", "1"),
            });

            Assert.Empty(result.ConfigurationProfiles);
            Assert.Empty(result.RegistryPolicies);
        }

        [Fact]
        public void User_scope_policies_are_collected_and_marked_as_user_scope()
        {
            // The agent runs as SYSTEM, where HKEY_CURRENT_USER resolves to S-1-5-18's own hive,
            // so user policy is only reachable through HKEY_USERS. Verified against a planted
            // probe value on a real endpoint before this path was written.
            const string sid = "S-1-5-21-3988616498-1384486608-2171474746-1001";
            var result = GroupFixture(user: new[]
            {
                Row($@"HKEY_USERS\{sid}\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI", "NC_ShowSharedAccessUI", "0"),
            });

            var profile = Assert.Single(result.ConfigurationProfiles);
            Assert.Equal("User", profile.Type);
            Assert.Contains(sid, profile.Description);
            Assert.Equal("Microsoft", profile.Organization);
            Assert.Equal("0", profile.Payloads.Single().Settings["NC_ShowSharedAccessUI"]);
        }

        [Fact]
        public void The_default_hive_and_the_system_sid_are_one_hive_not_two()
        {
            // HKU\.DEFAULT and HKU\S-1-5-18 alias the same hive. A probe planted once under
            // .DEFAULT came back through both names; without folding them together every such
            // policy reports twice.
            var result = GroupFixture(user: new[]
            {
                Row(@"HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Contoso\App\Setting", "Setting", "1"),
                Row(@"HKEY_USERS\S-1-5-18\SOFTWARE\Policies\Contoso\App\Setting", "Setting", "1"),
            });

            Assert.Single(result.ConfigurationProfiles);
            Assert.Single(result.RegistryPolicies);
            Assert.Contains("S-1-5-18", result.ConfigurationProfiles[0].Description);
        }

        [Fact]
        public void Machine_and_user_copies_of_the_same_policy_stay_separate()
        {
            // Same product, both scopes. These are genuinely different settings and must not
            // collapse into one another the way the WOW6432Node duplicate does.
            var result = GroupFixture(
                machine: new[] { Row($@"{Hklm}\SOFTWARE\Policies\Google\Chrome\HomepageLocation", "HomepageLocation", "https://machine.example", "REG_SZ") },
                user: new[] { Row(@"HKEY_USERS\S-1-5-21-1-2-3-1001\SOFTWARE\Policies\Google\Chrome\HomepageLocation", "HomepageLocation", "https://user.example", "REG_SZ") });

            Assert.Equal(2, result.ConfigurationProfiles.Count);
            Assert.Equal(2, result.RegistryPolicies.Count);
            Assert.Equal(new[] { "Device", "User" },
                result.ConfigurationProfiles.Select(p => p.Type).OrderBy(t => t));
        }
    }
}
