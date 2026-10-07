using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using ReportMate.Shared;
using ReportMate.WindowsClient.Configuration;
using Xunit;
using static ReportMate.WindowsClient.Tests.TestMarkers;

namespace ReportMate.WindowsClient.Tests
{
    public class SecretStoreTests
    {
        private const string Policy = ReportMateSettingsKeys.PolicyRegistryPath;
        private const string Settings = ReportMateSettingsKeys.SettingsRegistryPath;
        private const string Config = ReportMateSettingsKeys.LegacyConfigRegistryPath;
        private const string Top = ReportMateSettingsKeys.LegacyRegistryPath;

        [Theory]
        [InlineData("Passphrase")]
        [InlineData("passphrase")]
        [InlineData("ApiKey")]
        public void Credentials_are_secrets(string name) => Assert.True(SecretStore.IsSecret(name));

        [Fact]
        public void Other_settings_are_not() => Assert.False(SecretStore.IsSecret("ApiUrl"));

        [Fact]
        public void Store_admits_only_system_and_administrators()
        {
            var security = SecretStore.ProtectedSecurity();
            Assert.True(security.AreAccessRulesProtected);

            var sids = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<RegistryAccessRule>()
                .Select(r => ((SecurityIdentifier)r.IdentityReference).Value)
                .OrderBy(v => v)
                .ToArray();
            Assert.Equal(new[] { "S-1-5-18", "S-1-5-32-544" }, sids);
        }

        [Fact]
        public void Policy_beats_settings_and_both_are_blanked()
        {
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Settings] = "s", [Policy] = "p" }, storeHasValue: true);

            Assert.Equal("p", plan.ValueToStore);
            Assert.Equal(Policy, plan.StoredFrom);
            Assert.Equal(new[] { Settings, Policy }, plan.PathsToClear);
        }

        [Fact]
        public void Blanked_policy_keeps_control_after_an_earlier_move()
        {
            // Policy's copy was moved and blanked; a value that later appears in Settings
            // must not replace what policy stored.
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Settings] = "s", [Policy] = "" }, storeHasValue: true);

            Assert.Null(plan.ValueToStore);
            Assert.Equal(new[] { Settings }, plan.PathsToClear);
        }

        [Fact]
        public void Legacy_value_fills_an_empty_store_and_is_deleted_not_blanked()
        {
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Top] = "top", [Config] = "config" }, storeHasValue: false);

            Assert.Equal("config", plan.ValueToStore);
            Assert.Empty(plan.PathsToClear);
            Assert.Equal(new[] { Config, Top }, plan.PathsToDelete);
        }

        [Fact]
        public void Legacy_value_does_not_replace_a_stored_one()
        {
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Top] = "top" }, storeHasValue: true);
            Assert.Null(plan.ValueToStore);
        }

        [Fact]
        public void Legacy_value_does_not_override_a_managed_key()
        {
            // Settings holds the name, blanked by an earlier move: it, not the legacy key, decides.
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Settings] = "", [Top] = "top" }, storeHasValue: false);
            Assert.Null(plan.ValueToStore);
        }

        [Fact]
        public void Stored_secret_beats_every_readable_source_but_the_command_line()
        {
            var inputs = new SettingsInputs
            {
                Secrets = new Dictionary<string, object> { ["Passphrase"] = Marker("store") },
                Policy = new Dictionary<string, object> { ["Passphrase"] = Marker("policy") },
                LegacyTopLevel = new Dictionary<string, object> { ["Passphrase"] = Marker("legacy") },
            };
            Assert.Equal(Marker("store"), SettingsLoader.Build(inputs)["ReportMate:Passphrase"]);

            inputs.Secrets.Clear();
            inputs.Policy.Clear();
            Assert.Equal(Marker("legacy"), SettingsLoader.Build(inputs)["ReportMate:Passphrase"]);
        }
    }

    public class LegacySettingsMigrationTests
    {
        [Fact]
        public void Copies_legacy_settings_that_settings_lacks()
        {
            var plan = LegacySettingsMigration.Plan(
                settingsNames: new[] { "LogLevel" },
                legacyConfig: new Dictionary<string, object> { ["ServerUrl"] = "https://mdm", ["LogLevel"] = "Debug" },
                legacyTopLevel: new Dictionary<string, object> { ["ApiUrl"] = "https://top", ["CollectionInterval"] = 7200 });

            Assert.Equal("https://mdm", plan["ApiUrl"]);
            Assert.Equal(7200, plan["CollectionIntervalSeconds"]);
            Assert.False(plan.ContainsKey("LogLevel"));
            Assert.False(plan.ContainsKey("ServerUrl"));
        }

        [Fact]
        public void Never_copies_credentials_or_run_state()
        {
            var plan = LegacySettingsMigration.Plan(
                settingsNames: new string[0],
                legacyConfig: new Dictionary<string, object>(),
                legacyTopLevel: new Dictionary<string, object>
                {
                    ["Passphrase"] = Marker("legacy-passphrase"),
                    ["ApiKey"] = Marker("legacy-api-key"),
                    ["LastRunTime"] = "2026-10-06",
                    ["Version"] = "1",
                });

            Assert.Empty(plan);
        }

        [Fact]
        public void An_older_spelling_in_settings_counts_as_present()
        {
            var plan = LegacySettingsMigration.Plan(
                settingsNames: new[] { "CollectionInterval" },
                legacyConfig: new Dictionary<string, object>(),
                legacyTopLevel: new Dictionary<string, object> { ["CollectionIntervalSeconds"] = 60 });

            Assert.Empty(plan);
        }

        [Fact]
        public void Current_spelling_wins_within_one_legacy_key()
        {
            var plan = LegacySettingsMigration.Plan(
                settingsNames: new string[0],
                legacyConfig: new Dictionary<string, object> { ["ServerUrl"] = "https://older", ["ApiUrl"] = "https://current" },
                legacyTopLevel: new Dictionary<string, object>());

            Assert.Equal("https://current", plan["ApiUrl"]);
        }
    }
}
