using System.Collections.Generic;
using ReportMate.Shared;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class CredentialMigrationTests
    {
        private const string Policy = ReportMateSettingsKeys.PolicyRegistryPath;
        private const string Settings = ReportMateSettingsKeys.SettingsRegistryPath;
        private const string Config = ReportMateSettingsKeys.LegacyConfigRegistryPath;
        private const string Top = ReportMateSettingsKeys.LegacyRegistryPath;

        [Fact]
        public void Legacy_credential_is_stored_and_every_legacy_copy_deleted()
        {
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Config] = "config", [Top] = "top" }, storeHasValue: false);

            Assert.Equal("config", plan.ValueToStore);
            Assert.Equal(Config, plan.StoredFrom);
            Assert.Equal(new[] { Config, Top }, plan.PathsToDelete);
            Assert.Empty(plan.PathsToClear);
        }

        [Fact]
        public void Legacy_copy_is_deleted_without_replacing_a_stored_value()
        {
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Top] = "top" }, storeHasValue: true);

            Assert.Null(plan.ValueToStore);
            Assert.Equal(new[] { Top }, plan.PathsToDelete);
        }

        [Fact]
        public void Managed_value_wins_and_legacy_copies_are_still_deleted()
        {
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Policy] = "p", [Top] = "top" }, storeHasValue: false);

            Assert.Equal("p", plan.ValueToStore);
            Assert.Equal(new[] { Policy }, plan.PathsToClear);
            Assert.Equal(new[] { Top }, plan.PathsToDelete);
        }

        [Fact]
        public void Empty_legacy_value_is_left_alone()
        {
            var plan = SecretStore.Plan(new Dictionary<string, string?> { [Top] = "" }, storeHasValue: false);

            Assert.Null(plan.ValueToStore);
            Assert.Empty(plan.PathsToDelete);
        }

        [Theory]
        [InlineData("secret", "secret", true)]
        [InlineData("secret", "Secret", false)]
        [InlineData("secret", null, false)]
        [InlineData(null, "already-stored", true)]
        [InlineData(null, null, false)]
        [InlineData(null, "", false)]
        public void Copies_are_removed_only_when_the_store_reads_back(string? written, string? readBack, bool verified)
        {
            Assert.Equal(verified, SecretStore.IsVerified(written, readBack));
        }

        [Theory]
        [InlineData(false, false, CredentialStatus.UnlockToView)]
        [InlineData(false, true, CredentialStatus.UnlockToView)]
        [InlineData(true, false, "Not saved")]
        [InlineData(true, true, "Saved — enter a new value to replace it")]
        public void App_shows_saved_state_only_once_unlocked(bool elevated, bool saved, string expected)
        {
            Assert.Equal(expected, CredentialStatus.Describe(elevated, saved));
        }
    }
}
