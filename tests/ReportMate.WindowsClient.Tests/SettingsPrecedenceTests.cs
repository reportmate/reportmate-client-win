using System;
using System.Collections.Generic;
using System.IO;
using ReportMate.Shared;
using ReportMate.WindowsClient.Configuration;
using Xunit;
using static ReportMate.WindowsClient.Tests.TestMarkers;

namespace ReportMate.WindowsClient.Tests
{
    public class SettingsPrecedenceTests : IDisposable
    {
        private readonly string _dir = Path.Combine(Path.GetTempPath(), "rm-settings-" + Guid.NewGuid().ToString("N"));
        private readonly string _yaml;

        public SettingsPrecedenceTests()
        {
            Directory.CreateDirectory(_dir);
            _yaml = Path.Combine(_dir, "appsettings.yaml");
            File.WriteAllText(_yaml, "ReportMate:\n  ApiUrl: https://yaml\n  DeviceId: yaml-device\n");
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { }
        }

        // Every source sets ApiUrl to its own name, so the winner is visible.
        private SettingsInputs AllSources() => new()
        {
            CommandLine = new Dictionary<string, string?> { ["ReportMate:ApiUrl"] = "https://cli" },
            Policy = new Dictionary<string, object> { ["ApiUrl"] = "https://policy" },
            Settings = new Dictionary<string, object> { ["ApiUrl"] = "https://settings" },
            LegacyConfig = new Dictionary<string, object> { ["ServerUrl"] = "https://legacy-config" },
            LegacyTopLevel = new Dictionary<string, object> { ["ApiUrl"] = "https://legacy-top" },
            Environment = new Dictionary<string, string> { ["REPORTMATE_API_URL"] = "https://env" },
            LegacySettingsFile = _yaml,
        };

        [Fact]
        public void Each_source_beats_every_source_below_it()
        {
            var inputs = AllSources();
            Assert.Equal("https://cli", SettingsLoader.Build(inputs)["ReportMate:ApiUrl"]);

            inputs.CommandLine.Clear();
            Assert.Equal("https://policy", SettingsLoader.Build(inputs)["ReportMate:ApiUrl"]);

            inputs.Policy.Clear();
            Assert.Equal("https://settings", SettingsLoader.Build(inputs)["ReportMate:ApiUrl"]);

            inputs.Settings.Clear();
            Assert.Equal("https://legacy-config", SettingsLoader.Build(inputs)["ReportMate:ApiUrl"]);

            inputs.LegacyConfig.Clear();
            Assert.Equal("https://legacy-top", SettingsLoader.Build(inputs)["ReportMate:ApiUrl"]);

            inputs.LegacyTopLevel.Clear();
            Assert.Equal("https://env", SettingsLoader.Build(inputs)["ReportMate:ApiUrl"]);

            var withoutEnv = new SettingsInputs { LegacySettingsFile = _yaml };
            Assert.Equal("https://yaml", SettingsLoader.Build(withoutEnv)["ReportMate:ApiUrl"]);

            Assert.Null(SettingsLoader.Build(new SettingsInputs())["ReportMate:ApiUrl"]);
        }

        [Fact]
        public void Environment_never_beats_policy()
        {
            var inputs = new SettingsInputs
            {
                Policy = new Dictionary<string, object> { ["Passphrase"] = Marker("policy") },
                Environment = new Dictionary<string, string>
                {
                    ["REPORTMATE_PASSPHRASE"] = Marker("env"),
                    ["REPORTMATE_ReportMate__Passphrase"] = Marker("env-nested"),
                },
            };

            Assert.Equal(Marker("policy"), SettingsLoader.Build(inputs)["ReportMate:Passphrase"]);
        }

        [Fact]
        public void Untrusted_yaml_is_not_read()
        {
            var inputs = new SettingsInputs { LegacySettingsFile = null };
            Assert.Null(SettingsLoader.Build(inputs)["ReportMate:DeviceId"]);
        }

        [Fact]
        public void Sources_fill_in_settings_a_higher_source_leaves_unset()
        {
            var inputs = AllSources();
            Assert.Equal("yaml-device", SettingsLoader.Build(inputs)["ReportMate:DeviceId"]);
        }

        [Fact]
        public void Registry_dword_booleans_become_true_or_false()
        {
            var inputs = new SettingsInputs
            {
                Policy = new Dictionary<string, object> { ["DebugLogging"] = 1, ["CompressPayload"] = 0, ["MaxRetryAttempts"] = 5 },
            };
            var config = SettingsLoader.Build(inputs);

            Assert.Equal("true", config["ReportMate:DebugLogging"]);
            Assert.Equal("false", config["ReportMate:CompressPayload"]);
            Assert.Equal("5", config["ReportMate:MaxRetryAttempts"]);
        }

        [Fact]
        public void Current_value_name_wins_over_its_older_alias_in_one_key()
        {
            var inputs = new SettingsInputs
            {
                Policy = new Dictionary<string, object>
                {
                    ["ApiUrl"] = "https://current",
                    ["ServerUrl"] = "https://older",
                    ["CollectionInterval"] = 60,
                },
            };
            var config = SettingsLoader.Build(inputs);

            Assert.Equal("https://current", config["ReportMate:ApiUrl"]);
            Assert.Equal("60", config["ReportMate:CollectionIntervalSeconds"]);
        }

        [Fact]
        public void Every_value_name_maps_to_a_setting()
        {
            Assert.Equal("ReportMate:UserAgent", ReportMateSettingsKeys.ToConfigurationKey("UserAgent"));
            Assert.Equal("Logging:LogLevel:Default", ReportMateSettingsKeys.ToConfigurationKey("LogLevel"));
        }

        [Theory]
        [InlineData(new[] { "run", "--api-url", "https://x", "--device-id", "d1" }, "https://x", "d1")]
        [InlineData(new[] { "--api-url=https://y" }, "https://y", null)]
        [InlineData(new[] { "--api-url", "--force" }, null, null)]
        [InlineData(new[] { "--force" }, null, null)]
        public void Reads_one_off_flags(string[] args, string? apiUrl, string? deviceId)
        {
            var overrides = SettingsLoader.CommandLineOverrides(args);

            Assert.Equal(apiUrl, overrides.GetValueOrDefault("ReportMate:ApiUrl"));
            Assert.Equal(deviceId, overrides.GetValueOrDefault("ReportMate:DeviceId"));
        }
    }
}
