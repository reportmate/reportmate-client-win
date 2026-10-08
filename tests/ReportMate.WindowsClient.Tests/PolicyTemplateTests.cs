#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using ReportMate.Shared;
using ReportMate.WindowsClient.Configuration;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// The ADMX in resources/ must offer every Prefs setting, under the key the client reads,
    /// with the registry type the client parses. A setting the template misses cannot be
    /// managed; one written as the wrong type is silently ignored by the runner.
    /// </summary>
    public class PolicyTemplateTests
    {
        private static readonly XNamespace Ns = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";

        private static string RepoRoot()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ReportMate.sln")))
                dir = dir.Parent;
            return dir?.FullName ?? throw new InvalidOperationException("ReportMate.sln not found above the test output");
        }

        private static readonly Lazy<XDocument> Admx = new(() => XDocument.Load(Path.Combine(RepoRoot(), "resources", "ReportMate.admx")));
        private static readonly Lazy<XDocument> Adml = new(() => XDocument.Load(Path.Combine(RepoRoot(), "resources", "en-US", "ReportMate.adml")));

        private static IEnumerable<XElement> Policies => Admx.Value.Descendants(Ns + "policy");

        /// <summary>Value name to how the template writes it: "boolean", "decimal", "text" or "enum".</summary>
        private static Dictionary<string, string> WrittenValues()
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var policy in Policies)
            {
                if (policy.Attribute("valueName") is { } direct)
                    result.Add(direct.Value, "boolean");
                foreach (var element in policy.Element(Ns + "elements")?.Elements() ?? [])
                    result.Add(element.Attribute("valueName")!.Value, element.Name.LocalName);
            }
            return result;
        }

        [Fact]
        public void EveryPolicyWritesTheKeyTheClientReads()
        {
            Assert.All(Policies, p =>
            {
                Assert.Equal(ReportMateSettingsKeys.PolicyRegistryPath, p.Attribute("key")!.Value);
                Assert.Equal("Machine", p.Attribute("class")!.Value);
            });
        }

        [Fact]
        public void EveryPrefsSettingHasAPolicyUnderItsCurrentName()
        {
            var written = WrittenValues().Keys.ToHashSet();
            Assert.Equal(PrefsSettingWrites.SettingNames.OrderBy(n => n), written.OrderBy(n => n));
            foreach (var name in PrefsSettingWrites.SettingNames)
                Assert.Equal(name, ReportMateSettingsKeys.PolicyValueNames[name][0]);
        }

        [Fact]
        public void TheAppWatchesEveryPrefsSettingUnderPolicy() =>
            Assert.Equal(PrefsSettingWrites.SettingNames.OrderBy(n => n), ReportMateSettingsKeys.PolicyValueNames.Keys.OrderBy(n => n));

        [Fact]
        public void EachValueIsWrittenAsTheTypeTheClientParses()
        {
            foreach (var (name, kind) in WrittenValues())
            {
                var isBoolean = ReportMateSettingsKeys.BooleanValueNames.Contains(name);
                var isDword = PrefsSettingWrites.DwordValueNames.Contains(name);
                switch (kind)
                {
                    case "boolean":
                        Assert.True(isBoolean && isDword, $"{name} is a toggle in the template but not a DWORD boolean in the client");
                        break;
                    case "decimal":
                        Assert.True(isDword && !isBoolean, $"{name} is a number in the template but not a DWORD number in the client");
                        break;
                    default:
                        Assert.False(isDword, $"{name} is a string in the template but a DWORD in the client");
                        break;
                }
            }
        }

        [Fact]
        public void BooleanPoliciesWriteOneAndZero()
        {
            foreach (var policy in Policies.Where(p => p.Attribute("valueName") is not null))
            {
                Assert.Equal("1", policy.Element(Ns + "enabledValue")!.Element(Ns + "decimal")!.Attribute("value")!.Value);
                Assert.Equal("0", policy.Element(Ns + "disabledValue")!.Element(Ns + "decimal")!.Attribute("value")!.Value);
            }
        }

        [Fact]
        public void StorageModeOffersExactlyTheModesTheRunnerAccepts()
        {
            var values = Policies.Single(p => p.Attribute("name")!.Value == "StorageMode")
                .Descendants(Ns + "string").Select(s => s.Value);
            Assert.Equal(ReportMateSettingsKeys.StorageModes.OrderBy(v => v), values.OrderBy(v => v));
        }

        [Fact]
        public void EveryStringPresentationAndCategoryResolves()
        {
            var strings = Adml.Value.Descendants(Ns + "string").Select(s => s.Attribute("id")!.Value).ToHashSet();
            var presentations = Adml.Value.Descendants(Ns + "presentation").ToDictionary(p => p.Attribute("id")!.Value);
            var categories = Admx.Value.Descendants(Ns + "category").Select(c => c.Attribute("name")!.Value).ToHashSet();
            var admxText = Admx.Value.ToString();

            foreach (Match m in Regex.Matches(admxText, @"\$\(string\.([^)]+)\)"))
                Assert.Contains(m.Groups[1].Value, strings);

            foreach (var policy in Policies)
            {
                Assert.Contains(policy.Element(Ns + "parentCategory")!.Attribute("ref")!.Value, categories);
                var elementIds = (policy.Element(Ns + "elements")?.Elements() ?? []).Select(e => e.Attribute("id")!.Value).ToList();
                if (policy.Attribute("presentation") is not { } pres)
                {
                    Assert.Empty(elementIds);
                    continue;
                }
                var id = Regex.Match(pres.Value, @"^\$\(presentation\.([^)]+)\)$").Groups[1].Value;
                Assert.True(presentations.TryGetValue(id, out var presentation), $"presentation {id} missing");
                var refIds = presentation!.Elements().Select(e => e.Attribute("refId")!.Value).ToList();
                Assert.Equal(elementIds.OrderBy(x => x), refIds.OrderBy(x => x));
            }
        }

        [Theory]
        [InlineData("ApiKey_Help")]
        [InlineData("Passphrase_Help")]
        public void SecretPoliciesSayTheValueIsReadableOnTheDevice(string helpId)
        {
            var help = Adml.Value.Descendants(Ns + "string").Single(s => s.Attribute("id")!.Value == helpId).Value;
            Assert.Contains("every user on the device can read", help);
            Assert.Contains(SecretStore.RegistryPath, help);
        }
    }

    public class StorageModeResolutionTests
    {
        [Theory]
        [InlineData("deep", true, "quick", "deep")]     // an explicit flag wins
        [InlineData("auto", false, "quick", "quick")]   // the flag's default does not
        [InlineData(null, false, "DEEP", "deep")]
        [InlineData(null, false, null, "auto")]
        [InlineData(null, false, "everything", "auto")]
        [InlineData("bogus", true, "quick", "auto")]
        public void FlagThenSettingThenAuto(string? flag, bool given, string? configured, string expected) =>
            Assert.Equal(expected, ReportMateSettingsKeys.ResolveStorageMode(flag, given, configured));
    }

    public class RunnerHttpHandlerTests
    {
        private static IConfiguration Config(params (string Key, string Value)[] values) =>
            new ConfigurationBuilder()
                .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
                .Build();

        [Fact]
        public void NoSettingsLeavesTheDefaults()
        {
            using var handler = RunnerHttpHandler.Create(Config());
            Assert.Null(handler.ServerCertificateCustomValidationCallback);
            Assert.Null(RunnerHttpHandler.ProxyFrom(Config()));
        }

        [Theory]
        [InlineData("ReportMate:ProxyUrl", "http://proxy.example.com:8080")]
        [InlineData("ReportMate:Proxy:Url", "http://proxy.example.com:8080")]
        public void UsesTheConfiguredProxy(string key, string url)
        {
            using var handler = RunnerHttpHandler.Create(Config((key, url)));
            Assert.True(handler.UseProxy);
            Assert.Equal(new Uri(url), handler.Proxy!.GetProxy(new Uri("https://api.example.org/")));
        }

        [Theory]
        [InlineData("proxy.example.com:8080")]
        [InlineData("ftp://proxy.example.com")]
        [InlineData("   ")]
        public void IgnoresAProxyThatIsNotAnHttpUrl(string url) =>
            Assert.Null(RunnerHttpHandler.ProxyFrom(Config(("ReportMate:ProxyUrl", url))));

        [Theory]
        [InlineData("true", true)]
        [InlineData("True", true)]
        [InlineData("false", false)]
        [InlineData("1", false)]
        public void SkipsValidationOnlyWhenExplicitlyTrue(string value, bool skips)
        {
            var config = Config(("ReportMate:SkipCertificateValidation", value));
            Assert.Equal(skips, RunnerHttpHandler.SkipsCertificateValidation(config));
            using var handler = RunnerHttpHandler.Create(config);
            Assert.Equal(skips, handler.ServerCertificateCustomValidationCallback is not null);
        }

        [Fact]
        public void APolicyDwordOneReachesTheHandlerAsTrue()
        {
            // The registry layer turns a boolean DWORD into "true"/"false" before the handler sees it.
            var fromPolicy = SettingsLoader.FromRegistry(new Dictionary<string, object> { ["SkipCertificateValidation"] = 1 });
            Assert.Equal("true", fromPolicy["ReportMate:SkipCertificateValidation"]);
        }
    }
}
