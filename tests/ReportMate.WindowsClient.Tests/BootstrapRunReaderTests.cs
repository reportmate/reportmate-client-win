#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// Pins the records BootstrapMate writes, in the shape it writes them: status.json keyed
    /// by phase with enum numbers for Stage, last-run.json in snake_case, and the registry's
    /// LastRunVersion that exists only after a clean run.
    /// </summary>
    public class BootstrapRunReaderTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "rm-bootstrap-" + Guid.NewGuid().ToString("N"));

        private const string StatusJson = @"{
  ""SetupAssistant"": { ""Stage"": 2, ""StartTime"": ""2026-10-04 03:00:05"", ""CompletionTime"": ""2026-10-04 03:03:40"", ""ExitCode"": 0, ""Version"": ""2026.10.04.1200"", ""Phase"": 0, ""Architecture"": ""X64"", ""BootstrapUrl"": ""https://example.com/bootstrap.json?sig=abc"", ""LastError"": """", ""RunId"": ""run-1"" },
  ""Userland"": { ""Stage"": 4, ""StartTime"": ""2026-10-04 03:04:12"", ""CompletionTime"": ""2026-10-04 03:04:12"", ""ExitCode"": 0, ""Version"": ""2026.10.04.1200"", ""Phase"": 1, ""Architecture"": ""X64"", ""BootstrapUrl"": """", ""LastError"": """", ""RunId"": ""run-1"" },
  ""Preflight"": { ""Stage"": 2, ""StartTime"": ""2026-10-04 03:00:01"", ""CompletionTime"": ""2026-10-04 03:00:04"", ""ExitCode"": 2, ""Version"": ""2026.10.04.1200"", ""Phase"": 2, ""Architecture"": ""X64"", ""BootstrapUrl"": """", ""LastError"": """", ""RunId"": ""run-1"" }
}";

        private const string LastRunJson = @"{
  ""session_id"": ""2026-10-04-030001"",
  ""run_type"": ""baseline"",
  ""status"": ""partial_failure"",
  ""tool_version"": ""2026.10.04.1200"",
  ""start_time"": ""2026-10-04T03:00:01.120-07:00"",
  ""end_time"": ""2026-10-04T03:04:12.480-07:00"",
  ""duration_seconds"": 251,
  ""errors"": 1,
  ""warnings"": 0,
  ""items"": [
    { ""name"": ""Example Agent"", ""stage"": ""setupassistant"", ""result"": ""skipped"" },
    { ""name"": ""Example Tools"", ""stage"": ""setupassistant"", ""result"": ""failed"", ""error"": ""Download stalled: no data for 60 seconds"" },
    { ""name"": ""Example Runtime"", ""stage"": ""setupassistant"", ""result"": ""installed"" }
  ]
}";

        public BootstrapRunReaderTests()
        {
            Directory.CreateDirectory(Path.Combine(_root, "ManagedBootstrap"));
        }

        public void Dispose()
        {
            try { Directory.Delete(_root, recursive: true); } catch { }
        }

        [Fact]
        public void NoRecordsIsNull()
        {
            Assert.Null(BootstrapRunReader.Build(null, null, null, null));
        }

        [Fact]
        public void StatusJsonPhasesReadInRunOrderWithStageNames()
        {
            var run = BootstrapRunReader.Build("2026.10.04.1200", StatusJson, null, null)!;

            Assert.Equal("status.json", run.PhaseSource);
            Assert.Equal(new[] { "Preflight", "SetupAssistant", "Userland" }, run.Phases.Select(p => p.Name));
            Assert.Equal(new[] { "Completed", "Completed", "Skipped" }, run.Phases.Select(p => p.Stage));
            Assert.Equal(2, run.Phases[0].ExitCode);
            Assert.Equal("completed", run.Result);
            Assert.Equal("2026.10.04.1200", run.Version);
            Assert.Equal("2026.10.04.1200", run.LastRunVersion);
        }

        [Fact]
        public void PhaseTimesBecomeIsoWithOffset()
        {
            var run = BootstrapRunReader.Build(null, StatusJson, null, null)!;

            Assert.StartsWith("2026-10-04T03:04:12", run.CompletedAt);
            Assert.True(DateTimeOffset.TryParse(run.CompletedAt, out _));
        }

        [Fact]
        public void LastRunDecidesTheResultAndCompletedTime()
        {
            var run = BootstrapRunReader.Build(null, StatusJson, null, LastRunJson)!;

            Assert.Equal("partial_failure", run.Result);
            Assert.Equal("2026-10-04T03:04:12.480-07:00", run.CompletedAt);
            Assert.Null(run.LastRunVersion);
            var lastRun = run.LastRun!;
            Assert.Equal("baseline", lastRun.RunType);
            Assert.Equal(251, lastRun.DurationSeconds);
            Assert.Equal(1, lastRun.ItemsInstalled);
            Assert.Equal(1, lastRun.ItemsSkipped);
            Assert.Equal(1, lastRun.ItemsFailed);
            Assert.Equal("Example Tools", lastRun.FailedItems.Single().Name);
            Assert.Equal("Download stalled: no data for 60 seconds", lastRun.FailedItems.Single().Error);
        }

        [Fact]
        public void RunningRecordHasNoCompletedTime()
        {
            const string running = @"{ ""session_id"": ""s"", ""run_type"": ""provisioning"", ""status"": ""running"", ""tool_version"": ""2026.10.04.1200"", ""start_time"": ""2026-10-04T03:00:01-07:00"", ""end_time"": null, ""duration_seconds"": null, ""errors"": 0, ""warnings"": 0, ""items"": [] }";

            var run = BootstrapRunReader.Build(null, null, null, running)!;

            Assert.Equal("running", run.Result);
            Assert.Null(run.CompletedAt);
            Assert.Null(run.LastRun!.DurationSeconds);
        }

        [Fact]
        public void FailedPhaseIsAFailedRun()
        {
            var phases = new List<BootstrapPhase>
            {
                new() { Name = "Userland", Stage = "Skipped" },
                new() { Name = "SetupAssistant", Stage = "Failed", LastError = "Manifest would not load" },
                new() { Name = "Preflight", Stage = "Completed" }
            };

            var run = BootstrapRunReader.Build(null, null, phases, null)!;

            Assert.Equal("registry", run.PhaseSource);
            Assert.Equal("failed", run.Result);
            Assert.Equal("Preflight", run.Phases[0].Name);
        }

        [Fact]
        public void RegistryIsUsedOnlyWhenStatusJsonHasNoPhases()
        {
            var phases = new List<BootstrapPhase> { new() { Name = "Preflight", Stage = "Running" } };

            Assert.Equal("status.json", BootstrapRunReader.Build(null, StatusJson, phases, null)!.PhaseSource);
            Assert.Equal("registry", BootstrapRunReader.Build(null, "{ not json", phases, null)!.PhaseSource);
            Assert.Equal("running", BootstrapRunReader.Build(null, "{ not json", phases, null)!.Result);
        }

        [Fact]
        public void LastRunVersionAloneIsStillARecord()
        {
            var run = BootstrapRunReader.Build("2025.08.30.1300", null, null, null)!;

            Assert.Equal("2025.08.30.1300", run.LastRunVersion);
            Assert.Equal("2025.08.30.1300", run.Version);
            Assert.Null(run.Result);
            Assert.Empty(run.Phases);
        }

        [Fact]
        public void StringStagesAndLongErrorsAreHandled()
        {
            var longError = new string('x', 300) + "\nsecond line";
            var json = "{ \"Preflight\": { \"Stage\": \"Failed\", \"ExitCode\": 1, \"LastError\": \"" + longError.Replace("\n", "\\n") + "\" } }";

            var phase = BootstrapRunReader.ParseStatusJson(json).Single();

            Assert.Equal("Failed", phase.Stage);
            Assert.Equal(200, phase.LastError!.Length);
            Assert.DoesNotContain("second", phase.LastError);
        }

        [Fact]
        public void ReadPicksUpTheFilesUnderProgramData()
        {
            File.WriteAllText(Path.Combine(_root, "ManagedBootstrap", "status.json"), StatusJson);
            File.WriteAllText(Path.Combine(_root, "ManagedBootstrap", "last-run.json"), LastRunJson);

            var run = BootstrapRunReader.Read(_root)!;

            Assert.Equal("partial_failure", run.Result);
            Assert.Equal(3, run.Phases.Count);
        }

        [Fact]
        public void ManifestUrlIsNotCarried()
        {
            var serialized = System.Text.Json.JsonSerializer.Serialize(BootstrapRunReader.Build(null, StatusJson, null, LastRunJson));

            Assert.DoesNotContain("sig=abc", serialized);
            Assert.DoesNotContain("BootstrapUrl", serialized);
        }
    }
}
