#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class BoundedProcessTests
    {
        private static ProcessStartInfo Cmd(string command) => new("cmd.exe", $"/d /c {command}");

        [Fact]
        public async Task AChildThatNeverReturnsIsKilledAtTheTimeout()
        {
            var clock = Stopwatch.StartNew();

            var run = await BoundedProcess.RunAsync(Cmd("echo started& ping -n 60 127.0.0.1 >nul"), TimeSpan.FromSeconds(2));

            Assert.True(run.TimedOut);
            Assert.Null(run.ExitCode);
            Assert.False(run.Succeeded);
            Assert.Contains("started", run.Output);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20), $"took {clock.Elapsed}");
        }

        [Fact]
        public async Task AHungPowerShellScriptIsKilledAtTheTimeout()
        {
            var clock = Stopwatch.StartNew();

            var run = await BoundedProcess.RunPowerShellAsync("Start-Sleep -Seconds 120", TimeSpan.FromSeconds(3));

            Assert.True(run.TimedOut);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), $"took {clock.Elapsed}");
        }

        [Fact]
        public async Task TheRunnerReturnsNullWhenPowerShellTimesOut()
        {
            var output = await PowerShellRunner.ExecuteAsync(
                "Write-Output early; Start-Sleep -Seconds 120", NullLogger.Instance, TimeSpan.FromSeconds(3));

            Assert.Null(output);
        }

        [Fact]
        public async Task AChildThatFinishesReturnsItsOutputAndExitCode()
        {
            var run = await BoundedProcess.RunAsync(Cmd("echo hello& exit /b 3"), TimeSpan.FromSeconds(30));

            Assert.False(run.TimedOut);
            Assert.Equal(3, run.ExitCode);
            Assert.Equal("hello", run.Output.Trim());
        }

        [Fact]
        public async Task OutputLargerThanThePipeBufferDoesNotStall()
        {
            var run = await BoundedProcess.RunPowerShellAsync("1..20000 | ForEach-Object { 'line ' + $_ }", TimeSpan.FromSeconds(60));

            Assert.True(run.Succeeded);
            Assert.EndsWith("line 20000", run.Output.Trim());
        }

        [Fact]
        public void TheSummaryIsTheFirstNonEmptyLine() =>
            Assert.Equal("try {", PowerShellRunner.Summarize("\r\n   \r\n  try {\r\n  Get-Thing\r\n}"));
    }

    public class ComputerSystemIdentityTests
    {
        [Fact]
        public void AJoinedMachineReportsItsDomain()
        {
            var identity = ComputerSystemIdentity.From(new Dictionary<string, object?>
            {
                ["Name"] = "HOST-01",
                ["Domain"] = "corp.example",
                ["Workgroup"] = null,
                ["PartOfDomain"] = true,
            });

            Assert.Equal(new ComputerSystemIdentity("HOST-01", "corp.example", null), identity);
        }

        [Fact]
        public void AWorkgroupMachineHasNoDomain()
        {
            var identity = ComputerSystemIdentity.From(new Dictionary<string, object?>
            {
                ["Name"] = "HOST-02",
                ["Domain"] = "WORKGROUP",
                ["Workgroup"] = "WORKGROUP",
                ["PartOfDomain"] = false,
            });

            Assert.Equal(new ComputerSystemIdentity("HOST-02", null, "WORKGROUP"), identity);
        }

        [Fact]
        public void AnEmptyRowHasNothing() =>
            Assert.Equal(new ComputerSystemIdentity(null, null, null),
                ComputerSystemIdentity.From(new Dictionary<string, object?>()));
    }
}
