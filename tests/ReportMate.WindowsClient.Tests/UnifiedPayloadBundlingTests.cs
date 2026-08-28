using System;
using System.Linq;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests;

/// <summary>
/// One submission per collection run, not one per module.
///
/// A scheduled run such as --run-modules security,network,management,identity,hardware
/// used to build a payload per module and POST each separately: five HTTP requests,
/// five full metadata envelopes and five identical system_info queries for an answer
/// that cannot change between them. Fleet-wide that was roughly 126 submissions per
/// Windows device per day against a schedule calling for 33 collection runs.
///
/// These cover the metadata decisions the server reads, which is where bundling can
/// silently change meaning.
/// </summary>
public class UnifiedPayloadBundlingTests
{
    [Fact]
    public void OneModuleStillReportsAsSingle()
    {
        // --run-module hardware must look exactly as it always has on the ingest
        // side; the server distinguishes an ad-hoc module run from a sweep by this.
        Assert.Equal("Single", ModularDataCollectionService.DetermineCollectionType(1));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(9)]
    public void SeveralModulesReportAsFull(int moduleCount)
    {
        Assert.Equal("Full", ModularDataCollectionService.DetermineCollectionType(moduleCount));
    }

    [Fact]
    public void InstallsIsLeftOutOfTheSummary()
    {
        // installs emits its own events conditionally. Summarising it here would
        // double-count, which is why the single-module path skipped it too.
        var summary = ModularDataCollectionService.SummaryModules(
            new[] { "inventory", "installs" });

        Assert.Equal(new[] { "inventory" }, summary);
    }

    [Fact]
    public void ARunOfOnlyInstallsProducesNoSummary()
    {
        var summary = ModularDataCollectionService.SummaryModules(new[] { "installs" });

        Assert.Empty(summary);
    }

    [Fact]
    public void InstallsIsMatchedRegardlessOfCasing()
    {
        var summary = ModularDataCollectionService.SummaryModules(
            new[] { "Installs", "INSTALLS", "hardware" });

        Assert.Equal(new[] { "hardware" }, summary);
    }

    [Fact]
    public void EmptyAndNullModuleIdsAreDropped()
    {
        var summary = ModularDataCollectionService.SummaryModules(
            new[] { "network", "", null!, "   " });

        Assert.Equal(new[] { "network" }, summary);
    }

    [Fact]
    public void SummaryModulesToleratesANullSequence()
    {
        Assert.Empty(ModularDataCollectionService.SummaryModules(null!));
    }

    [Fact]
    public void ASingleModuleKeepsItsExistingWording()
    {
        // The dashboard has shown "Hardware data reported" for a one-module run
        // since before bundling; a five-module sweep must not silently reword it.
        var message = ModularDataCollectionService.SummaryMessage(new[] { "hardware" });

        Assert.Equal("Hardware data reported", message);
    }

    [Fact]
    public void ASweepIsSummarisedByCount()
    {
        var message = ModularDataCollectionService.SummaryMessage(
            new[] { "security", "network", "management", "identity", "hardware" });

        Assert.Equal("5 modules reported", message);
    }

    [Fact]
    public void TheHourlyScheduleCollapsesToOneSubmission()
    {
        // The real hourly schedule from module-schedules.json. Before bundling
        // this run produced five submissions; it is now one, and it is a Full.
        var hourly = new[] { "security", "network", "management", "identity", "hardware" };

        Assert.Equal("Full", ModularDataCollectionService.DetermineCollectionType(hourly.Length));
        Assert.Equal(5, ModularDataCollectionService.SummaryModules(hourly).Count);
    }
}
