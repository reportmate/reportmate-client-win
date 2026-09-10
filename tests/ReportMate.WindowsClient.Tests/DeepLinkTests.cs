using ReportMate.App.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests;

/// <summary>
/// The link spec is shared with the Mac app and the web dashboard: one link has to open
/// the same view in all three. These cases are that contract.
/// </summary>
public class DeepLinkTests
{
    [Theory]
    [InlineData("reportmate://dashboard", "dashboard")]
    [InlineData("reportmate://devices", "devices")]
    [InlineData("reportmate://events", "events")]
    [InlineData("reportmate://installs", "installs")]
    [InlineData("reportmate://applications", "applications")]
    [InlineData("reportmate://system", "system")]
    [InlineData("reportmate://management", "management")]
    [InlineData("reportmate://identity", "identity")]
    [InlineData("reportmate://hardware", "hardware")]
    [InlineData("reportmate://peripherals", "peripherals")]
    [InlineData("reportmate://security", "security")]
    [InlineData("reportmate://network", "network")]
    [InlineData("reportmate://settings", "settings")]
    public void ParsesEverySection(string url, string expected) =>
        Assert.Equal(expected, DeepLink.Parse(url)!.Section);

    [Fact]
    public void BareSchemeOpensTheDashboard() =>
        Assert.Equal("dashboard", DeepLink.Parse("reportmate://")!.Section);

    [Theory]
    [InlineData("reportmate://this-device")]
    [InlineData("reportmate://this-pc")]
    [InlineData("reportmate://this-mac")]
    [InlineData("reportmate://local")]
    public void EachPlatformsLocalAliasResolvesToThisDevice(string url) =>
        Assert.Equal("this-device", DeepLink.Parse(url)!.Section);

    [Fact]
    public void DeviceLinkCarriesSerialAndTab()
    {
        var link = DeepLink.Parse("reportmate://device/ABC123?tab=installs&filter=errors")!;
        Assert.Equal("device", link.Section);
        Assert.Equal("ABC123", link.Argument);
        Assert.Equal("installs", link.DeviceTab);
        Assert.Equal("errors", link["filter"]);
    }

    [Fact]
    public void WebFragmentIsAcceptedAsTheTab()
    {
        // The web device page carries its tab as the fragment rather than a query value.
        var link = DeepLink.Parse("https://reportmate.example.org/device/ABC123#installs")!;
        Assert.Equal("device", link.Section);
        Assert.Equal("ABC123", link.Argument);
        Assert.Equal("installs", link.DeviceTab);
    }

    [Fact]
    public void ExplicitTabWinsOverTheFragment()
    {
        var link = DeepLink.Parse("https://host.example.org/device/A1?tab=security#installs")!;
        Assert.Equal("security", link.DeviceTab);
    }

    [Fact]
    public void SwappedSchemeKeepingTheWebHostIgnoresTheHost()
    {
        // reportmate://host/device/X - a host with a dot is the web host, not a section.
        var link = DeepLink.Parse("reportmate://reportmate.example.org/device/ABC123")!;
        Assert.Equal("device", link.Section);
        Assert.Equal("ABC123", link.Argument);
    }

    [Fact]
    public void HandoffRouteResolvesToTheSameView()
    {
        var link = DeepLink.Parse("https://host.example.org/open/device/ABC123?filter=errors#installs")!;
        Assert.Equal("device", link.Section);
        Assert.Equal("ABC123", link.Argument);
        Assert.Equal("installs", link.DeviceTab);
        Assert.Equal("errors", link["filter"]);
    }

    [Fact]
    public void EventsFailuresKeepsItsSubRoute()
    {
        var link = DeepLink.Parse("reportmate://events/failures")!;
        Assert.Equal("events", link.Section);
        Assert.Equal("failures", link.Argument);
    }

    [Fact]
    public void ApplicationUsageDrillDownKeepsItsArgumentAndQuery()
    {
        var link = DeepLink.Parse("reportmate://applications/usage/Google%20Chrome?days=30")!;
        Assert.Equal("applications", link.Section);
        Assert.Equal("usage/Google Chrome", link.Argument);
        Assert.Equal("30", link["days"]);
    }

    [Fact]
    public void DeviceFiltersArePassedThroughExactly()
    {
        var link = DeepLink.Parse("reportmate://devices?status=active&search=lab&usage=&catalog=")!;
        Assert.Equal("active", link["status"]);
        Assert.Equal("lab", link["search"]);
        // An empty value is absent rather than an empty filter.
        Assert.Null(link["usage"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a url")]
    [InlineData("mailto:someone@example.org")]
    [InlineData("reportmate://not-a-section")]
    public void NonLinksAreRejected(string input) => Assert.Null(DeepLink.Parse(input));

    [Fact]
    public void ProfilesRoutesToManagement() =>
        Assert.Equal("management", DeepLink.Parse("reportmate://profiles")!.Section);

    // ── Building links ───────────────────────────────────────────────────

    [Fact]
    public void AppLinkRoundTrips()
    {
        var built = DeepLink.For("device", "ABC123", ("tab", "installs")).ToAppUrl();
        Assert.Equal("reportmate://device/ABC123?tab=installs", built);

        var reparsed = DeepLink.Parse(built)!;
        Assert.Equal("ABC123", reparsed.Argument);
        Assert.Equal("installs", reparsed.DeviceTab);
    }

    [Fact]
    public void HandoffLinkIsTheWebRouteUnderOpen()
    {
        var link = DeepLink.For("device", "ABC123", ("tab", "installs"));
        Assert.Equal("https://host.example.org/open/device/ABC123?tab=installs",
            link.ToHandoffUrl("https://host.example.org"));
        Assert.Equal("https://host.example.org/device/ABC123?tab=installs",
            link.ToWebUrl("https://host.example.org"));
    }

    [Fact]
    public void TrailingSlashOnTheWebHostDoesNotDoubleUp() =>
        Assert.Equal("https://host.example.org/dashboard",
            DeepLink.For("dashboard").ToWebUrl("https://host.example.org/"));

    [Fact]
    public void EmptyFiltersAreLeftOutOfABuiltLink() =>
        Assert.Equal("reportmate://devices?status=active",
            DeepLink.For("devices", null, ("status", "active"), ("search", ""), ("area", null)).ToAppUrl());

    [Fact]
    public void WithNoWebUrlConfiguredTheLinkStaysAnAppLink() =>
        Assert.Equal("reportmate://dashboard", DeepLink.For("dashboard").ToWebUrl(""));
}
