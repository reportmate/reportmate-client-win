using System.Windows;
using System.Windows.Controls;
using ReportMate.App.Services;
using ReportMate.App.Views.Shared;

namespace ReportMate.App.Views.Fleet;

/// <summary>The web app's fleet events view.</summary>
public sealed class EventsPage : FleetPage
{
    protected override async Task<UIElement> BuildAsync()
    {
        var result = await FleetApiClient.Instance.GetEventsAsync(500);
        if (!result.Ok) return FleetUnavailable(result.Status, result.Detail);

        var events = result.Data!.Events;
        var page = new StackPanel();
        page.Children.Add(Ui.TabHeader("Events", "What the fleet has reported", "", Accent.Cyan,
            Ui.Caption($"{events.Count:N0} events")));

        if (events.Count == 0)
        {
            page.Children.Add(Ui.Card(Ui.EmptyState("No events have been reported.")));
            return page;
        }

        var rows = events
            .OrderByDescending(e => e.When ?? DateTime.MinValue)
            .Select(e => new EventRow
            {
                Kind = Format.Capitalize(e.Kind ?? e.EventType ?? "info"),
                KindTone = Classify(e.Kind ?? e.EventType),
                Device = e.DeviceName ?? e.SerialNumber ?? e.Device ?? "",
                Message = e.Message ?? "",
                When = e.When,
            })
            .ToList();

        var table = new FilteredTable<EventRow>("Events", "{0} of {1} events", rows,
            (r, q) => r.Matches(q),
            [
                Col.Pill("Kind", "Kind", "KindTone", 110),
                Col.Text("Device", "Device", 220),
                Col.Text("Message", "Message", star: true, wrap: true),
                Col.Text("When", "WhenLabel", 130),
            ], "Search events...", "No events match the current filters")
            .Filter([
                new("all", "All", rows.Count),
                new("error", "Errors", rows.Count(r => r.KindTone == Tone.Error)),
                new("warning", "Warnings", rows.Count(r => r.KindTone == Tone.Warning)),
            ], (r, k) => k switch
            {
                "error" => r.KindTone == Tone.Error,
                "warning" => r.KindTone == Tone.Warning,
                _ => true,
            }, initial: InitialFilter())
            .WithQuery(Filter("q"))
            .Build();

        table.Margin = new Thickness(0, 20, 0, 0);
        page.Children.Add(table);
        return page;
    }

    /// <summary>
    /// The events route carries its filter as a comma-separated list and has a failures
    /// sub-route; both mean the same thing to a single-choice filter here, so the first
    /// recognised kind wins.
    /// </summary>
    private string InitialFilter()
    {
        if (string.Equals(Link?.Argument, "failures", StringComparison.OrdinalIgnoreCase)) return "error";
        var raw = Filter("filter");
        if (raw is null) return "all";
        foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            switch (part.ToLowerInvariant())
            {
                case "errors" or "error": return "error";
                case "warnings" or "warning": return "warning";
            }
        return "all";
    }

    private static Tone Classify(string? kind) => (kind ?? "").ToLowerInvariant() switch
    {
        "error" or "failed" or "failure" => Tone.Error,
        "warning" or "warn" => Tone.Warning,
        "success" or "installed" => Tone.Success,
        _ => Tone.Neutral,
    };

    private sealed class EventRow
    {
        public string Kind { get; init; } = "";
        public Tone KindTone { get; init; }
        public string Device { get; init; } = "";
        public string Message { get; init; } = "";
        public DateTime? When { get; init; }

        public string WhenLabel
        {
            get
            {
                if (When is null) return "unknown";
                var delta = DateTime.UtcNow - When.Value.ToUniversalTime();
                if (delta < TimeSpan.FromMinutes(1)) return "just now";
                if (delta < TimeSpan.FromHours(1)) return $"{(int)delta.TotalMinutes}m ago";
                if (delta < TimeSpan.FromDays(1)) return $"{(int)delta.TotalHours}h ago";
                return $"{(int)delta.TotalDays}d ago";
            }
        }

        public bool Matches(string query) =>
            string.IsNullOrWhiteSpace(query)
            || $"{Kind} {Device} {Message}".Contains(query, StringComparison.OrdinalIgnoreCase);
    }
}
