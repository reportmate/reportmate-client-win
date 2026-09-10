// Explicit usings: this file is also compiled into the test project, which does not
// enable implicit usings.
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;

namespace ReportMate.App.Services;

/// <summary>
/// A parsed <c>reportmate://</c> link: which section to open and the filters that
/// section should apply. Links are the web routes with the scheme swapped, so one
/// link opens the same view in the Windows app, the Mac app or the web dashboard.
/// </summary>
public sealed record DeepLink(string Section, string? Argument, NameValueCollection Query)
{
    /// <summary>The web routes, and therefore the link sections, both apps understand.</summary>
    public static readonly string[] Sections =
    [
        "dashboard", "devices", "device", "events", "installs", "applications",
        "system", "management", "identity", "hardware", "peripherals", "security",
        "network", "settings", "this-device",
    ];

    public string? this[string key] => string.IsNullOrEmpty(Query[key]) ? null : Query[key];

    /// <summary>
    /// Parse a link. Accepts the app form (<c>reportmate://device/ABC123?tab=installs</c>),
    /// a pasted web URL (<c>https://host/device/ABC123#installs</c>), the swapped form that
    /// keeps the web host (<c>reportmate://host/device/ABC123</c>), and the web handoff
    /// route (<c>/open/device/ABC123</c>). Returns null when it is not a ReportMate link.
    /// </summary>
    public static DeepLink? Parse(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var text = raw.Trim().Trim('"');

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)) return null;
        var isApp = uri.Scheme.Equals("reportmate", StringComparison.OrdinalIgnoreCase);
        if (!isApp && uri.Scheme is not ("http" or "https")) return null;

        // For the app scheme the "host" is really the first path segment, unless it
        // carries a dot -- then it is the web host the link was swapped from, and the
        // route starts after it.
        var segments = new List<string>();
        if (isApp && !string.IsNullOrEmpty(uri.Host) && !uri.Host.Contains('.'))
            segments.Add(uri.Host);
        segments.AddRange(uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(Uri.UnescapeDataString));

        // The web handoff route is the same link one level down.
        if (segments.Count > 0 && segments[0].Equals("open", StringComparison.OrdinalIgnoreCase))
            segments.RemoveAt(0);

        if (segments.Count == 0) return new DeepLink("dashboard", null, Parameters(uri));

        var section = Normalize(segments[0]);
        if (section is null) return null;

        var argument = segments.Count > 1 ? string.Join('/', segments.Skip(1)) : null;
        var query = Parameters(uri);

        // The web device page carries its tab as the fragment; the app form uses ?tab=.
        var fragment = uri.Fragment.TrimStart('#');
        if (!string.IsNullOrWhiteSpace(fragment) && string.IsNullOrEmpty(query["tab"]))
            query["tab"] = Uri.UnescapeDataString(fragment);

        return new DeepLink(section, argument, query);
    }

    private static NameValueCollection Parameters(Uri uri)
    {
        // ParseQueryString on an empty string still yields a usable collection, so
        // callers never have to null-check the query.
        var parsed = HttpUtility.ParseQueryString(uri.Query);
        var copy = HttpUtility.ParseQueryString("");
        foreach (string? key in parsed)
            if (key is not null) copy[key] = parsed[key];
        return copy;
    }

    /// <summary>Map a route segment onto a section, allowing each platform's local aliases.</summary>
    private static string? Normalize(string segment)
    {
        var s = segment.ToLowerInvariant();
        return s switch
        {
            "this-device" or "this-pc" or "this-mac" or "local" => "this-device",
            // The web nav carries both of these; neither is a section of its own here.
            "profiles" => "management",
            "inventory" => "devices",
            _ => Sections.Contains(s) ? s : null,
        };
    }

    /// <summary>
    /// The tab a device link should open, accepting the web page's own fragment names.
    /// </summary>
    public string? DeviceTab => this["tab"];

    // ── Building links ───────────────────────────────────────────────────

    /// <summary>
    /// The raw app link. Opens instantly where the app is installed, and nowhere else.
    /// The tab leads the query and the rest is sorted, so this app and the Mac app emit
    /// byte-identical links and comparing two links is a string comparison.
    /// </summary>
    public string ToAppUrl() => "reportmate://" + Route(tabInFragment: false);

    /// <summary>
    /// The plain web link for the configured dashboard. The tab goes in the fragment
    /// rather than the query, because that is the form the web app's own address bar
    /// shows and its pages read.
    /// </summary>
    public string ToWebUrl(string webBaseUrl) => Combine(webBaseUrl, Route(tabInFragment: true));

    /// <summary>
    /// The shareable form. A bare <c>reportmate://</c> link cannot fall back on a machine
    /// with no handler, so the handoff route tries the app and then continues to the same
    /// page in the browser.
    /// </summary>
    public string ToHandoffUrl(string webBaseUrl) => Combine(webBaseUrl, "open/" + Route(tabInFragment: true));

    private string Route(bool tabInFragment)
    {
        var path = Section;
        if (!string.IsNullOrWhiteSpace(Argument))
            path += "/" + string.Join('/', Argument.Split('/').Select(Uri.EscapeDataString));

        var present = Query.AllKeys
            .Where(k => !string.IsNullOrEmpty(k) && !string.IsNullOrEmpty(Query[k]))
            .Select(k => k!)
            .ToList();

        var tab = present.FirstOrDefault(k => k.Equals("tab", StringComparison.OrdinalIgnoreCase));
        var rest = present
            .Where(k => !k.Equals("tab", StringComparison.OrdinalIgnoreCase))
            .OrderBy(k => k, StringComparer.Ordinal)
            .Select(Pair)
            .ToList();

        var fragment = "";
        if (tab is not null)
        {
            if (tabInFragment) fragment = "#" + Uri.EscapeDataString(Query[tab]!);
            else rest.Insert(0, Pair(tab));
        }

        var query = rest.Count == 0 ? "" : "?" + string.Join('&', rest);
        return path + query + fragment;

        string Pair(string key) => $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(Query[key]!)}";
    }

    private static string Combine(string baseUrl, string route) =>
        string.IsNullOrWhiteSpace(baseUrl) ? "reportmate://" + route : baseUrl.TrimEnd('/') + "/" + route;

    /// <summary>Build a link for a section, with the filters a page is currently showing.</summary>
    public static DeepLink For(string section, string? argument = null, params (string Key, string? Value)[] filters)
    {
        var query = HttpUtility.ParseQueryString("");
        foreach (var (key, value) in filters)
            if (!string.IsNullOrWhiteSpace(value)) query[key] = value;
        return new DeepLink(section, argument, query);
    }
}
