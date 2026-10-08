#nullable enable
using System;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.Configuration;

namespace ReportMate.WindowsClient.Configuration;

/// <summary>
/// The handler under every HttpClient the runner's factory hands out, so the ProxyUrl and
/// SkipCertificateValidation settings the Prefs tab and the ADMX offer take effect.
/// </summary>
public static class RunnerHttpHandler
{
    public static HttpClientHandler Create(IConfiguration configuration)
    {
        var handler = new HttpClientHandler();

        if (ProxyFrom(configuration) is { } proxy)
        {
            handler.Proxy = new WebProxy(proxy) { BypassProxyOnLocal = true };
            handler.UseProxy = true;
        }

        if (SkipsCertificateValidation(configuration))
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        return handler;
    }

    /// <summary>The configured proxy, or null when none is set or the value is not an absolute http(s) URL.</summary>
    public static Uri? ProxyFrom(IConfiguration configuration)
    {
        var value = configuration["ReportMate:ProxyUrl"];
        if (string.IsNullOrWhiteSpace(value)) value = configuration["ReportMate:Proxy:Url"];
        if (string.IsNullOrWhiteSpace(value)) return null;
        return Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
            ? uri
            : null;
    }

    /// <summary>True only when SkipCertificateValidation is explicitly true.</summary>
    public static bool SkipsCertificateValidation(IConfiguration configuration) =>
        bool.TryParse(configuration["ReportMate:SkipCertificateValidation"], out var skip) && skip;
}
