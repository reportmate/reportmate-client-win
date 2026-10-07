using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using Microsoft.Extensions.Configuration;
using Microsoft.Win32;
using ReportMate.Shared;

namespace ReportMate.WindowsClient.Configuration;

/// <summary>
/// Everything the runner's settings are built from, gathered up front so the
/// precedence can be tested without touching the registry.
/// </summary>
public sealed class SettingsInputs
{
    /// <summary>One-off flags for this run, already as configuration keys.</summary>
    public IDictionary<string, string?> CommandLine { get; init; } = new Dictionary<string, string?>();
    public IDictionary<string, object> Policy { get; init; } = new Dictionary<string, object>();
    public IDictionary<string, object> Settings { get; init; } = new Dictionary<string, object>();
    public IDictionary<string, object> LegacyConfig { get; init; } = new Dictionary<string, object>();
    public IDictionary<string, object> LegacyTopLevel { get; init; } = new Dictionary<string, object>();
    public IDictionary Environment { get; init; } = new Dictionary<string, string>();
    /// <summary>The legacy YAML file, or null when there is none or it is not trusted.</summary>
    public string? LegacySettingsFile { get; init; }
    /// <summary>Credentials from the protected store (SecretStore), by setting name.</summary>
    public IDictionary<string, object> Secrets { get; init; } = new Dictionary<string, object>();
}

[SupportedOSPlatform("windows")]
public static class SettingsLoader
{
    /// <summary>
    /// Reads the machine's settings sources. Notes collects one line per source that was
    /// skipped, for the caller to log once logging is up.
    /// </summary>
    public static SettingsInputs ReadMachine(IDictionary<string, string?> commandLine, List<string> notes)
    {
        var yamlPath = Path.Combine(ReportMateSettingsKeys.DataDirectory, ReportMateSettingsKeys.LegacySettingsFileName);
        string? trustedYaml = null;
        if (File.Exists(yamlPath))
        {
            var why = TrustedSettingsFile.WhyUntrusted(yamlPath);
            if (why is null)
                trustedYaml = yamlPath;
            else
                notes.Add($"Ignoring {yamlPath}: {why}");
        }

        // Credentials first: readable copies are moved into the protected store before
        // anything is read.
        notes.AddRange(SecretStore.MigrateReadableCopies());
        var secrets = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in SecretStore.SecretNames)
        {
            if (SecretStore.Read(name) is { } value)
                secrets[name] = value;
        }

        var inputs = new SettingsInputs
        {
            CommandLine = commandLine,
            Secrets = secrets,
            Policy = ReadRegistryValues(ReportMateSettingsKeys.PolicyRegistryPath, notes),
            Settings = ReadRegistryValues(ReportMateSettingsKeys.SettingsRegistryPath, notes),
            LegacyConfig = ReadRegistryValues(ReportMateSettingsKeys.LegacyConfigRegistryPath, notes),
            LegacyTopLevel = ReadRegistryValues(ReportMateSettingsKeys.LegacyRegistryPath, notes),
            Environment = System.Environment.GetEnvironmentVariables(),
            LegacySettingsFile = trustedYaml,
        };

        // Legacy keys are deprecated; say so when one still supplies a setting.
        var inEffect = LegacySettingsMigration.Plan(
            inputs.Settings.Keys.Concat(inputs.Policy.Keys),
            (IReadOnlyDictionary<string, object>)inputs.LegacyConfig,
            (IReadOnlyDictionary<string, object>)inputs.LegacyTopLevel);
        if (inEffect.Count > 0)
        {
            notes.Add($"Using deprecated legacy registry values for {string.Join(", ", inEffect.Keys.OrderBy(k => k))}; " +
                      "reinstall or upgrade ReportMate to copy them to the Settings key");
        }

        return inputs;
    }

    /// <summary>Layers the sources, lowest precedence first, so later ones win.</summary>
    public static IConfiguration Build(SettingsInputs inputs)
    {
        var builder = new ConfigurationBuilder();

        if (inputs.LegacySettingsFile is { } yaml)
        {
            builder.SetBasePath(Path.GetDirectoryName(yaml)!)
                   .AddYamlFile(Path.GetFileName(yaml), optional: true, reloadOnChange: false);
        }

        builder.AddInMemoryCollection(FromEnvironment(inputs.Environment));
        builder.AddInMemoryCollection(FromRegistry(inputs.LegacyTopLevel));
        builder.AddInMemoryCollection(FromRegistry(inputs.LegacyConfig));
        builder.AddInMemoryCollection(FromRegistry(inputs.Settings));
        builder.AddInMemoryCollection(FromRegistry(inputs.Policy));
        // The store only ever holds what policy or settings supplied (or a legacy value when
        // neither did), so it sits above them.
        builder.AddInMemoryCollection(FromRegistry(inputs.Secrets));
        builder.AddInMemoryCollection(inputs.CommandLine);

        return builder.Build();
    }

    /// <summary>
    /// --api-url and --device-id, read ahead of the command parser because the
    /// configuration is built before it runs.
    /// </summary>
    public static Dictionary<string, string?> CommandLineOverrides(string[] args)
    {
        var result = new Dictionary<string, string?>();
        for (var i = 0; i < args.Length; i++)
        {
            foreach (var (flag, key) in new[] { ("--api-url", "ReportMate:ApiUrl"), ("--device-id", "ReportMate:DeviceId") })
            {
                string? value = null;
                if (args[i].Equals(flag, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    value = args[i + 1];
                else if (args[i].StartsWith(flag + "=", StringComparison.OrdinalIgnoreCase))
                    value = args[i][(flag.Length + 1)..];

                if (!string.IsNullOrWhiteSpace(value) && !value.StartsWith('-'))
                    result[key] = value;
            }
        }
        return result;
    }

    /// <summary>
    /// REPORTMATE_ReportMate__ApiUrl style variables, as the environment-variable
    /// configuration provider maps them, plus the older REPORTMATE_API_URL, API_URL
    /// and SERVER_URL names for the API URL.
    /// </summary>
    internal static Dictionary<string, string?> FromEnvironment(IDictionary environment)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in environment)
        {
            var name = entry.Key?.ToString();
            if (name is null || !name.StartsWith(ReportMateSettingsKeys.EnvironmentPrefix, StringComparison.OrdinalIgnoreCase))
                continue;
            if (string.IsNullOrEmpty(entry.Value?.ToString())) continue;
            var rest = name[ReportMateSettingsKeys.EnvironmentPrefix.Length..];
            // REPORTMATE_ReportMate__ApiUrl names a key outright; REPORTMATE_API_KEY and
            // the like name a ReportMate setting, matched without case or underscores.
            var key = rest.Contains("__")
                ? rest.Replace("__", ":")
                : $"ReportMate:{rest.Replace("_", "")}";
            result[key] = entry.Value?.ToString();
        }

        if (!result.TryGetValue("ReportMate:ApiUrl", out var apiUrl) || string.IsNullOrEmpty(apiUrl))
        {
            foreach (var name in new[] { "REPORTMATE_API_URL", "API_URL", "SERVER_URL" })
            {
                if (environment[name]?.ToString() is { Length: > 0 } fallback)
                {
                    result["ReportMate:ApiUrl"] = fallback;
                    break;
                }
            }
        }

        return result;
    }

    internal static Dictionary<string, string?> FromRegistry(IDictionary<string, object> values)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        // Older spellings first, so a value under the current name wins within one key.
        foreach (var (name, raw) in values.OrderBy(v => ReportMateSettingsKeys.ValueNameAliases.ContainsKey(v.Key) ? 0 : 1))
        {
            var text = raw switch
            {
                int i when ReportMateSettingsKeys.BooleanValueNames.Contains(name) => i != 0 ? "true" : "false",
                string[] multi => string.Join(",", multi),
                _ => raw?.ToString(),
            };
            if (string.IsNullOrEmpty(text)) continue;
            result[ReportMateSettingsKeys.ToConfigurationKey(name)] = text;
        }
        return result;
    }

    private static Dictionary<string, object> ReadRegistryValues(string path, List<string> notes)
    {
        var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(path, writable: false);
            if (key is null) return values;

            foreach (var name in key.GetValueNames())
            {
                if (string.IsNullOrEmpty(name)) continue;
                if (key.GetValue(name) is { } value)
                    values[name] = value;
            }
        }
        catch (Exception ex)
        {
            notes.Add($"Could not read HKLM\\{path}: {ex.Message}");
        }
        return values;
    }
}
