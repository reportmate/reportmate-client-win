using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace ReportMate.Shared;

/// <summary>
/// Where credentials live: HKLM\SOFTWARE\ReportMate\Secrets, with its own ACL (SYSTEM and
/// Administrators full control, nobody else). Every other ReportMate key is readable by all
/// users, so a credential that arrives in one of them is moved here by an elevated run and
/// the readable copy removed. Compiled into both the runner and the GUI.
/// </summary>
/// <remarks>
/// Only an elevated process can read or write the store; any other process reads nothing
/// and treats the credential as unset. Values are never logged or displayed.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class SecretStore
{
    public const string RegistryPath = @"SOFTWARE\ReportMate\Secrets";

    /// <summary>The settings that hold credentials.</summary>
    public static readonly string[] SecretNames = ["Passphrase", "ApiKey"];

    public static bool IsSecret(string name) => SecretNames.Contains(name, StringComparer.OrdinalIgnoreCase);

    /// <summary>The stored value, or null when unset or this process may not read it.</summary>
    public static string? Read(string name)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(RegistryPath);
            return key?.GetValue(name) is string s && s.Length > 0 ? s : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Stores <paramref name="value"/>, or removes the entry when it is empty. Must run elevated.</summary>
    public static void Write(string name, string? value)
    {
        using var key = OpenProtected();
        if (string.IsNullOrEmpty(value))
            key.DeleteValue(name, throwOnMissingValue: false);
        else
            key.SetValue(name, value, RegistryValueKind.String);
    }

    /// <summary>
    /// Readable places a credential may be found, lowest precedence first, matching the
    /// runner's order: legacy top-level values, legacy Config\ReportMate, Settings, policy.
    /// </summary>
    public static readonly string[] ReadablePaths =
    [
        ReportMateSettingsKeys.LegacyRegistryPath,
        ReportMateSettingsKeys.LegacyConfigRegistryPath,
        ReportMateSettingsKeys.SettingsRegistryPath,
        ReportMateSettingsKeys.PolicyRegistryPath,
    ];

    /// <summary>
    /// What to do with one credential found in readable keys: the value to store, where it
    /// came from, managed copies to blank, and legacy copies to delete.
    /// </summary>
    public sealed record MigrationPlan(
        string? ValueToStore,
        string? StoredFrom,
        IReadOnlyList<string> PathsToClear,
        IReadOnlyList<string> PathsToDelete);

    private static readonly string[] ManagedPaths =
    [
        ReportMateSettingsKeys.SettingsRegistryPath,
        ReportMateSettingsKeys.PolicyRegistryPath,
    ];

    private static readonly string[] LegacyPaths =
    [
        ReportMateSettingsKeys.LegacyConfigRegistryPath,
        ReportMateSettingsKeys.LegacyRegistryPath,
    ];

    /// <summary>
    /// Decides what to store, blank and delete for one credential. Kept apart from the
    /// registry so it can be tested.
    /// </summary>
    /// <remarks>
    /// Settings and policy: the higher key that holds the name at all decides. A value left
    /// empty by an earlier move still counts, so policy keeps control and a lower key cannot
    /// replace what it set; an empty value stores nothing. Their readable copies are blanked.
    /// Legacy keys: their value is stored only when the store is empty and neither managed
    /// key holds the name (Config\ReportMate before the top-level key). Every legacy copy is
    /// deleted, since the store or a managed key supplies the credential from then on.
    /// Nothing is blanked or deleted until the store is verified (see <see cref="IsVerified"/>).
    /// </remarks>
    /// <param name="found">Per readable path, the value under the name, or null when the name is absent.</param>
    /// <param name="storeHasValue">Whether the protected store already holds this credential.</param>
    public static MigrationPlan Plan(IReadOnlyDictionary<string, string?> found, bool storeHasValue)
    {
        string? value = null;
        string? from = null;
        var claimed = false;
        var clear = new List<string>();
        var delete = new List<string>();

        foreach (var path in ManagedPaths)
        {
            if (!found.TryGetValue(path, out var v) || v is null) continue;
            claimed = true;
            if (v.Length > 0)
            {
                clear.Add(path);
                value = v;
                from = path;
            }
            else
            {
                value = null;
                from = null;
            }
        }

        foreach (var path in LegacyPaths)
        {
            if (!found.TryGetValue(path, out var v) || string.IsNullOrEmpty(v)) continue;
            delete.Add(path);
            if (!claimed && !storeHasValue && value is null)
            {
                value = v;
                from = path;
            }
        }

        return new MigrationPlan(value, from, clear, delete);
    }

    /// <summary>
    /// Whether the store can be trusted to hold the credential before readable copies are
    /// removed: it must read back exactly the value just written, or, when nothing was
    /// written, already hold one.
    /// </summary>
    public static bool IsVerified(string? written, string? readBack) =>
        written is not null ? readBack == written : !string.IsNullOrEmpty(readBack);

    /// <summary>
    /// Moves every credential found in a readable key into the store. Settings and policy
    /// copies are blanked rather than deleted, so a policy setting still shows as managed
    /// and a later copy cannot take over; legacy copies are deleted (only these two values,
    /// nothing else in the legacy keys). Nothing is removed unless the store is verified
    /// first. Returns one line per action, naming the setting and place, never the value.
    /// Must run elevated, before settings are loaded.
    /// </summary>
    public static List<string> MigrateReadableCopies()
    {
        var notes = new List<string>();
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using (OpenProtected()) { }

            foreach (var name in SecretNames)
            {
                var found = new Dictionary<string, string?>();
                foreach (var path in ReadablePaths)
                {
                    using var key = hklm.OpenSubKey(path);
                    if (key is null) continue;
                    if (key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
                        found[path] = key.GetValue(name)?.ToString() ?? string.Empty;
                }

                var plan = Plan(found, storeHasValue: Read(name) is not null);
                if (plan.ValueToStore is null && plan.PathsToClear.Count == 0 && plan.PathsToDelete.Count == 0)
                    continue;

                if (plan.ValueToStore is not null)
                    Write(name, plan.ValueToStore);

                if (!IsVerified(plan.ValueToStore, Read(name)))
                {
                    notes.Add($"Could not verify {name} in the protected store; readable copies were left in place");
                    continue;
                }
                if (plan.ValueToStore is not null)
                    notes.Add($"Stored {name} from HKLM\\{plan.StoredFrom} in the protected store");

                foreach (var path in plan.PathsToClear)
                {
                    using var key = hklm.OpenSubKey(path, writable: true);
                    if (key is null) continue;
                    key.SetValue(name, string.Empty, RegistryValueKind.String);
                    notes.Add($"Blanked the readable copy of {name} in HKLM\\{path}");
                }

                foreach (var path in plan.PathsToDelete)
                {
                    using var key = hklm.OpenSubKey(path, writable: true);
                    if (key is null) continue;
                    key.DeleteValue(name, throwOnMissingValue: false);
                    notes.Add($"Deleted the readable copy of {name} from the deprecated key HKLM\\{path}");
                }
            }
        }
        catch (Exception ex)
        {
            notes.Add($"Could not move credentials to the protected store: {ex.Message}");
        }
        return notes;
    }

    /// <summary>SYSTEM and Administrators full control, nothing inherited, nobody else.</summary>
    public static RegistrySecurity ProtectedSecurity()
    {
        var security = new RegistrySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(sid, null),
                RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        return security;
    }

    /// <summary>Opens the store for writing, creating it, and resets its ACL every time.</summary>
    private static RegistryKey OpenProtected()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var key = hklm.CreateSubKey(RegistryPath, writable: true);
        key.SetAccessControl(ProtectedSecurity());
        return key;
    }
}
