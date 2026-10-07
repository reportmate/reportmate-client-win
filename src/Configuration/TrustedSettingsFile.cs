using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ReportMate.WindowsClient.Configuration;

/// <summary>
/// Decides whether the runner, which runs as SYSTEM, may trust a settings file. A file
/// is trusted only when SYSTEM, Administrators or TrustedInstaller own it and no other
/// account is allowed to change it.
/// </summary>
[SupportedOSPlatform("windows")]
public static class TrustedSettingsFile
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    // Generic write and generic all show up unmapped on some ACEs.
    private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;
    private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;

    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
        GenericWrite | GenericAll;

    public static bool IsAdministrative(SecurityIdentifier? sid) =>
        sid is not null && (sid == System || sid == Administrators || sid == TrustedInstaller);

    /// <summary>
    /// Returns null when the file can be trusted, otherwise why not. A missing file
    /// returns null: there is nothing to read.
    /// </summary>
    public static string? WhyUntrusted(string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists) return null;

            if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return "it is a link, not a file";
            if (file.Directory is { } dir && dir.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return "its folder is a link";

            return WhyUntrusted(file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
        }
        catch (Exception ex)
        {
            return $"its permissions could not be read ({ex.Message})";
        }
    }

    /// <summary>Checks an owner and DACL; kept apart from the disk so it can be tested.</summary>
    public static string? WhyUntrusted(FileSystemSecurity security)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!IsAdministrative(owner))
            return $"it is owned by {owner?.Value ?? "an unknown account"}, not an administrator";

        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            // Deny entries only take rights away, and an inherit-only entry does not apply
            // to the object it sits on.
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue;
            if ((rule.FileSystemRights & WriteRights) == 0) continue;

            var sid = rule.IdentityReference as SecurityIdentifier;
            if (!IsAdministrative(sid))
                return $"{sid?.Value ?? rule.IdentityReference.Value} can change it";
        }

        return null;
    }
}
