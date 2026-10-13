#nullable enable
using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace ReportMate.Shared;

/// <summary>
/// Hands the pending Prefs values to the elevated --apply-settings run over a one-shot named
/// pipe, so credentials never touch disk. The pipe has a random name and an ACL that admits
/// only the current user, Administrators and SYSTEM; that still works when UAC is approved
/// with a different administrator account.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SettingsPipe
{
    private const string Prefix = "ReportMate-settings-";
    private static readonly Regex NamePattern = new($"^{Prefix}[0-9a-f]{{32}}$", RegexOptions.CultureInvariant);

    public static string NewName() => Prefix + Guid.NewGuid().ToString("N");

    /// <summary>True for a name this app generated; the elevated side connects to nothing else.</summary>
    public static bool IsValidName(string? name) => name is not null && NamePattern.IsMatch(name);

    /// <summary>The single-instance server end, readable and writable only by the user, Administrators and SYSTEM.</summary>
    public static NamedPipeServerStream CreateServer(string name)
    {
        if (!IsValidName(name)) throw new ArgumentException("Not a settings pipe name.", nameof(name));

        var security = new PipeSecurity();
        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (identity.User is { } user)
                security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        }
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));

        // FirstPipeInstance fails if anyone already created a pipe by this name.
        return NamedPipeServerStreamAcl.Create(name, PipeDirection.Out, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, security);
    }

    /// <summary>Waits for the client, sends the payload and closes the pipe.</summary>
    public static async Task SendAsync(NamedPipeServerStream server, string payload, CancellationToken cancellationToken)
    {
        await server.WaitForConnectionAsync(cancellationToken);
        await server.WriteAsync(Encoding.UTF8.GetBytes(payload), cancellationToken);
        await server.FlushAsync(cancellationToken);
        server.WaitForPipeDrain();
        server.Disconnect();
    }

    /// <summary>The elevated side: connects, reads the whole payload and returns it.</summary>
    public static string Receive(string name, TimeSpan timeout)
    {
        if (!IsValidName(name)) throw new ArgumentException("Not a settings pipe name.", nameof(name));
        using var client = new NamedPipeClientStream(".", name, PipeDirection.In);
        client.Connect((int)timeout.TotalMilliseconds);
        using var reader = new StreamReader(client, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
