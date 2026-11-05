#nullable enable
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace ReportMate.WindowsClient.Services;

/// <summary>
/// The output of a command run as the signed-in user, and which user and session it ran in.
/// </summary>
public sealed record UserSessionRunResult(
    string Output, string UserName, uint SessionId, int? ExitCode, bool TimedOut);

/// <summary>
/// Runs a command-line tool as the user signed in to an interactive session, from a
/// runner that is itself running as LocalSystem.
/// </summary>
/// <remarks>
/// Some state exists only in a user's logon session. The Entra primary refresh token
/// and the Kerberos tickets that <c>dsregcmd /status</c> reports under "SSO State" are
/// per user, so the same command run as SYSTEM always reports AzureAdPrt NO.
///
/// The runner takes the session user's primary token (WTSQueryUserToken, which
/// LocalSystem may call) and starts a fixed System32 tool with CreateProcessAsUser,
/// reading its output over a pipe. The child inherits only the pipe's write end
/// (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), never the runner's other handles, and its output
/// is capped. Nothing is written to disk and no scheduled task is left behind, so there
/// is no file a user could edit for SYSTEM to read back.
/// </remarks>
public static class UserSessionProcess
{
    private const uint NoSession = 0xFFFFFFFF;
    private const int WtsActive = 0;
    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;
    private const uint HandleFlagInherit = 0x1;
    private const int StartfUseStdHandles = 0x100;
    private const int StartfUseShowWindow = 0x1;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private static readonly IntPtr ProcThreadAttributeHandleList = (IntPtr)0x00020002;
    private const uint WaitTimeout = 0x102;
    private const int ErrorNoToken = 1008;

    private static readonly TimeSpan DrainAfterExit = TimeSpan.FromSeconds(5);

    /// <summary>Output beyond this is discarded; the tools run here print a few kilobytes.</summary>
    public const int MaxOutputBytes = 1024 * 1024;

    /// <summary>True when this process runs as LocalSystem.</summary>
    public static bool IsLocalSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem;
    }

    /// <summary>
    /// The interactive session to run in: the physical console when a user is signed in
    /// there, otherwise the first active remote session. Null when no user is signed in.
    /// </summary>
    public static (uint SessionId, string UserName)? FindSignedInSession()
    {
        var console = WTSGetActiveConsoleSessionId();
        if (console != NoSession)
        {
            var user = SessionUserName(console);
            if (!string.IsNullOrEmpty(user))
                return (console, user);
        }

        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var sessions, out var count))
            return null;
        try
        {
            var size = Marshal.SizeOf<WtsSessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WtsSessionInfo>(sessions + i * size);
                if (info.State != WtsActive || info.SessionId == 0)
                    continue;
                var user = SessionUserName(info.SessionId);
                if (!string.IsNullOrEmpty(user))
                    return (info.SessionId, user);
            }
        }
        finally
        {
            WTSFreeMemory(sessions);
        }
        return null;
    }

    /// <summary>
    /// Runs a tool from the System32 directory, by file name, as the user of
    /// <paramref name="sessionId"/>. Only a SYSTEM-owned binary can be started: the path is
    /// fixed to System32 and passed as the application name, so neither the user's PATH
    /// nor the working directory is searched. Returns null when that session has no user
    /// token (the user signed out). Throws <see cref="Win32Exception"/> when the process
    /// cannot be started.
    /// </summary>
    public static async Task<UserSessionRunResult?> RunSystemToolAsync(
        uint sessionId, string userName, string toolFileName, string arguments, TimeSpan timeout)
    {
        if (string.IsNullOrWhiteSpace(toolFileName) || toolFileName != Path.GetFileName(toolFileName)
            || toolFileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("A System32 tool is named by file name only", nameof(toolFileName));
        var application = Path.Combine(Environment.SystemDirectory, toolFileName);
        if (!File.Exists(application))
            throw new FileNotFoundException("System tool not found", application);
        var commandLine = $"\"{application}\" {arguments}";

        if (!WTSQueryUserToken(sessionId, out var token))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorNoToken)
                return null;
            throw new Win32Exception(error, "WTSQueryUserToken failed");
        }

        IntPtr environment = IntPtr.Zero;
        IntPtr readPipe = IntPtr.Zero, writePipe = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero, handleArray = IntPtr.Zero;
        var attributeListReady = false;
        var processInfo = default(ProcessInformation);
        try
        {
            if (!CreateEnvironmentBlock(out environment, token, false))
                environment = IntPtr.Zero;

            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                InheritHandle = true,
            };
            if (!CreatePipe(out readPipe, out writePipe, ref attributes, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreatePipe failed");
            // The parent's read end is never inheritable.
            if (!SetHandleInformation(readPipe, HandleFlagInherit, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetHandleInformation failed");

            // The child crosses from SYSTEM to the user, so it must inherit exactly one
            // handle, the pipe write end, and none of the runner's other inheritable
            // handles. PROC_THREAD_ATTRIBUTE_HANDLE_LIST restricts inheritance to that list.
            var listSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref listSize);
            attributeList = Marshal.AllocHGlobal(listSize);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref listSize))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList failed");
            attributeListReady = true;
            handleArray = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(handleArray, writePipe);
            if (!UpdateProcThreadAttribute(attributeList, 0, ProcThreadAttributeHandleList, handleArray,
                    (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute failed");

            var startup = new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Size = Marshal.SizeOf<StartupInfoEx>(),
                    Desktop = @"winsta0\default",
                    Flags = StartfUseStdHandles | StartfUseShowWindow,
                    ShowWindow = 0,
                    StdOutput = writePipe,
                    StdError = writePipe,
                },
                AttributeList = attributeList,
            };
            var flags = CreateNoWindow | ExtendedStartupInfoPresent
                | (environment != IntPtr.Zero ? CreateUnicodeEnvironment : 0);
            var command = new StringBuilder(commandLine);
            if (!CreateProcessAsUser(token, application, command, IntPtr.Zero, IntPtr.Zero, true, flags,
                    environment, Environment.SystemDirectory, ref startup, out processInfo))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser failed");

            // The child holds its own copy now; ours must close or the read never ends.
            CloseHandle(writePipe);
            writePipe = IntPtr.Zero;

            var reader = new FileStream(new SafeFileHandle(readPipe, ownsHandle: true), FileAccess.Read);
            readPipe = IntPtr.Zero;
            var read = ReadAllAsync(reader);

            var waited = await Task.Run(() => WaitForSingleObject(processInfo.Process, (uint)timeout.TotalMilliseconds));
            var timedOut = waited == WaitTimeout;
            int? exitCode = null;
            if (timedOut)
                TerminateProcess(processInfo.Process, 1);
            else if (GetExitCodeProcess(processInfo.Process, out var code))
                exitCode = (int)code;

            // Another process started meanwhile may have inherited the pipe; never wait on it.
            var drained = await Task.WhenAny(read, Task.Delay(DrainAfterExit)) == read;
            var bytes = drained ? await read : Array.Empty<byte>();
            if (!drained)
                reader.Dispose();
            return new UserSessionRunResult(Decode(bytes), userName, sessionId, exitCode, timedOut);
        }
        finally
        {
            if (processInfo.Process != IntPtr.Zero) CloseHandle(processInfo.Process);
            if (processInfo.Thread != IntPtr.Zero) CloseHandle(processInfo.Thread);
            if (writePipe != IntPtr.Zero) CloseHandle(writePipe);
            if (readPipe != IntPtr.Zero) CloseHandle(readPipe);
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (attributeListReady) DeleteProcThreadAttributeList(attributeList);
            if (attributeList != IntPtr.Zero) Marshal.FreeHGlobal(attributeList);
            if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
            CloseHandle(token);
        }
    }

    /// <summary>
    /// Reads the child's output up to <see cref="MaxOutputBytes"/>. Past the cap the read
    /// stops; a child still writing then blocks and is ended by the timeout.
    /// </summary>
    private static async Task<byte[]> ReadAllAsync(FileStream stream)
    {
        using (stream)
        using (var buffer = new MemoryStream())
        {
            try
            {
                var chunk = new byte[16 * 1024];
                int read;
                while (buffer.Length < MaxOutputBytes
                       && (read = await stream.ReadAsync(chunk.AsMemory(0, (int)Math.Min(chunk.Length, MaxOutputBytes - buffer.Length)))) > 0)
                    buffer.Write(chunk, 0, read);
            }
            catch (IOException)
            {
                // A broken pipe after the child exits ends the output.
            }
            catch (ObjectDisposedException)
            {
            }
            return buffer.ToArray();
        }
    }

    /// <summary>
    /// Console tools write either the OEM code page or UTF-16 when redirected; the
    /// text this runner reads is ASCII either way.
    /// </summary>
    public static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        var zeros = 0;
        for (var i = 1; i < bytes.Length; i += 2)
            if (bytes[i] == 0) zeros++;
        if (bytes.Length > 8 && zeros > bytes.Length / 4)
            return Encoding.Unicode.GetString(bytes);
        return Encoding.UTF8.GetString(bytes);
    }

    private static string SessionUserName(uint sessionId)
    {
        var user = SessionString(sessionId, WtsUserName);
        if (string.IsNullOrEmpty(user))
            return string.Empty;
        var domain = SessionString(sessionId, WtsDomainName);
        return string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}";
    }

    private static string SessionString(uint sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
            return string.Empty;
        try
        {
            return Marshal.PtrToStringUni(buffer) ?? string.Empty;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public uint SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute;
        public int Flags;
        public short ShowWindow;
        public short Reserved2Size;
        public IntPtr Reserved2;
        public IntPtr StdInput;
        public IntPtr StdOutput;
        public IntPtr StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public int ProcessId;
        public int ThreadId;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, uint sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes attributes, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(IntPtr token, string? application, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
        IntPtr environment, string? currentDirectory, ref StartupInfoEx startupInfo, out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute,
        IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
