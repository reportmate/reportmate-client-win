#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Inventory of system binaries: where each one is, its version, whether it was running when
    /// collected, and the package it came from.
    ///
    /// The collector runs as SYSTEM, so it never executes what it finds. The version comes from the
    /// file's version resource, which is read without running the file; a binary that carries no
    /// version resource, such as nginx.exe, is reported with no version rather than guessed.
    /// </summary>
    public static class SystemBinaryInventory
    {
        public static readonly IReadOnlyDictionary<string, string> Targets = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["httpd"] = "server", ["nginx"] = "server", ["sshd"] = "server", ["named"] = "server",
            ["mysqld"] = "database", ["mariadbd"] = "database", ["postgres"] = "database",
            ["redis-server"] = "database", ["sqlservr"] = "database",
            ["openssl"] = "library",
            ["php"] = "runtime", ["python"] = "runtime", ["python3"] = "runtime", ["node"] = "runtime",
            ["java"] = "runtime", ["ruby"] = "runtime", ["perl"] = "runtime",
            ["curl"] = "tool", ["git"] = "tool",
        };

        private const int ProgramFilesDepth = 5;
        private const int RootFolderDepth = 4;

        /// <summary>Top-level folders on the system drive that are searched elsewhere or hold no installs.</summary>
        private static readonly HashSet<string> SkippedRootFolders = new(StringComparer.OrdinalIgnoreCase)
        {
            "Windows", "Users", "Program Files", "Program Files (x86)", "ProgramData", "$Recycle.Bin",
            "System Volume Information", "Recovery", "PerfLogs", "$WinREAgent", "Config.Msi", "OneDriveTemp",
        };

        private static readonly Regex VersionToken = new(@"[0-9]+(?:[.\-][0-9A-Za-z]+)*", RegexOptions.Compiled);

        /// <summary>Leading version from a version resource string, e.g. "3.12.4150.1013" or "2.47.1.windows.1".</summary>
        public static string? NormalizeVersion(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var match = VersionToken.Match(raw.Trim());
            return match.Success ? match.Value.TrimEnd('.', '-') : null;
        }

        /// <summary>Executable path from a service ImagePath such as "\"C:\\Apache24\\bin\\httpd.exe\" -k runservice".</summary>
        public static string? ServiceExecutable(string? imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath)) return null;
            var value = Environment.ExpandEnvironmentVariables(imagePath.Trim());
            if (value.StartsWith('"'))
            {
                var end = value.IndexOf('"', 1);
                return end > 1 ? value[1..end] : null;
            }
            var exe = value.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return exe > 0 ? value[..(exe + 4)] : null;
        }

        public static string TargetName(string path) => System.IO.Path.GetFileNameWithoutExtension(path);

        /// <summary>The installed product whose install folder holds the binary, choosing the deepest match.</summary>
        public static (string Name, string? Version)? OwningProduct(string path, IEnumerable<(string Location, string Name, string? Version)> products)
        {
            (string Name, string? Version)? best = null;
            var bestLength = 0;
            foreach (var (location, name, version) in products)
            {
                var root = location.TrimEnd('\\', '/') + "\\";
                if (root.Length > 3 && root.Length > bestLength && path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                {
                    best = (name, version);
                    bestLength = root.Length;
                }
            }
            return best;
        }

        public static List<SystemBinary> Collect(IEnumerable<SystemService> services, ILogger logger)
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var processes = RunningProcesses(logger);
            var serviceNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var service in services)
            {
                var exe = ServiceExecutable(service.Path);
                if (exe != null && Targets.ContainsKey(TargetName(exe))) serviceNames.TryAdd(exe, service.Name);
            }

            var paths = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var path in CandidatePaths(windows, logger).Concat(processes.Keys).Concat(serviceNames.Keys))
            {
                if (Targets.ContainsKey(TargetName(path)) && File.Exists(path)) paths.Add(System.IO.Path.GetFullPath(path));
            }

            var products = InstalledProducts(logger);
            var results = new List<SystemBinary>();
            foreach (var path in paths)
            {
                try
                {
                    results.Add(Describe(path, windows, processes, serviceNames, products));
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "Skipped binary {Path}", path);
                }
            }
            return results;
        }

        private static SystemBinary Describe(
            string path, string windows, Dictionary<string, int> processes,
            Dictionary<string, string> serviceNames, List<(string, string, string?)> products)
        {
            var name = TargetName(path).ToLowerInvariant();
            var binary = new SystemBinary { Name = name, Category = Targets[name], Path = path };
            if (processes.Count > 0)
            {
                processes.TryGetValue(path, out var count);
                binary.Running = count > 0;
                binary.ProcessCount = count;
            }
            if (serviceNames.TryGetValue(path, out var serviceName)) binary.ServiceName = serviceName;

            var info = FileVersionInfo.GetVersionInfo(path);
            var raw = string.IsNullOrWhiteSpace(info.ProductVersion) ? info.FileVersion : info.ProductVersion;
            binary.Version = NormalizeVersion(raw);
            if (binary.Version != null)
            {
                binary.VersionString = raw!.Trim();
                binary.VersionSource = "fileVersion";
            }
            if (!string.IsNullOrWhiteSpace(info.CompanyName)) binary.Publisher = info.CompanyName.Trim();

            var chocolatey = path.IndexOf(@"\chocolatey\lib\", StringComparison.OrdinalIgnoreCase);
            if (path.StartsWith(windows.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
            {
                binary.Source = "os";
            }
            else if (chocolatey >= 0)
            {
                binary.Source = "chocolatey";
                binary.Package = path[(chocolatey + 16)..].Split('\\')[0];
            }
            else if (OwningProduct(path, products) is { } product)
            {
                binary.Source = "package";
                binary.Package = product.Name;
                binary.PackageVersion = product.Version;
            }
            return binary;
        }

        private static IEnumerable<string> CandidatePaths(string windows, ILogger logger)
        {
            var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var flat = new List<string> { system32, System.IO.Path.Combine(system32, "OpenSSH") };
            var machinePath = Environment.GetEnvironmentVariable("Path", EnvironmentVariableTarget.Machine) ?? string.Empty;
            flat.AddRange(machinePath.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(Environment.ExpandEnvironmentVariables)
                // Chocolatey shims are launchers without the real version; the real binaries are under chocolatey\lib.
                .Where(dir => !dir.EndsWith(@"\chocolatey\bin", StringComparison.OrdinalIgnoreCase)));

            foreach (var dir in flat.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                foreach (var file in Files(dir, 0, logger)) yield return file;
            }

            var deep = new List<(string, int)>();
            foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            {
                var dir = Environment.GetFolderPath(folder);
                if (!string.IsNullOrEmpty(dir)) deep.Add((dir, ProgramFilesDepth));
            }
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            deep.Add((System.IO.Path.Combine(programData, "chocolatey", "lib"), ProgramFilesDepth));

            var drive = System.IO.Path.GetPathRoot(windows) ?? @"C:\";
            foreach (var dir in SafeDirectories(drive))
            {
                if (!SkippedRootFolders.Contains(System.IO.Path.GetFileName(dir))) deep.Add((dir, RootFolderDepth));
            }
            // Per-user installs of Python, Node.js and Git land here.
            foreach (var profile in SafeDirectories(System.IO.Path.Combine(drive, "Users")))
            {
                deep.Add((System.IO.Path.Combine(profile, "AppData", "Local", "Programs"), RootFolderDepth));
            }

            foreach (var (dir, depth) in deep.DistinctBy(entry => entry.Item1, StringComparer.OrdinalIgnoreCase))
            {
                foreach (var file in Files(dir, depth, logger)) yield return file;
            }
        }

        private static IEnumerable<string> SafeDirectories(string path)
        {
            try { return Directory.Exists(path) ? Directory.GetDirectories(path) : Array.Empty<string>(); }
            catch { return Array.Empty<string>(); }
        }

        private static IEnumerable<string> Files(string dir, int depth, ILogger logger)
        {
            if (!Directory.Exists(dir)) return Array.Empty<string>();
            try
            {
                var options = new EnumerationOptions
                {
                    RecurseSubdirectories = depth > 0,
                    MaxRecursionDepth = depth,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline,
                };
                return Directory.EnumerateFiles(dir, "*.exe", options)
                    .Where(file => Targets.ContainsKey(TargetName(file)))
                    .ToList();
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Could not search {Directory} for binaries", dir);
                return Array.Empty<string>();
            }
        }

        private static Dictionary<string, int> RunningProcesses(ILogger logger)
        {
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            Process[] all;
            try { all = Process.GetProcesses(); }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Could not list processes for the binary inventory");
                return counts;
            }
            foreach (var process in all)
            {
                using (process)
                {
                    try
                    {
                        if (!Targets.ContainsKey(process.ProcessName)) continue;
                        var file = process.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(file))
                        {
                            file = System.IO.Path.GetFullPath(file);
                            counts[file] = counts.GetValueOrDefault(file) + 1;
                        }
                    }
                    catch
                    {
                        // Protected or exited processes cannot be opened; they are not counted.
                    }
                }
            }
            return counts;
        }

        private static List<(string, string, string?)> InstalledProducts(ILogger logger)
        {
            var products = new List<(string, string, string?)>();
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    using var uninstall = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    if (uninstall == null) continue;
                    foreach (var keyName in uninstall.GetSubKeyNames())
                    {
                        using var key = uninstall.OpenSubKey(keyName);
                        var location = key?.GetValue("InstallLocation") as string;
                        var name = key?.GetValue("DisplayName") as string;
                        if (string.IsNullOrWhiteSpace(location) || string.IsNullOrWhiteSpace(name)) continue;
                        products.Add((Environment.ExpandEnvironmentVariables(location.Trim().Trim('"')), name.Trim(),
                            (key?.GetValue("DisplayVersion") as string)?.Trim()));
                    }
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "Could not read installed products for the binary inventory");
                }
            }
            return products;
        }
    }
}
