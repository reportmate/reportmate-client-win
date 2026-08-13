#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// Hand-authored fixtures. No collected data from any machine belongs in
    /// this repository, so the inventory and the executable paths are written
    /// from publicly documented product names and default install locations.
    ///
    /// installed-applications.json is shaped to match what the registry actually
    /// contains: mostly entries with no InstallLocation, several sub-component
    /// entries for one product, and Appx packages with exact versioned paths.
    /// Its ORDER is load-bearing. The Security Log path takes the first entry
    /// that matches rather than the best one, so reordering the file changes the
    /// answers and the suite stops reproducing production behaviour.
    ///
    /// Each entry in observed-exe-paths.json exercises a specific behaviour;
    /// both files carry comments saying which.
    /// </summary>
    public static class Fixtures
    {
        private static readonly JsonSerializerOptions Options = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        /// <summary>
        /// Where fixtures are read from: the copy beside the test binary, put
        /// there by the csproj's CopyToOutputDirectory.
        /// </summary>
        public static string Dir =>
            Path.Combine(AppContext.BaseDirectory, "Fixtures");

        /// <summary>
        /// Where regenerated fixtures are written: the copy under source control.
        ///
        /// Writing to <see cref="Dir"/> would update the build output and leave
        /// the committed file untouched, so a test run straight after a
        /// regeneration passes against the regenerated copy and reads as
        /// confirmation when nothing has been reviewed. Found while fixing work
        /// item 4353; work item 4444.
        /// </summary>
        public static string SourceDir
        {
            get
            {
                var dir = new DirectoryInfo(AppContext.BaseDirectory);
                while (dir != null)
                {
                    if (dir.GetFiles("ReportMate.WindowsClient.Tests.csproj").Length > 0)
                        return Path.Combine(dir.FullName, "Fixtures");
                    dir = dir.Parent;
                }

                throw new DirectoryNotFoundException(
                    "Could not locate the test project directory above " +
                    AppContext.BaseDirectory + "; regenerated fixtures would be written " +
                    "to the build output and lost.");
            }
        }

        private static T Load<T>(string fileName)
        {
            var path = Path.Combine(Dir, fileName);
            if (!File.Exists(path))
                throw new FileNotFoundException($"Fixture not found: {path}");
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<T>(json, Options)
                   ?? throw new InvalidOperationException($"Fixture deserialized to null: {fileName}");
        }

        public static List<InstalledApplication> InstalledApplications() =>
            Load<List<InstalledApplication>>("installed-applications.json");

        public static List<string> ObservedExePaths() =>
            Load<List<string>>("observed-exe-paths.json");

        public static List<ResolutionCase> ExpectedResolutions() =>
            Load<List<ResolutionCase>>("expected-resolutions.json");

        /// <summary>
        /// Rewrite a fixture in the source tree. Key casing matches what is
        /// committed, so a regeneration produces a diff of the values that moved
        /// rather than a rename of every key in the file.
        /// </summary>
        public static void Write<T>(string fileName, T value)
        {
            var json = JsonSerializer.Serialize(value, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
            File.WriteAllText(Path.Combine(SourceDir, fileName), json + Environment.NewLine);
        }
    }

    /// <summary>
    /// One pinned resolution. <see cref="SecurityLog"/> is what the Security Log
    /// path resolves the executable to (null when it drops the process entirely);
    /// <see cref="Tracker"/> is what the usage tracker merge resolves it to.
    ///
    /// <see cref="Defect"/> is set when the pinned value is known to be wrong.
    /// These are pinned deliberately: the suite records what the collector does
    /// today so that a change in attribution shows up as a failing assertion
    /// rather than as silently different data in the fleet.
    /// </summary>
    public sealed class ResolutionCase
    {
        public string ExePath { get; set; } = string.Empty;
        public string? SecurityLog { get; set; }
        public string Tracker { get; set; } = string.Empty;

        /// <summary>Work item id when the pinned value is a known defect, else null.</summary>
        public string? Defect { get; set; }

        /// <summary>What the value should be once <see cref="Defect"/> is fixed.</summary>
        public string? Should { get; set; }
    }
}
