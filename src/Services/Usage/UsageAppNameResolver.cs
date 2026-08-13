#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Usage
{
    /// <summary>
    /// Resolves an executable path to the name of an installed application.
    ///
    /// This is the single place that decides the app_name written on every
    /// usage_history row, and it is deliberately free of logging, I/O and any
    /// other dependency so it can be exercised directly by tests.
    ///
    /// Two independent collection paths call in here and they do not agree today:
    ///
    /// - <see cref="ResolveInstalledApp"/> backs the Security Log path, which
    ///   supplies total_seconds. It uses the fuzzy <see cref="MatchesApplication"/>
    ///   predicate and drops anything it cannot match.
    /// - <see cref="ResolveTrackerAppName"/> backs the per-user usage tracker
    ///   merge, which supplies foreground and active seconds. It consults only
    ///   InstallLocation and keeps what it cannot match, under the exe filename.
    ///
    /// The disagreement is why one application can appear as two rows. It is
    /// tracked as work item 4353 and the fixture tests in
    /// ReportMate.WindowsClient.Tests pin the current behaviour so that any
    /// change to it is visible in a diff.
    /// </summary>
    public static class UsageAppNameResolver
    {
        /// <summary>
        /// Security Log path: first installed application that the fuzzy
        /// predicate accepts, or null. Note that this is first-to-match and not
        /// best-match, so the result depends on the order of the inventory.
        /// </summary>
        public static InstalledApplication? ResolveInstalledApp(
            string processPath,
            IEnumerable<InstalledApplication> installedApps)
        {
            return installedApps.FirstOrDefault(app => MatchesApplication(processPath, app));
        }

        /// <summary>
        /// Usage tracker path: name of the application whose InstallLocation is
        /// the longest prefix of the executable path, falling back to the
        /// executable filename without its extension.
        /// </summary>
        public static string ResolveTrackerAppName(
            string exePath,
            IEnumerable<InstalledApplication> installedApps)
        {
            if (string.IsNullOrWhiteSpace(exePath)) return string.Empty;

            string? bestName = null;
            int bestLen = 0;
            var normExe = exePath.Replace('/', '\\').TrimEnd('\\');

            foreach (var app in installedApps)
            {
                var loc = app.InstallLocation;
                if (string.IsNullOrWhiteSpace(loc)) continue;
                var normLoc = loc.Replace('/', '\\').TrimEnd('\\');
                if (normLoc.Length == 0) continue;
                if (normExe.StartsWith(normLoc, StringComparison.OrdinalIgnoreCase) &&
                    (normExe.Length == normLoc.Length || normExe[normLoc.Length] == '\\'))
                {
                    if (normLoc.Length > bestLen)
                    {
                        bestLen = normLoc.Length;
                        bestName = app.Name;
                    }
                }
            }

            if (!string.IsNullOrEmpty(bestName)) return bestName!;
            try { return Path.GetFileNameWithoutExtension(exePath) ?? string.Empty; }
            catch { return string.Empty; }
        }

        /// <summary>
        /// Check if a process path matches an installed application.
        /// Uses intelligent matching strategies (no hardcoded mappings):
        /// 1. Install location prefix matching (most reliable)
        /// 2. Path component analysis - extracts meaningful words from path and matches against app name/publisher
        /// 3. Process filename to app name matching (fallback)
        /// </summary>
        public static bool MatchesApplication(string processPath, InstalledApplication app)
        {
            if (string.IsNullOrEmpty(processPath))
                return false;

            var normalizedProcessPath = processPath.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();

            // Strategy 1: Install location prefix match (most accurate)
            if (!string.IsNullOrEmpty(app.InstallLocation))
            {
                var normalizedInstallPath = app.InstallLocation.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
                if (normalizedProcessPath.StartsWith(normalizedInstallPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            // Strategy 2: Intelligent path component matching
            // Extract meaningful words from path like: C:\Program Files\Google\Chrome\Application\chrome.exe
            // Match against app name words and publisher words
            var pathComponents = ExtractPathComponents(normalizedProcessPath);
            var appNameWords = ExtractWords(app.Name);
            var publisherWords = !string.IsNullOrEmpty(app.Publisher) ? ExtractWords(app.Publisher) : new List<string>();

            var matchScore = CalculateMatchScore(pathComponents, appNameWords, publisherWords);

            // Require 50% match of significant app words found in path
            if (matchScore >= 0.5)
            {
                return true;
            }

            // Strategy 3: Process filename directly matches app name word (minimum 4 chars to avoid false positives)
            var processFileName = System.IO.Path.GetFileNameWithoutExtension(normalizedProcessPath);
            if (processFileName.Length >= 4 && !string.IsNullOrEmpty(app.Name))
            {
                var appNameLower = app.Name.ToLowerInvariant();
                if (appNameLower.Contains(processFileName))
                {
                    return true;
                }
            }

            // Strategy 4: App name word matches process filename only (NOT full path)
            // Restricted to filename match to prevent false positives from vendor names
            // appearing in unrelated paths (e.g. "microsoft" matching C:\Program Files\Microsoft\...\anything.exe)
            if (!string.IsNullOrEmpty(app.Name))
            {
                var nameWords = app.Name.ToLowerInvariant()
                    .Split(new[] { ' ', '-', '_', '.' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(w => w.Length >= 4)
                    .Where(w => !IsCommonWord(w))
                    .Where(w => !IsVendorName(w));

                foreach (var word in nameWords)
                {
                    // Only match against process filename, not full path
                    if (processFileName.Contains(word))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Check if a word is a vendor/publisher name that appears in many unrelated paths.
        /// These must not be used alone for single-word matching (Strategy 4) since
        /// "microsoft" appears in paths for Defender, Intune, Office, Edge, .NET, etc.
        /// </summary>
        public static bool IsVendorName(string word)
        {
            var vendorNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "microsoft", "google", "apple", "adobe", "mozilla", "autodesk",
                "oracle", "intel", "nvidia", "amd", "dell", "lenovo", "hewlett",
                "packard", "samsung", "vmware", "citrix", "cisco", "juniper"
            };
            return vendorNames.Contains(word);
        }

        /// <summary>
        /// Extract meaningful components from a file path for matching.
        /// Filters out common path words like "Program Files", "x86", etc.
        /// </summary>
        public static List<string> ExtractPathComponents(string path)
        {
            var components = path
                .Split(new[] { '\\', '/', ' ', '-', '_' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(c => c.Length >= 3)
                .Where(c => !IsCommonPathWord(c))
                .Select(c => c.ToLowerInvariant().Replace(".exe", ""))
                .Distinct()
                .ToList();

            return components;
        }

        /// <summary>
        /// Extract meaningful words from an app name or publisher string.
        /// </summary>
        public static List<string> ExtractWords(string? text)
        {
            if (string.IsNullOrEmpty(text))
                return new List<string>();

            return text
                .Split(new[] { ' ', '-', '_', '.', '(', ')' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(w => w.Length >= 3)
                .Where(w => !IsCommonWord(w))
                .Select(w => w.ToLowerInvariant())
                .Distinct()
                .ToList();
        }

        /// <summary>
        /// Common path words that should be ignored during matching.
        /// NOTE: Vendor names (microsoft, google, apple, adobe) are intentionally NOT filtered
        /// because they are critical for matching apps like Chrome, VS Code, Teams, etc.
        /// </summary>
        public static bool IsCommonPathWord(string word)
        {
            var commonWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Path structure words
                "program", "files", "x86", "x64", "application", "applications", "app", "apps",
                "bin", "exe", "dll", "common", "shared", "resources", "lib", "usr", "local",
                "windowsapps", "appdata", "roaming", "users", "programdata",
                // Version/architecture patterns
                "win32", "win64", "amd64", "arm64",
                // SDK/Tool paths (not vendor names)
                "sdks", "cli2", "cli", "tools", "sdk", "kits",
                // OS-related paths
                "windows", "system", "system32", "syswow64"
                // NOTE: Do NOT filter vendor names like microsoft, google, apple, adobe, mozilla, etc.
                // These are essential for matching apps like "Google Chrome", "Microsoft Teams", etc.
            };
            return commonWords.Contains(word);
        }

        /// <summary>
        /// Common words in app names/publishers that should be ignored during matching.
        /// These words are too generic to reliably identify an application.
        /// NOTE: Vendor names (microsoft, google, etc.) are intentionally NOT filtered
        /// because they help match apps like "Google Chrome", "Microsoft Teams".
        /// </summary>
        public static bool IsCommonWord(string word)
        {
            var commonWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Generic business suffixes
                "inc", "llc", "ltd", "corp", "corporation", "software", "technologies",
                // Common generic app name words
                "the", "for", "and", "pro", "free", "edition", "version", "update",
                // OS-related generic words
                "desktop", "runtime", "client", "installer", "setup"
                // NOTE: Do NOT filter vendor names like microsoft, google, apple, adobe, etc.
                // These are essential for matching apps by their full names.
            };
            return commonWords.Contains(word);
        }

        /// <summary>
        /// Calculate a match score between path components and app name/publisher words.
        /// Returns a score from 0.0 to 1.0 indicating match confidence.
        /// Requires multiple significant word matches to avoid false positives.
        /// </summary>
        public static double CalculateMatchScore(List<string> pathComponents, List<string> appNameWords, List<string> publisherWords)
        {
            // Need at least 1 meaningful app name word (after filtering common words)
            if (appNameWords.Count == 0)
                return 0;

            // Count how many app name words match path components
            var appNameMatches = 0;
            foreach (var appWord in appNameWords)
            {
                // Skip short words - they cause too many false positives
                if (appWord.Length < 4)
                    continue;

                foreach (var pathComp in pathComponents)
                {
                    if (pathComp.Length < 4)
                        continue;

                    // Require exact match or strong containment (not just partial overlap)
                    if (pathComp == appWord ||
                        pathComp.StartsWith(appWord) ||
                        appWord.StartsWith(pathComp))
                    {
                        appNameMatches++;
                        break;
                    }
                }
            }

            // Require at least 1 significant app name match
            if (appNameMatches == 0)
                return 0;

            // Calculate score based on app name matches only (publisher is bonus, not required)
            var score = (double)appNameMatches / appNameWords.Count;

            // Bonus for publisher match (but don't rely on it alone)
            if (publisherWords.Count > 0)
            {
                var publisherMatches = publisherWords.Count(pw =>
                    pw.Length >= 4 && pathComponents.Any(pc => pc.Length >= 4 && (pc == pw || pc.StartsWith(pw) || pw.StartsWith(pc))));
                if (publisherMatches > 0)
                {
                    score = Math.Min(1.0, score + 0.1);
                }
            }

            return score;
        }
    }
}
