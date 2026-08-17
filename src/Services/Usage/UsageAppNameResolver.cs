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
    /// Two collection paths call in here, and they now run the same algorithm:
    ///
    /// - <see cref="ResolveInstalledApp"/> backs the Security Log path, which
    ///   supplies total_seconds, and drops anything it cannot name.
    /// - <see cref="ResolveTrackerAppName"/> backs the per-user usage tracker
    ///   merge, which supplies foreground and active seconds, and keeps what it
    ///   cannot name under the executable filename -- except an OS component,
    ///   which it drops, because "not an application" and "an application I do
    ///   not recognise" warrant different answers.
    ///
    /// They used to differ -- the Security Log path ran the fuzzy predicate
    /// first while the tracker consulted only InstallLocation -- so the same
    /// application arrived as two rows, one holding total_seconds under
    /// "Google Chrome" and another holding foreground and active seconds under
    /// "chrome". Both now resolve through the same lookup, in this order:
    ///
    ///   1. never an operating-system component (<see cref="IsOperatingSystemComponent"/>)
    ///   2. the longest InstallLocation that is a directory prefix of the path
    ///   3. the fuzzy <see cref="MatchesApplication"/> predicate, as a guess
    ///
    /// The fixture tests in ReportMate.WindowsClient.Tests pin every resolution,
    /// so any change to attribution is visible in a diff. Work item 4353.
    /// </summary>
    public static class UsageAppNameResolver
    {
        /// <summary>
        /// Security Log path: the installed application this executable belongs
        /// to, or null when nothing in the inventory owns it.
        ///
        /// InstallLocation is decided by longest prefix, so the result no longer
        /// depends on the order of the inventory. Only the fuzzy fallback is
        /// still first-to-match, and it is reached only when no location covers
        /// the path at all.
        /// </summary>
        public static InstalledApplication? ResolveInstalledApp(
            string processPath,
            IEnumerable<InstalledApplication> installedApps)
        {
            if (string.IsNullOrWhiteSpace(processPath)) return null;

            // An OS component is never an installed application.
            if (IsOperatingSystemComponent(processPath)) return null;

            // InstallLocation is authoritative when it covers the executable, and
            // the longest one wins so a bundled tool is not swallowed by the suite
            // it ships inside. Only when no location covers the path does the
            // fuzzy predicate get a say -- it is a guess, and it used to run first
            // for every lookup, which is how msedge.exe became "Microsoft OneDrive".
            return ResolveByInstallLocation(processPath, installedApps)
                   ?? installedApps.FirstOrDefault(app => MatchesApplication(processPath, app));
        }

        /// <summary>
        /// The installed application whose InstallLocation is the longest
        /// directory prefix of the executable path, or null.
        ///
        /// The boundary check is what keeps "C:\Program Files\Widget" from
        /// claiming "C:\Program Files\WidgetWorks\other.exe".
        /// </summary>
        private static InstalledApplication? ResolveByInstallLocation(
            string exePath,
            IEnumerable<InstalledApplication> installedApps)
        {
            InstalledApplication? best = null;
            var bestLen = 0;
            var normExe = exePath.Replace('/', '\\').TrimEnd('\\');

            foreach (var app in installedApps)
            {
                var loc = app.InstallLocation;
                if (string.IsNullOrWhiteSpace(loc)) continue;
                var normLoc = loc.Replace('/', '\\').TrimEnd('\\');
                if (normLoc.Length == 0 || normLoc.Length <= bestLen) continue;

                if (normExe.StartsWith(normLoc, StringComparison.OrdinalIgnoreCase) &&
                    (normExe.Length == normLoc.Length || normExe[normLoc.Length] == '\\'))
                {
                    bestLen = normLoc.Length;
                    best = app;
                }
            }

            return best;
        }

        /// <summary>
        /// Usage tracker path: the same resolution the Security Log path makes,
        /// falling back to the executable filename without its extension when
        /// nothing in the inventory owns it, and to nothing at all when the
        /// executable is an operating-system component.
        ///
        /// The caller skips an empty name, so returning empty is how this path
        /// drops a process -- the same outcome the Security Log path reaches by
        /// returning a null application.
        /// </summary>
        public static string ResolveTrackerAppName(
            string exePath,
            IEnumerable<InstalledApplication> installedApps)
        {
            if (string.IsNullOrWhiteSpace(exePath)) return string.Empty;

            // An OS component is dropped rather than named. ResolveInstalledApp
            // returns null for two different reasons -- "this is not an
            // application" and "I don't recognise this application" -- and only
            // the second one justifies the basename fallback below. Without this
            // check the shell reached the report as "explorer", 74.7 active hours
            // across 150 devices, ranked above After Effects and Maya, while the
            // Security Log path had already dropped every one of those sessions.
            // Work item 4525.
            if (IsOperatingSystemComponent(exePath)) return string.Empty;

            // Deliberately the same call the Security Log path makes. The two
            // used to run different algorithms -- this one consulted only
            // InstallLocation and kept the exe filename when that missed, so
            // chrome.exe arrived as "chrome" here and "Google Chrome" there, and
            // the same application landed as two usage_history rows. Sharing the
            // resolver makes them agree by construction rather than by
            // maintenance.
            var app = ResolveInstalledApp(exePath, installedApps);
            if (!string.IsNullOrWhiteSpace(app?.Name)) return app!.Name;

            // Nothing in the inventory owns it. Keep the executable name so the
            // usage is still attributed to something recognisable.
            return ExecutableBaseName(exePath);
        }

        /// <summary>
        /// The filename of a Windows executable path, without its extension.
        ///
        /// Deliberately not Path.GetFileNameWithoutExtension: that splits on the
        /// host's separator, so on a non-Windows host it treats an entire
        /// "C:\Windows\explorer.exe" as one filename. These paths are always
        /// Windows paths regardless of where the code runs, and the resolver's
        /// results must not depend on the machine evaluating them.
        /// </summary>
        public static string ExecutableBaseName(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return string.Empty;

            var normalized = path.Replace('/', '\\').TrimEnd('\\');
            var slash = normalized.LastIndexOf('\\');
            var name = slash >= 0 ? normalized.Substring(slash + 1) : normalized;

            var dot = name.LastIndexOf('.');
            return dot > 0 ? name.Substring(0, dot) : name;
        }

        /// <summary>
        /// Whether a path is an operating-system component rather than an
        /// installed application.
        ///
        /// Nothing under the Windows directory is owned by an entry in the
        /// installed-applications inventory, but the fuzzy predicate below
        /// happily claims them: in production it attributed C:\Windows\explorer.exe
        /// to "Microsoft Azure Storage Explorer", System32\wscript.exe to
        /// "VS Script Debugging Common", and most SystemApps binaries to
        /// "Microsoft OneDrive". Every one of those inflates an unrelated
        /// application's usage with shell and input-stack activity.
        ///
        /// Store apps live under Program Files\WindowsApps, not here, so they
        /// are unaffected.
        /// </summary>
        public static bool IsOperatingSystemComponent(string processPath)
        {
            if (string.IsNullOrWhiteSpace(processPath)) return false;
            var normalized = processPath.Replace('/', '\\');

            // Drive-qualified (C:\Windows\...) rather than %SystemRoot%, so the
            // check behaves identically wherever the tests run.
            var windows = normalized.IndexOf(@":\Windows\", StringComparison.OrdinalIgnoreCase);
            return windows == 1;
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

            // An OS component is never an installed application. This is checked
            // before InstallLocation too: an inventory entry whose location is a
            // Windows directory would otherwise capture the entire shell.
            if (IsOperatingSystemComponent(processPath))
                return false;

            var normalizedProcessPath = processPath.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();

            // Strategy 1: Install location prefix match (most accurate)
            if (!string.IsNullOrEmpty(app.InstallLocation))
            {
                var normalizedInstallPath = app.InstallLocation.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
                // Directory boundary, so "C:\Program Files\Widget" does not claim
                // "C:\Program Files\WidgetWorks\other.exe".
                if (normalizedProcessPath.StartsWith(normalizedInstallPath, StringComparison.OrdinalIgnoreCase) &&
                    (normalizedProcessPath.Length == normalizedInstallPath.Length ||
                     normalizedProcessPath[normalizedInstallPath.Length] == '\\'))
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
            var processFileName = ExecutableBaseName(normalizedProcessPath);
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
        /// Whether two path or name words refer to the same thing.
        ///
        /// Equal words match. A longer word matches a shorter one only when the
        /// extra characters are not letters, which admits a version suffix
        /// ("python312" is Python) while rejecting a different word glued on
        /// ("widgetworks" is not Widget). Plain StartsWith accepted both, and
        /// that false positive now reaches the foreground and active counters
        /// too, because the tracker path consults this predicate.
        /// </summary>
        public static bool IsWordOrVersionedMatch(string a, string b)
        {
            if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;

            var (longer, shorter) = a.Length > b.Length ? (a, b) : (b, a);
            if (!longer.StartsWith(shorter, StringComparison.OrdinalIgnoreCase)) return false;

            for (var i = shorter.Length; i < longer.Length; i++)
            {
                if (char.IsLetter(longer[i])) return false;
            }
            return true;
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

                    if (IsWordOrVersionedMatch(pathComp, appWord))
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
                    pw.Length >= 4 && pathComponents.Any(pc => pc.Length >= 4 && IsWordOrVersionedMatch(pc, pw)));
                if (publisherMatches > 0)
                {
                    score = Math.Min(1.0, score + 0.1);
                }
            }

            return score;
        }
    }
}
