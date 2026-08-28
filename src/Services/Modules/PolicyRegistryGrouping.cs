#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using ReportMate.WindowsClient.Models.Modules;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Turns flat policy registry rows into the same shape the macOS client reports for
    /// mobileconfig profiles: one profile per policy branch, each carrying every key beneath
    /// it as payload settings.
    ///
    /// There is deliberately no per-product logic anywhere in here. Chrome, Edge, Firefox,
    /// Adobe, Cimian and anything installed next are all just branches under a policy root,
    /// so coverage never depends on someone remembering to add a query. The previous design
    /// enumerated products by hand and silently reported nothing for every product missing
    /// from the list.
    /// </summary>
    public static class PolicyRegistryGrouping
    {
        /// <summary>A policy registry root to sweep: which query supplies it, and how to label it.</summary>
        public readonly record struct PolicyRoot(string Query, string Source, string Scope);

        public sealed class Result
        {
            public List<RegistryPolicy> RegistryPolicies { get; } = new();
            public List<ConfigurationProfile> ConfigurationProfiles { get; } = new();
        }

        public static Result Group(
            IEnumerable<PolicyRoot> roots,
            IReadOnlyDictionary<string, List<Dictionary<string, object>>> osqueryResults,
            DateTime collectedAt)
        {
            var result = new Result();

            // Keyed by branch so a policy present in both the native and WOW6432Node views
            // collapses into one profile instead of appearing twice.
            var branches = new Dictionary<string, ConfigurationProfile>(StringComparer.OrdinalIgnoreCase);
            var seenValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var root in roots)
            {
                if (!osqueryResults.TryGetValue(root.Query, out var rows) || rows is null) continue;

                foreach (var row in rows)
                {
                    var fullPath = Field(row, "path");
                    var valueName = Field(row, "name");
                    if (fullPath.Length == 0 || valueName.Length == 0) continue;

                    var value = Field(row, "data");
                    var valueType = Field(row, "type");

                    // osquery reports the value's own path; the branch is its parent key.
                    var branchPath = NormalisePolicyPath(GetParentKey(fullPath));
                    if (branchPath.Length == 0) continue;

                    var category = ExtractPolicyCategory(fullPath);

                    // Flat view - every value, every key, unmodified.
                    if (seenValues.Add(branchPath + "|" + valueName))
                    {
                        result.RegistryPolicies.Add(new RegistryPolicy
                        {
                            KeyPath = branchPath,
                            ValueName = valueName,
                            Value = value,
                            Type = valueType,
                            Source = root.Source,
                            Category = category,
                            LastModified = collectedAt
                        });
                    }

                    // Profile view - grouped the way a mobileconfig groups its payloads.
                    if (!branches.TryGetValue(branchPath, out var profile))
                    {
                        var branchName = GetPolicyBranchName(branchPath);
                        var vendor = ExtractPolicyVendor(branchPath);

                        profile = new ConfigurationProfile
                        {
                            Name = branchName,
                            ProfileName = branchName,
                            Uuid = branchPath,
                            Identifier = branchPath,
                            Source = root.Source,
                            Organization = vendor,
                            Category = category,
                            Type = root.Scope,
                            Status = "Applied",
                            Description = IsUserHive(branchPath)
                                ? "User hive " + GetUserHiveSid(branchPath)
                                : "",
                            InstallDate = collectedAt,
                            LastModified = collectedAt,
                            Payloads =
                            {
                                new ProfilePayload
                                {
                                    Type = vendor,
                                    Identifier = branchPath,
                                    DisplayName = branchName
                                }
                            }
                        };
                        branches[branchPath] = profile;
                    }

                    profile.Payloads[0].Settings[valueName] = value;
                    profile.Settings[valueName] = value;
                    if (!profile.AppliedSettings.Contains(valueName)) profile.AppliedSettings.Add(valueName);
                }
            }

            foreach (var profile in branches.Values)
            {
                profile.PayloadCount = profile.Payloads.Count;
                result.ConfigurationProfiles.Add(profile);
            }

            return result;
        }

        private static string Field(Dictionary<string, object> row, string key)
            => row.TryGetValue(key, out var v) ? v?.ToString() ?? "" : "";

        /// <summary>Parent key of a registry value path.</summary>
        public static string GetParentKey(string path)
        {
            var i = path.LastIndexOf('\\');
            return i <= 0 ? path : path.Substring(0, i);
        }

        /// <summary>
        /// Collapses the 32-bit registry view onto its native equivalent so a policy visible in
        /// both does not report as two separate profiles.
        /// </summary>
        public static string NormalisePolicyPath(string path)
        {
            // HKU\.DEFAULT and HKU\S-1-5-18 are two names for the same hive; without this they
            // report as two profiles holding identical settings.
            path = path.Replace("HKEY_USERS\\.DEFAULT\\", "HKEY_USERS\\S-1-5-18\\", StringComparison.OrdinalIgnoreCase);
            return path.Replace("\\SOFTWARE\\WOW6432Node\\", "\\SOFTWARE\\", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>True when the value lives in a loaded user hive rather than machine scope.</summary>
        public static bool IsUserHive(string path)
            => path.StartsWith("HKEY_USERS\\", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// The hive a user-scope value belongs to. Returns the SID as written; callers get
        /// S-1-5-18 for the SYSTEM/default hive because NormalisePolicyPath folds .DEFAULT onto it.
        /// </summary>
        public static string GetUserHiveSid(string path)
        {
            if (!IsUserHive(path)) return "";
            var rest = path.Substring("HKEY_USERS\\".Length);
            var i = rest.IndexOf('\\');
            return i > 0 ? rest.Substring(0, i) : rest;
        }

        /// <summary>
        /// The path segments that introduce a policy root. Order matters only in that the first
        /// match wins; every root a query sweeps needs an entry, or its branches fall back to the
        /// full registry path and read as unnamed profiles.
        /// </summary>
        private static readonly string[] PolicyRootMarkers =
        {
            "\\SOFTWARE\\Policies\\",
            "\\PolicyManager\\current\\",
            "\\CurrentVersion\\Policies\\",
            "\\CurrentControlSet\\Policies\\",
        };

        /// <summary>Branch name relative to its policy root, e.g. Google\Chrome.</summary>
        public static string GetPolicyBranchName(string branchPath)
        {
            foreach (var marker in PolicyRootMarkers)
            {
                var i = branchPath.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (i >= 0) return branchPath.Substring(i + marker.Length);
            }
            return branchPath;
        }

        /// <summary>Vendor is the first segment under the policy root - derived, never enumerated.</summary>
        public static string ExtractPolicyVendor(string branchPath)
        {
            // Windows' own policy branches live under Microsoft's key, so the owner is structural
            // rather than something to look up. Without this the first segment of the branch name
            // ("System", "Explorer") would be reported as though it were a vendor.
            if (branchPath.IndexOf("\\CurrentVersion\\Policies\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                branchPath.IndexOf("\\CurrentControlSet\\Policies\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "Microsoft";
            }

            var name = GetPolicyBranchName(branchPath);
            var i = name.IndexOf('\\');
            return i > 0 ? name.Substring(0, i) : name;
        }

        /// <summary>
        /// Category is derived from where the policy lives, not from a list of known products.
        /// For GPO/ADMX branches that is the vendor plus its product segment ("Google Chrome",
        /// "Mozilla Firefox"); for CSP branches it is the policy area Windows itself uses.
        /// A product nobody has heard of yet categorises correctly on the day it ships.
        /// </summary>
        public static string ExtractPolicyCategory(string path)
        {
            const string csp = "\\PolicyManager\\current\\";
            var cspIndex = path.IndexOf(csp, StringComparison.OrdinalIgnoreCase);
            if (cspIndex >= 0)
            {
                // .../current/device/<Area>/<Setting> - the area is the meaningful grouping.
                var area = path.Substring(cspIndex + csp.Length)
                               .Split('\\', StringSplitOptions.RemoveEmptyEntries)
                               .FirstOrDefault(seg =>
                                   !seg.Equals("device", StringComparison.OrdinalIgnoreCase) &&
                                   !seg.Equals("user", StringComparison.OrdinalIgnoreCase));
                return string.IsNullOrEmpty(area) ? "MDM" : area;
            }

            const string gpo = "\\SOFTWARE\\Policies\\";
            var gpoIndex = path.IndexOf(gpo, StringComparison.OrdinalIgnoreCase);
            if (gpoIndex >= 0)
            {
                var segments = path.Substring(gpoIndex + gpo.Length)
                                   .Split('\\', StringSplitOptions.RemoveEmptyEntries);
                if (segments.Length == 0) return "General";

                // Drop the trailing value name so a one-level branch does not read as its value.
                var branch = segments.Length > 1 ? segments[..^1] : segments;
                return branch.Length >= 2 ? branch[0] + " " + branch[1] : branch[0];
            }

            foreach (var marker in new[] { "\\CurrentVersion\\Policies\\", "\\CurrentControlSet\\Policies\\" })
            {
                var i = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (i < 0) continue;

                var segments = path.Substring(i + marker.Length)
                                   .Split('\\', StringSplitOptions.RemoveEmptyEntries);
                // Drop the trailing value name so a one-level branch does not read as its value.
                var branch = segments.Length > 1 ? segments[..^1] : segments;
                return branch.Length > 0 ? "Windows " + branch[0] : "Windows";
            }

            return "General";
        }
    }
}
