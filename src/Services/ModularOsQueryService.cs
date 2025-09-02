using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Services;
using ReportMate.WindowsClient.Models;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Service for loading and managing modular osquery configurations
    /// </summary>
    public class ModularOsQueryService
    {
        private readonly ILogger<ModularOsQueryService> _logger;

        public ModularOsQueryService(ILogger<ModularOsQueryService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Load all enabled osquery modules and combine their queries
        /// </summary>
        public Dictionary<string, object> LoadModularQueries()
        {
            try
            {
                var combinedQueries = new Dictionary<string, object>();
                
                // Find the modular osquery directory in working data directory (ProgramData)
                var workingDataDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "ManagedReports");
                var osqueryDir = Path.Combine(workingDataDir, "osquery");
                var modulesDir = Path.Combine(osqueryDir, "modules");
                var enabledModulesFile = Path.Combine(osqueryDir, "enabled-modules.json");

                if (!Directory.Exists(modulesDir))
                {
                    _logger.LogWarning("Modular osquery directory not found at {Path}, falling back to unified query file", modulesDir);
                    return LoadUnifiedQueries();
                }

                if (!File.Exists(enabledModulesFile))
                {
                    _logger.LogWarning("enabled-modules.json not found, loading all available modules");
                    return LoadAllModules(modulesDir);
                }

                // Load enabled modules configuration
                var enabledModulesJson = File.ReadAllText(enabledModulesFile);
                var enabledConfig = JsonSerializer.Deserialize(enabledModulesJson, ReportMateJsonContext.Default.EnabledModulesConfig);

                if (enabledConfig?.Enabled == null || !enabledConfig.Enabled.Any())
                {
                    _logger.LogWarning("No enabled modules found, loading all available modules");
                    return LoadAllModules(modulesDir);
                }

                _logger.LogInformation($"Loading {enabledConfig.Enabled.Count} enabled osquery modules");

                // Load each enabled module
                foreach (var moduleName in enabledConfig.Enabled)
                {
                    var moduleFile = Path.Combine(modulesDir, $"{moduleName}.json");
                    if (File.Exists(moduleFile))
                    {
                        LoadModule(moduleFile, combinedQueries);
                    }
                    else
                    {
                        _logger.LogWarning($"Module file not found: {moduleFile}");
                    }
                }

                _logger.LogInformation($"Loaded {combinedQueries.Count} queries from {enabledConfig.Enabled.Count} modules");
                return combinedQueries;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading modular osquery configuration, falling back to unified");
                return LoadUnifiedQueries();
            }
        }

        private Dictionary<string, object> LoadAllModules(string modulesDir)
        {
            var combinedQueries = new Dictionary<string, object>();
            var moduleFiles = Directory.GetFiles(modulesDir, "*.json");

            _logger.LogInformation($"Loading all {moduleFiles.Length} available modules");

            foreach (var moduleFile in moduleFiles)
            {
                LoadModule(moduleFile, combinedQueries);
            }

            return combinedQueries;
        }

        private void LoadModule(string moduleFile, Dictionary<string, object> combinedQueries)
        {
            try
            {
                var moduleJson = File.ReadAllText(moduleFile);
                var module = JsonSerializer.Deserialize(moduleJson, ReportMateJsonContext.Default.OsQueryModule);

                if (module?.Queries != null)
                {
                    var moduleName = Path.GetFileNameWithoutExtension(moduleFile);
                    _logger.LogInformation($"    Loading module: {moduleName} ({module.Queries.Count} queries)");

                    foreach (var query in module.Queries)
                    {
                        combinedQueries[query.Key] = query.Value;
                        _logger.LogDebug($"     Added query: {query.Key}");
                    }
                }
                else
                {
                    _logger.LogWarning($"Module {moduleFile} has no queries or failed to deserialize");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Error loading module: {moduleFile}");
            }
        }

        /// <summary>
        /// Load queries for a specific module only
        /// </summary>
        public Dictionary<string, object> LoadModuleQueries(string moduleId)
        {
            try
            {
                var moduleQueries = new Dictionary<string, object>();
                
                // Find the modular osquery directory in working data directory (ProgramData)
                var workingDataDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "ManagedReports");
                var osqueryDir = Path.Combine(workingDataDir, "osquery");
                var modulesDir = Path.Combine(osqueryDir, "modules");

                if (!Directory.Exists(modulesDir))
                {
                    _logger.LogWarning("Modular osquery directory not found for module {ModuleId} at {Path}", moduleId, modulesDir);
                    return new Dictionary<string, object>();
                }

                // Also load system_info for device UUID extraction (needed for all modules)
                var systemModuleFile = Path.Combine(modulesDir, "system.json");
                if (File.Exists(systemModuleFile))
                {
                    LoadSpecificQueriesFromModule(systemModuleFile, moduleQueries, new[] { "system_info" });
                }

                // Load the specific module
                var moduleFile = Path.Combine(modulesDir, $"{moduleId}.json");
                if (!File.Exists(moduleFile))
                {
                    _logger.LogError("Module file not found for {ModuleId}: {ModuleFile}", moduleId, moduleFile);
                    return new Dictionary<string, object>();
                }

                _logger.LogInformation("Loading queries for single module: {ModuleId}", moduleId);
                LoadModule(moduleFile, moduleQueries);

                _logger.LogInformation("Loaded {QueryCount} queries for module {ModuleId}", moduleQueries.Count, moduleId);
                return moduleQueries;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading queries for module {ModuleId}", moduleId);
                return new Dictionary<string, object>();
            }
        }

        /// <summary>
        /// Load specific queries from a module file
        /// </summary>
        private void LoadSpecificQueriesFromModule(string moduleFile, Dictionary<string, object> combinedQueries, string[] queryNames)
        {
            try
            {
                var moduleJson = File.ReadAllText(moduleFile);
                var module = JsonSerializer.Deserialize(moduleJson, ReportMateJsonContext.Default.OsQueryModule);

                if (module?.Queries != null)
                {
                    var moduleName = Path.GetFileNameWithoutExtension(moduleFile);
                    
                    foreach (var queryName in queryNames)
                    {
                        if (module.Queries.TryGetValue(queryName, out var query))
                        {
                            combinedQueries[queryName] = query;
                            _logger.LogDebug("Added specific query: {QueryName} from module {ModuleName}", queryName, moduleName);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error loading specific queries from module: {ModuleFile}", moduleFile);
            }
        }

        private Dictionary<string, object> LoadUnifiedQueries()
        {
            try
            {
                // Fallback to unified query file
                var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                var unifiedFile = Path.Combine(baseDir, "osquery-unified.json");

                if (File.Exists(unifiedFile))
                {
                    _logger.LogInformation(" Loading unified osquery configuration as fallback");
                    var unifiedJson = File.ReadAllText(unifiedFile);
                    var unified = JsonSerializer.Deserialize<Dictionary<string, object>>(unifiedJson);
                    
                    if (unified?.ContainsKey("queries") == true)
                    {
                        return JsonSerializer.Deserialize<Dictionary<string, object>>(unified["queries"].ToString() ?? "{}") ?? new Dictionary<string, object>();
                    }
                }

                _logger.LogError("No osquery configuration files found");
                return new Dictionary<string, object>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading unified osquery configuration");
                return new Dictionary<string, object>();
            }
        }
    }

    public class EnabledModulesConfig
    {
        public List<string> Enabled { get; set; } = new List<string>();
        public string Version { get; set; } = "1.0.0";
        public string Generated { get; set; } = DateTime.UtcNow.ToString("O");
        public string Description { get; set; } = "";
        public string Platform { get; set; } = "windows";
    }

    public class OsQueryModule
    {
        public string Module { get; set; } = "";
        public string Version { get; set; } = "1.0.0";
        public string Description { get; set; } = "";
        public Dictionary<string, object> Queries { get; set; } = new Dictionary<string, object>();
    }
}
