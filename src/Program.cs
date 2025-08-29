#nullable enable
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Services;
using ReportMate.WindowsClient.Services.Modules;
using ReportMate.WindowsClient.Configuration;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using NetEscapades.Configuration.Yaml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Serilog;
using Serilog.Extensions.Logging;

namespace ReportMate.WindowsClient;

/// <summary>
/// ReportMate - Collects device data using osquery and sends to ReportMate API
/// Designed to run as a postflight script after managed software updates
/// </summary>
public class Program
{
    private static ServiceProvider? _serviceProvider;
    private static ILogger<Program>? _logger;

    // Windows API for console attachment
    [DllImport("kernel32.dll")]
    static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool AllocConsole();

    [DllImport("kernel32.dll")]
    static extern bool FreeConsole();

    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    const int ATTACH_PARENT_PROCESS = -1;

    public static async Task<int> Main(string[] args)
    {
        try
        {
            // Check for verbose flag early to enable console output
            var verboseLevel = GetVerboseLevelFromArgs(args);
            var isVerbose = verboseLevel > 0;
            
            // Handle console attachment for verbose mode
            if (isVerbose)
            {
                // Try to attach to the parent process console (the terminal we were launched from)
                if (AttachConsole(ATTACH_PARENT_PROCESS))
                {
                    // Successfully attached to parent console
                    // Redirect console output to the attached console
                    Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
                    Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
                }
                else
                {
                    // Could not attach to parent console - running interactively or from a different context
                    // Don't allocate a new console, just use the existing one
                    Console.WriteLine("Warning: Could not attach to parent console, using current console output");
                }
            }
            
            // Initialize enhanced logging for verbose mode
            if (isVerbose)
            {
                Logger.SetVerboseLevel(verboseLevel);
                ConsoleFormatter.SetVerboseMode(verboseLevel >= 2); // Enable for INFO level and above
                Logger.Section("ReportMate Windows Client", "Verbose logging enabled");
                Logger.Info("Version: {0}", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown");
                Logger.Info("Arguments: {0}", string.Join(" ", args));
                Logger.Info("Verbose Level: {0} ({1})", verboseLevel, GetVerboseLevelName(verboseLevel));
                Logger.Info("Platform: {0}", Environment.OSVersion.VersionString);
                Logger.Debug("Logger initialized with level {0}", verboseLevel);
            }
            
            // Build configuration from multiple sources
            var configuration = BuildConfiguration(verboseLevel);
            
            if (isVerbose)
            {
                Logger.Info("Configuration built successfully");
            }
            
            // Setup dependency injection with verbose flag
            _serviceProvider = ConfigureServices(configuration, verboseLevel);
            _logger = _serviceProvider.GetRequiredService<ILogger<Program>>();

            _logger.LogInformation("ReportMate v{Version} starting", 
                System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);

            // Log command line args
            _logger.LogInformation("Command line args: {Args}", string.Join(" ", args));

            // Create and configure command line interface
            var rootCommand = ConfigureCommandLine();
            
            // Preprocess arguments to convert -v, -vv, -vvv to --verbose=N format
            var processedArgs = PreprocessVerboseArgs(args);
            
            // Parse and execute commands
            var commandLineBuilder = new CommandLineBuilder(rootCommand)
                .UseDefaults()
                .UseExceptionHandler((exception, context) =>
                {
                    _logger?.LogError(exception, "Unhandled exception occurred");
                    context.ExitCode = 1;
                });

            var parser = commandLineBuilder.Build();
            return await parser.InvokeAsync(processedArgs);
        }
        catch (Exception ex)
        {
            // Handle console output for errors in verbose mode
            var verboseLevel = GetVerboseLevelFromArgs(args);
            var isVerbose = verboseLevel > 0;
            
            if (isVerbose)
            {
                Logger.SetVerboseLevel(verboseLevel);
                ConsoleFormatter.SetVerboseMode(verboseLevel >= 2); // Enable for INFO level and above
                Logger.Error("FATAL ERROR: {0}", ex.Message);
                if (verboseLevel >= 3)
                {
                    Logger.Debug("Stack Trace: {0}", ex.StackTrace ?? "No stack trace available");
                }
            }
            
            // Fallback logging when DI container fails - log to event log only
            try
            {
                using var eventLog = new System.Diagnostics.EventLog("Application");
                eventLog.Source = "ReportMate";
                eventLog.WriteEntry($"FATAL ERROR: {ex.Message}", System.Diagnostics.EventLogEntryType.Error);
            }
            catch
            {
                // If we can't even log to event log, just exit silently
            }
            Environment.ExitCode = 1;
            return 1;
        }
        finally
        {
            _serviceProvider?.Dispose();
            
            // Clean up console if we attached to it
            var verboseLevel = GetVerboseLevelFromArgs(args);
            var isVerbose = verboseLevel > 0;
            if (isVerbose && GetConsoleWindow() != IntPtr.Zero)
            {
                // Give a moment for output to flush
                await Task.Delay(100);
                
                // Don't free console if we attached to parent - let parent handle it
                // Only free if we allocated our own console
            }
        }
    }

    private static IConfiguration BuildConfiguration(int verboseLevel = 0)
    {
        var builder = new ConfigurationBuilder();
        var isVerbose = verboseLevel > 0;
        
        // Configuration hierarchy (lowest to highest precedence):
        if (isVerbose)
        {
            Logger.Section("Configuration Sources", "Loading settings from multiple sources in order of precedence");
            Logger.Info("1. Application defaults: Embedded in binary (no JSON dependency)");
        }
        
        // 2. YAML configuration from ProgramData (runtime/user editable)
        var programDataPath = ConfigurationService.GetWorkingDataDirectory();
        if (isVerbose)
        {
            Logger.Info("2. YAML configuration from: {0}", programDataPath);
        }
        if (Directory.Exists(programDataPath))
        {
            builder.SetBasePath(programDataPath)
                   .AddYamlFile("appsettings.yaml", optional: true, reloadOnChange: false);
        }
        
        // 3. Environment variables (prefix: REPORTMATE_)
        if (isVerbose)
        {
            Logger.Info("3. Environment variables with REPORTMATE_ prefix");
        }
        builder.AddEnvironmentVariables("REPORTMATE_");
        
        // 4. Check for default API URL from environment if not set
        var tempConfig = builder.Build();
        var apiUrl = tempConfig["ReportMate:ApiUrl"];
        if (string.IsNullOrEmpty(apiUrl))
        {
            // Try common environment variables
            var envApiUrl = Environment.GetEnvironmentVariable("REPORTMATE_API_URL") ?? 
                           Environment.GetEnvironmentVariable("API_URL") ?? 
                           Environment.GetEnvironmentVariable("SERVER_URL");
            
            if (!string.IsNullOrEmpty(envApiUrl))
            {
                if (isVerbose)
                {
                    Logger.Info("Using API URL from environment: {0}", envApiUrl);
                }
                builder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ReportMate:ApiUrl"] = envApiUrl
                });
            }
        }
        
        // 5. Windows Registry (highest precedence - CSP/Group Policy)
        if (isVerbose)
        {
            Logger.Info("4. Windows Registry (HIGHEST PRECEDENCE)");
            Logger.Debug("HKLM\\SOFTWARE\\ReportMate (standard)");
            Logger.Debug("HKLM\\SOFTWARE\\Config\\ReportMate (CSP/Group Policy)");
        }
        
        // Add registry configuration for both standard and policy locations
        try
        {
            // Standard ReportMate registry key
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\ReportMate"))
            {
                if (key != null)
                {
                    var registryDict = new Dictionary<string, string?>();
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName)?.ToString();
                        if (!string.IsNullOrEmpty(value))
                        {
                            // Map registry values to configuration keys
                            string configKey = valueName switch
                            {
                                "ApiUrl" => "ReportMate:ApiUrl",
                                "DeviceId" => "ReportMate:DeviceId",
                                "ApiKey" => "ReportMate:ApiKey",
                                "Passphrase" => "ReportMate:Passphrase",
                                "CollectionInterval" => "ReportMate:CollectionIntervalSeconds",
                                "LogLevel" => "Logging:LogLevel:Default",
                                "OsQueryPath" => "ReportMate:OsQueryPath",
                                _ => $"ReportMate:{valueName}"
                            };
                            registryDict[configKey] = value;
                            if (isVerbose)
                            {
                                Logger.Debug("Registry: {0} -> {1}", valueName, configKey);
                            }
                        }
                    }
                    if (registryDict.Count > 0)
                    {
                        builder.AddInMemoryCollection(registryDict);
                    }
                }
            }
            
            // Policy registry key (CSP/Group Policy) - highest precedence
            using (var policyKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Config\ReportMate"))
            {
                if (policyKey != null)
                {
                    var policyDict = new Dictionary<string, string?>();
                    foreach (var valueName in policyKey.GetValueNames())
                    {
                        var value = policyKey.GetValue(valueName)?.ToString();
                        if (!string.IsNullOrEmpty(value))
                        {
                            // Map policy registry values to configuration keys
                            string configKey = valueName switch
                            {
                                "ServerUrl" => "ReportMate:ApiUrl",
                                "ApiUrl" => "ReportMate:ApiUrl",
                                "DeviceId" => "ReportMate:DeviceId",
                                "ApiKey" => "ReportMate:ApiKey",
                                "Passphrase" => "ReportMate:Passphrase",
                                "CollectionInterval" => "ReportMate:CollectionIntervalSeconds",
                                "LogLevel" => "Logging:LogLevel:Default",
                                "OsQueryPath" => "ReportMate:OsQueryPath",
                                _ => $"ReportMate:{valueName}"
                            };
                            policyDict[configKey] = value;
                            if (isVerbose)
                            {
                                Logger.Debug("Policy: {0} -> {1}", valueName, configKey);
                            }
                        }
                    }
                    if (policyDict.Count > 0)
                    {
                        builder.AddInMemoryCollection(policyDict);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            if (isVerbose)
            {
                Logger.Warning("Could not read registry: {0}", ex.Message);
            }
        }

        var config = builder.Build();
        
        // Log the final configuration source for key settings only in verbose mode
        if (isVerbose)
        {
            Logger.Section("Final Configuration");
            var finalApiUrl = config["ReportMate:ApiUrl"];
            var deviceId = config["ReportMate:DeviceId"];
            var debugLogging = config["ReportMate:DebugLogging"];
            
            var configData = new Dictionary<string, object?>
            {
                ["ApiUrl"] = finalApiUrl ?? "NOT SET",
                ["DeviceId"] = deviceId ?? "NOT SET",
                ["DebugLogging"] = debugLogging ?? "NOT SET"
            };
            
            Logger.InfoWithData("Key configuration values", configData);
        }
        
        return config;
    }

    private static ServiceProvider ConfigureServices(IConfiguration configuration, int verboseLevel = 0)
    {
        var services = new ServiceCollection();

        // Configure Serilog first
        var logDirectory = configuration["ReportMate:LogDirectory"] ?? @"C:\ProgramData\ManagedReports\logs";
        Directory.CreateDirectory(logDirectory);
        
        var loggerConfig = new LoggerConfiguration();

        // Set Serilog minimum level based on enhanced logger verbose level
        var debugLogging = bool.TryParse(configuration["ReportMate:DebugLogging"], out var debugEnabled) && debugEnabled;
        
        // Map enhanced logger levels to Serilog levels:
        // Level 0 (Error only): Warning (to reduce noise, only show warnings and errors)
        // Level 1 (Error + Warning): Information (show info messages for better visibility)  
        // Level 2 (Error + Warning + Info): Information
        // Level 3 (All including Debug): Debug
        if (verboseLevel >= 3 || debugLogging)
        {
            loggerConfig.MinimumLevel.Debug();
        }
        else if (verboseLevel >= 1)
        {
            loggerConfig.MinimumLevel.Information();
        }
        else
        {
            // Level 0: Only errors and warnings to reduce noise
            loggerConfig.MinimumLevel.Warning();
        }

        // Always log to file and event log
        loggerConfig.WriteTo.File(
            Path.Combine(logDirectory, "reportmate-.log"),
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 30,
            fileSizeLimitBytes: 10 * 1024 * 1024, // 10MB
            shared: true)
            .Enrich.WithProperty("Application", "ReportMate")
            .Enrich.WithProperty("Version", System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown");

        // Add Windows Event Log in production
        var developmentEnabled = bool.TryParse(configuration["Development:Enabled"], out var devEnabled) && devEnabled;
        if (!developmentEnabled)
        {
            try
            {
                loggerConfig.WriteTo.EventLog("ReportMate", "Application", manageEventSource: true);
            }
            catch
            {
                // Ignore if event log cannot be configured
            }
        }

        // Add console logging in development mode OR when verbose flag is used
        if (developmentEnabled || verboseLevel > 0)
        {
            loggerConfig.WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}");
        }

        Log.Logger = loggerConfig.CreateLogger();

        // Configure logging
        services.AddLogging(builder =>
        {
            builder.ClearProviders();
            builder.AddSerilog(Log.Logger);
        });

        // Register configuration
        services.AddSingleton(configuration);
        
        // Register ReportMate configuration manually to avoid trim warnings
        var reportMateConfig = new ReportMateClientConfiguration
        {
            ApiUrl = configuration["ReportMate:ApiUrl"] ?? "",
            DeviceId = configuration["ReportMate:DeviceId"] ?? "",
            Passphrase = configuration["ReportMate:Passphrase"] ?? "",
            ApiKey = configuration["ReportMate:ApiKey"] ?? "",
            UserAgent = configuration["ReportMate:UserAgent"] ?? "ReportMate/1.0",
            CollectionIntervalSeconds = int.TryParse(configuration["ReportMate:CollectionIntervalSeconds"], out var interval) ? interval : 3600,
            MaxRetryAttempts = int.TryParse(configuration["ReportMate:MaxRetryAttempts"], out var attempts) ? attempts : 3,
            ApiTimeoutSeconds = int.TryParse(configuration["ReportMate:ApiTimeoutSeconds"], out var timeout) ? timeout : 300,
            MaxDataAgeMinutes = int.TryParse(configuration["ReportMate:MaxDataAgeMinutes"], out var maxAge) ? maxAge : 30,
            CimianIntegrationEnabled = bool.TryParse(configuration["ReportMate:CimianIntegrationEnabled"], out var enabled) ? enabled : true,
            DebugLogging = bool.TryParse(configuration["ReportMate:DebugLogging"], out var debug) && debug,
            OsQueryPath = configuration["ReportMate:OsQueryPath"] ?? @"C:\Program Files\osquery\osqueryi.exe"
        };
        services.AddSingleton(Microsoft.Extensions.Options.Options.Create(reportMateConfig));

        // Register HTTP client with proper configuration
        services.AddHttpClient<IApiService, ApiService>((serviceProvider, client) =>
        {
            var config = serviceProvider.GetRequiredService<IConfiguration>();
            var apiUrl = config["ReportMate:ApiUrl"];
            
            if (!string.IsNullOrEmpty(apiUrl))
            {
                client.BaseAddress = new Uri(apiUrl);
                client.Timeout = TimeSpan.FromMinutes(5);
                client.DefaultRequestHeaders.Add("User-Agent", 
                    $"ReportMate/{System.Reflection.Assembly.GetExecutingAssembly().GetName().Version}");
            }
        });

        // Register services
        // No longer using WMI - all data collection is done via osquery
        services.AddScoped<IApiService, ApiService>();
        services.AddScoped<IOsQueryService, OsQueryService>();
        services.AddScoped<IDataCollectionService, DataCollectionService>();
        services.AddScoped<IDeviceInfoService, DeviceInfoService>();
        services.AddScoped<IConfigurationService, ConfigurationService>();
        services.AddScoped<IWmiHelperService, WmiHelperService>(); // Add WMI service for fallback scenarios
        
        // Register modular services
        services.AddScoped<ModularOsQueryService>();
        services.AddScoped<IModularDataCollectionService, ModularDataCollectionService>();
        
        // Register module processors
        services.AddScoped<IModuleProcessorFactory, ModuleProcessorFactory>();
        services.AddScoped<ApplicationsModuleProcessor>();
        services.AddScoped<DisplayModuleProcessor>();
        services.AddScoped<HardwareModuleProcessor>();
        services.AddScoped<InventoryModuleProcessor>();
        services.AddScoped<InstallsModuleProcessor>();
        services.AddScoped<ManagementModuleProcessor>();
        services.AddScoped<NetworkModuleProcessor>();
        services.AddScoped<PeripheralsModuleProcessor>();
        services.AddScoped<PrinterModuleProcessor>();
        services.AddScoped<ProfilesModuleProcessor>();
        services.AddScoped<SecurityModuleProcessor>();
        services.AddScoped<SystemModuleProcessor>();

        return services.BuildServiceProvider();
    }

    private static RootCommand ConfigureCommandLine()
    {
        var rootCommand = new RootCommand("ReportMate - Device data collection and reporting");

        // Global options - these are used across all commands
        // Note: We handle -v, -vv, -vvv parsing manually in GetVerboseLevelFromArgs()
        // This option only handles --verbose=N format to avoid conflicts
        var verboseOption = new Option<int>("--verbose", () => 0, "Set verbose level (0=Error, 1=Warning, 2=Info, 3=Debug). Use -v, -vv, -vvv, -vvvv or --verbose=N")
        {
            Arity = ArgumentArity.ZeroOrOne
        };
        var deviceIdOption = new Option<string>("--device-id", "Override device ID");
        var apiUrlOption = new Option<string>("--api-url", "Override API URL");
        var forceOption = new Option<bool>("--force", "Force data collection even if recent run detected");
        var collectOnlyOption = new Option<bool>("--collect-only", "Collect data only without transmitting to API");
        var transmitOnlyOption = new Option<bool>("--transmit-only", "Transmit cached data only without collecting new data");
        var runModuleOption = new Option<string>("--run-module", "Run only a specific module (e.g., network, hardware, security). By default, this will collect and transmit the module data.");
        var runModulesOption = new Option<string>("--run-modules", "Run multiple specific modules separated by commas (e.g., hardware,installs,security). By default, this will collect and transmit the module data.");
        
        // Add global options to root command
        rootCommand.AddGlobalOption(verboseOption);
        rootCommand.AddOption(forceOption);
        rootCommand.AddOption(collectOnlyOption);
        rootCommand.AddOption(transmitOnlyOption);
        rootCommand.AddOption(runModuleOption);
        rootCommand.AddOption(runModulesOption);
        rootCommand.AddOption(deviceIdOption);
        rootCommand.AddOption(apiUrlOption);

        // Set default handler for root command (when no subcommand is specified)
        // This makes running the binary without any command default to data collection
        rootCommand.SetHandler(HandleRunCommand, forceOption, collectOnlyOption, transmitOnlyOption, runModuleOption, runModulesOption, deviceIdOption, apiUrlOption, verboseOption);

        // Run command - explicit run data collection (optional, since it's the default)
        var runCommand = new Command("run", "Run data collection and send to API (same as default behavior)")
        {
            forceOption,
            collectOnlyOption,
            transmitOnlyOption,
            runModuleOption,
            runModulesOption,
            deviceIdOption,
            apiUrlOption
        };
        runCommand.SetHandler(HandleRunCommand, forceOption, collectOnlyOption, transmitOnlyOption, runModuleOption, runModulesOption, deviceIdOption, apiUrlOption, verboseOption);

        // Transmit command - send cached data without collection
        var transmitCommand = new Command("transmit", "Transmit cached data without collecting new data (alias for --transmit-only)")
        {
            deviceIdOption,
            apiUrlOption
        };
        transmitCommand.SetHandler(HandleTransmitOnlyCommand, verboseOption);

        // Info command - display system and configuration information
        var infoCommand = new Command("info", "Display system and configuration information");
        infoCommand.SetHandler(HandleInfoCommand, verboseOption);

        // Install command - setup registry and configuration
        var installCommand = new Command("install", "Install and configure ReportMate client")
        {
            new Option<string>("--api-url", "API endpoint URL") { IsRequired = true },
            new Option<string>("--device-id", "Custom device identifier"),
            new Option<string>("--api-key", "API authentication key")
        };
        installCommand.SetHandler(HandleInstallCommand, verboseOption);

        // Build command - used by build script for signing operations
        var buildCommand = new Command("build", "Build and sign executable (internal use)")
        {
            new Option<bool>("--sign", "Sign the executable with code signing certificate"),
            new Option<string>("--version", "Version string for the build"),
            new Option<string>("--thumbprint", "Certificate thumbprint for signing")
        };
        buildCommand.SetHandler(HandleBuildCommand, verboseOption);

        rootCommand.AddCommand(runCommand);
        rootCommand.AddCommand(transmitCommand);
        rootCommand.AddCommand(infoCommand);
        rootCommand.AddCommand(installCommand);
        rootCommand.AddCommand(buildCommand);

        return rootCommand;
    }

    private static async Task<int> HandleRunCommand(bool force, bool collectOnly, bool transmitOnly, string? runModule, string? runModules, string? deviceId, string? apiUrl, int verbose)
    {
        try
        {
            // Set enhanced logger verbose level
            Logger.SetVerboseLevel(verbose);
            ConsoleFormatter.SetVerboseMode(verbose >= 2); // Enable for INFO level and above
            
            // Validate mutually exclusive options
            if (collectOnly && transmitOnly)
            {
                _logger?.LogError("Cannot use --collect-only and --transmit-only together");
                if (verbose > 0)
                {
                    Logger.Error("INVALID OPTIONS: --collect-only and --transmit-only are mutually exclusive");
                    Logger.Info("Use --collect-only to collect data without transmission");
                    Logger.Info("Use --transmit-only to transmit cached data without collection");
                }
                return 1;
            }
            
            if (verbose > 0)
            {
                Logger.Section("Command Execution", "Run command with enhanced verbose logging");
                
                var commandData = new Dictionary<string, object?>
                {
                    ["Command"] = "run",
                    ["Force"] = force,
                    ["Collect Only"] = collectOnly,
                    ["Transmit Only"] = transmitOnly,
                    ["Run Module"] = runModule ?? "NONE",
                    ["Run Modules"] = runModules ?? "NONE",
                    ["Effective Mode"] = !string.IsNullOrEmpty(runModule) ? $"Single Module: {runModule}" :
                                        !string.IsNullOrEmpty(runModules) ? $"Multiple Modules: {runModules}" :
                                        "ALL (full collection)",
                    ["Custom Device ID"] = deviceId ?? "NONE (will auto-detect)",
                    ["Custom API URL"] = apiUrl ?? "NONE (using config)",
                    ["Verbose Level"] = $"{verbose} ({GetVerboseLevelName(verbose)})"
                };
                
                Logger.InfoWithData("Command Parameters", commandData);
                
                if (transmitOnly)
                {
                    Logger.Info("Expected Flow: 1) Load Cached Data 2) Validate Cache 3) Transmit to API");
                }
                else
                {
                    Logger.Info("Expected Flow: 1) Detect Serial 2) Check Registration 3) Register if needed 4) {0}", 
                        collectOnly ? "Collect Data (NO TRANSMISSION)" : "Send Data");
                }
            }
            
            _logger!.LogInformation("ReportMate v{Version} - Device Registration & Data Collection", 
                System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);
            
            // Handle single module data collection if specified
            if (!string.IsNullOrEmpty(runModule))
            {
                if (verbose > 0)
                {
                    Logger.Section("Single Module Collection", $"Collecting data for module: {runModule}");
                    Logger.Info("Mode: Single module collection (modular architecture)");
                    Logger.Info("Module: {0}", runModule);
                    if (collectOnly)
                    {
                        Logger.Info("Output: JSON data will be displayed and cached locally (NO TRANSMISSION)");
                    }
                    else
                    {
                        Logger.Info("Output: JSON data will be displayed, cached locally, and transmitted to API");
                    }
                }
                
                return await HandleSingleModuleCollection(runModule, verbose, collectOnly);
            }
            
            // Handle multiple modules data collection if specified
            if (!string.IsNullOrEmpty(runModules))
            {
                var moduleList = runModules.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                          .Select(m => m.Trim())
                                          .ToArray();
                
                if (verbose > 0)
                {
                    Logger.Section("Multiple Module Collection", $"Collecting data for {moduleList.Length} modules: {string.Join(", ", moduleList)}");
                    Logger.Info("Mode: Multiple module collection (modular architecture)");
                    Logger.Info("Modules: {0}", string.Join(", ", moduleList));
                    if (collectOnly)
                    {
                        Logger.Info("Output: JSON data will be displayed and cached locally (NO TRANSMISSION)");
                    }
                    else
                    {
                        Logger.Info("Output: JSON data will be displayed, cached locally, and transmitted to API");
                    }
                }
                
                return await HandleMultipleModuleCollection(moduleList, verbose, collectOnly);
            }
            
            // Handle transmit-only mode (send cached data without collection)
            if (transmitOnly)
            {
                return await HandleTransmitOnlyCommand(verbose);
            }
            
            var dataCollectionService = _serviceProvider!.GetRequiredService<IDataCollectionService>();
            
            if (verbose > 0)
            {
                Logger.Debug("DataCollectionService retrieved successfully");
                Logger.Info("Calling CollectAndSendDataAsync - this will handle registration and {0}", 
                    collectOnly ? "data collection only" : "data transmission");
                _logger!.LogInformation("Calling CollectAndSendDataAsync - this will handle registration and {Mode}", 
                    collectOnly ? "data collection only" : "data transmission");
            }
            
            var result = await dataCollectionService.CollectAndSendDataAsync(force, collectOnly);
            
            if (result)
            {
                if (collectOnly)
                {
                    _logger!.LogInformation("Data collection completed successfully (transmission skipped)");
                    if (verbose > 0)
                    {
                        Logger.Info("CACHE: Data saved to local cache files only");
                        Logger.Info("TIP: Run without --collect-only to transmit data");
                    }
                }
                else
                {
                    _logger!.LogInformation("Data collection and transmission completed successfully");
                    if (verbose > 0)
                    {
                        Logger.Info("DASHBOARD: Check /device/{0} for new events", deviceId ?? "auto-detected");
                        Logger.Info("COMPLIANCE: Registration policy enforced successfully");
                    }
                }
                return 0;
            }
            else
            {
                _logger!.LogError("Data collection or transmission failed");
                if (verbose > 0)
                {
                    Logger.Error("IMPACT: Device may not be registered or API issues detected");
                    Logger.Error("ACTION REQUIRED: Check logs above for specific failure reasons");
                }
                return 1;
            }
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during data collection");
            return 1;
        }
    }

    private static async Task<int> HandleInfoCommand(int verbose)
    {
        try
        {
            var deviceInfoService = _serviceProvider!.GetRequiredService<IDeviceInfoService>();
            var configService = _serviceProvider!.GetRequiredService<IConfigurationService>();
            var configuration = _serviceProvider!.GetRequiredService<IConfiguration>();
            
            var deviceInfo = await deviceInfoService.GetBasicDeviceInfoAsync();
            var config = await configService.GetCurrentConfigurationAsync();
            
            Console.WriteLine("=== ReportMate Information ===");
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            var versionString = version != null ? $"{version.Major:D4}.{version.Minor:D2}.{version.Build:D2}" : "1.0.0";
            Console.WriteLine($"Version: {versionString}");
            Console.WriteLine($"");
            Console.WriteLine("=== Device Information ===");
            Console.WriteLine($"Device ID: {deviceInfo.DeviceId}");
            Console.WriteLine($"Serial Number: {deviceInfo.SerialNumber}");
            Console.WriteLine($"Computer Name: {deviceInfo.ComputerName}");
            Console.WriteLine($"Domain: {deviceInfo.Domain}");
            Console.WriteLine($"OS Version: {deviceInfo.OperatingSystem}");
            Console.WriteLine($"Manufacturer: {deviceInfo.Manufacturer}");
            Console.WriteLine($"Model: {deviceInfo.Model}");
            Console.WriteLine($"Memory: {deviceInfo.TotalMemoryGB}GB");
            Console.WriteLine($"");
            Console.WriteLine("=== Configuration ===");
            Console.WriteLine($"API URL: {config.ApiUrl}");
            Console.WriteLine($"Last Run: {config.LastRunTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");
            Console.WriteLine($"Is Configured: {config.IsConfigured}");
            
            if (verbose > 0)
            {
                Console.WriteLine($"");
                Console.WriteLine("=== Verbose Configuration Details ===");
                Console.WriteLine($"Debug Logging: {configuration["ReportMate:DebugLogging"]}");
                Console.WriteLine($"Collection Interval: {configuration["ReportMate:CollectionIntervalSeconds"]}s");
                Console.WriteLine($"API Timeout: {configuration["ReportMate:ApiTimeoutSeconds"]}s");
                Console.WriteLine($"OsQuery Path: {configuration["ReportMate:OsQueryPath"]}");
                Console.WriteLine($"Max Retry Attempts: {configuration["ReportMate:MaxRetryAttempts"]}");
                Console.WriteLine($"User Agent: {configuration["ReportMate:UserAgent"]}");
                
                // Check osquery availability
                var osqueryService = _serviceProvider!.GetRequiredService<IOsQueryService>();
                var osqueryAvailable = await osqueryService.IsOsQueryAvailableAsync();
                Console.WriteLine($"OsQuery Available: {osqueryAvailable}");
                
                if (osqueryAvailable)
                {
                    var osqueryVersion = await osqueryService.GetOsQueryVersionAsync();
                    Console.WriteLine($"OsQuery Version: {osqueryVersion}");
                }
            }
            
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error displaying information");
            return 1;
        }
    }

    private static async Task<int> HandleInstallCommand(int verbose)
    {
        try
        {
            if (verbose > 0)
            {
                Logger.Section("Install Mode", "Installing ReportMate client configuration");
            }
            
            _logger!.LogInformation("Installing ReportMate client configuration...");
            
            var configService = _serviceProvider!.GetRequiredService<IConfigurationService>();
            await configService.InstallConfigurationAsync();
            
            _logger!.LogInformation("Installation completed successfully");
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during installation");
            return 1;
        }
    }

    private static Task<int> HandleBuildCommand(int verbose)
    {
        try
        {
            if (verbose > 0)
            {
                Logger.Section("Build Command", "Internal build script operation");
                Logger.Info("This command is used internally by the build script");
            }
            
            _logger!.LogInformation("ReportMate Build Command");
            _logger!.LogInformation("This command is used internally by build.ps1 for signing operations");
            _logger!.LogInformation("Build script handles actual compilation and signing");
            _logger!.LogInformation("For manual builds, use: .\\build.ps1 -Sign");
            
            return Task.FromResult(0);
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error in build command");
            return Task.FromResult(1);
        }
    }

    /// <summary>
    /// Parse verbose level from command line arguments before full parsing
    /// Supports: -v (1), -vv (2), -vvv (3), -vvvv (4), --verbose=N
    /// </summary>
    private static int GetVerboseLevelFromArgs(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            
            // Handle --verbose=N format
            if (arg.StartsWith("--verbose="))
            {
                var levelStr = arg.Substring("--verbose=".Length);
                if (int.TryParse(levelStr, out var level))
                {
                    return Math.Max(0, Math.Min(3, level));
                }
            }
            // Handle explicit --verbose followed by number
            else if (arg == "--verbose" && i + 1 < args.Length)
            {
                if (int.TryParse(args[i + 1], out var level))
                {
                    return Math.Max(0, Math.Min(3, level));
                }
                // If next arg is not a number, treat as level 2 (info)
                return 2;
            }
            // Handle -v, -vv, -vvv, -vvvv format
            else if (arg.StartsWith("-v") && arg.All(c => c == 'v' || c == '-'))
            {
                return Math.Max(0, Math.Min(3, arg.Count(c => c == 'v')));
            }
            // Handle single --verbose flag
            else if (arg == "--verbose")
            {
                return 2; // Default to info level
            }
        }
        
        return 0; // No verbose flag found
    }

    /// <summary>
    /// Get human-readable name for verbose level
    /// </summary>
    private static string GetVerboseLevelName(int level)
    {
        return level switch
        {
            0 => "Errors Only",
            1 => "Errors + Warnings", 
            2 => "Errors + Warnings + Info",
            3 => "All Messages (Debug)",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Preprocess command line arguments to convert -v, -vv, -vvv format to --verbose=N
    /// This allows System.CommandLine to properly parse the arguments without conflicts
    /// </summary>
    private static string[] PreprocessVerboseArgs(string[] args)
    {
        var processedArgs = new List<string>();
        
        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            
            // Handle -v, -vv, -vvv, -vvvv format
            if (arg.StartsWith("-v") && arg.All(c => c == 'v' || c == '-') && arg != "--verbose")
            {
                var level = arg.Count(c => c == 'v');
                level = Math.Max(0, Math.Min(3, level)); // Clamp to 0-3
                processedArgs.Add($"--verbose={level}");
            }
            else
            {
                processedArgs.Add(arg);
            }
        }
        
        return processedArgs.ToArray();
    }
    
    /// <summary>
    /// Handle single module data collection
    /// </summary>
    private static async Task<int> HandleSingleModuleCollection(string moduleId, int verbose, bool collectOnly = false)
    {
        try
        {
            if (verbose > 0)
            {
                Logger.Info("Initializing modular data collection service...");
            }
            
            var modularService = _serviceProvider!.GetRequiredService<IModularDataCollectionService>();
            
            if (verbose > 0)
            {
                Logger.Info("Starting single module collection for: {0}", moduleId);
                if (collectOnly)
                {
                    Logger.Info("Mode: Collection only (no transmission)");
                }
                else
                {
                    Logger.Info("Mode: Collection and transmission");
                }
            }
            
            _logger!.LogInformation("Starting single module collection for: {ModuleId} (CollectOnly: {CollectOnly})", moduleId, collectOnly);
            
            // Use the efficient single module collection method
            var moduleData = await modularService.CollectSingleModuleDataAsync(moduleId);
            
            if (moduleData == null)
            {
                if (verbose > 0)
                {
                    Logger.Error("Module '{0}' not found or failed to collect data", moduleId);
                    Logger.Error("Available modules: applications, hardware, inventory, installs, management, network, printer, profiles, security, system");
                }
                _logger!.LogError("Module '{ModuleId}' not found or failed to collect data", moduleId);
                return 1;
            }

            // Create a module-specific unified payload for transmission support
            if (verbose > 0)
            {
                Logger.Info("Creating module-specific event.json for transmission support...");
            }
            
            var unifiedPayload = await modularService.CreateSingleModuleUnifiedPayloadAsync(moduleData);
            
            if (verbose > 0)
            {
                Logger.Info("✅ Module-specific event.json created successfully");
                Logger.Info("Cache Location: {0}", @"C:\ProgramData\ManagedReports\cache");
            }

            // Serialize the module data to JSON for display
            var jsonOptions = new JsonSerializerOptions(ReportMateJsonContext.Default.Options)
            {
                WriteIndented = true
            };

            var jsonData = JsonSerializer.Serialize(moduleData, moduleData.GetType(), jsonOptions);

            if (verbose > 0)
            {
                Logger.Section("Module Data", $"Collected data for module: {moduleId}");
                Logger.Info("Module: {0}", moduleData.ModuleId);
                Logger.Info("Version: {0}", moduleData.Version);
                Logger.Info("Collection Time: {0:yyyy-MM-dd HH:mm:ss} UTC", moduleData.CollectedAt);
                Logger.Info("Device ID: {0}", moduleData.DeviceId);
                
                if (verbose >= 3)
                {
                    Console.WriteLine();
                    Logger.Section("JSON Output", "Raw module data in JSON format");
                    // Output the full JSON data only for very verbose mode (-vvv)
                    Console.WriteLine(jsonData);
                }
                else
                {
                    // Show summary for normal verbose modes (-v, -vv)
                    Console.WriteLine();
                    Logger.Info("Data collected successfully. Use -vvv to see full JSON output.");
                    Logger.Info("JSON size: {0:N0} characters", jsonData.Length);
                }
            }
            else
            {
                // Silent mode - no JSON output
            }

            // Handle transmission if not in collect-only mode
            if (!collectOnly)
            {
                if (verbose > 0)
                {
                    Console.WriteLine();
                    Logger.Section("Data Transmission", "Sending module data to ReportMate API");
                    Logger.Info("Transmitting module '{0}' data to API...", moduleId);
                }

                try
                {
                    var apiService = _serviceProvider!.GetRequiredService<IApiService>();
                    var transmissionResult = await apiService.SendUnifiedPayloadAsync(unifiedPayload);

                    if (transmissionResult)
                    {
                        if (verbose > 0)
                        {
                            Logger.Info("✅ Transmission completed successfully");
                            Logger.Info("DASHBOARD: Check your ReportMate dashboard for updated {0} data", moduleId);
                            Logger.Info("DEVICE: Data for device {0} has been updated", moduleData.DeviceId);
                        }
                        _logger!.LogInformation("Single module transmission completed successfully for: {ModuleId}", moduleId);
                    }
                    else
                    {
                        if (verbose > 0)
                        {
                            Logger.Error("❌ Transmission failed");
                            Logger.Error("The module data has been collected and cached locally");
                            Logger.Info("TIP: Use --transmit-only later to retry transmission");
                            Logger.Info("TIP: Check your API configuration and network connectivity");
                        }
                        _logger!.LogError("Single module transmission failed for: {ModuleId}", moduleId);
                        return 1;
                    }
                }
                catch (Exception ex)
                {
                    if (verbose > 0)
                    {
                        Logger.Error("❌ Transmission error: {0}", ex.Message);
                        Logger.Error("The module data has been collected and cached locally");
                        Logger.Info("TIP: Use --transmit-only later to retry transmission");
                        if (verbose >= 3)
                        {
                            Logger.Debug("Transmission stack trace: {0}", ex.StackTrace ?? "No stack trace available");
                        }
                    }
                    _logger!.LogError(ex, "Error during single module transmission for: {ModuleId}", moduleId);
                    return 1;
                }
            }
            else
            {
                if (verbose > 0)
                {
                    Console.WriteLine();
                    Logger.Info("✅ Single module collection completed successfully (transmission skipped)");
                    Logger.Info("TIP: Run without --collect-only to both collect and transmit this module's data");
                    Logger.Info("TIP: Use --transmit-only to send all cached data");
                }
            }

            if (verbose > 0 && collectOnly)
            {
                Logger.Info("CACHE: Module data saved to local cache files only");
            }

            _logger!.LogInformation("Single module collection completed successfully for: {ModuleId}", moduleId);            return 0;
        }
        catch (Exception ex)
        {
            if (verbose > 0)
            {
                Logger.Error("Error during single module collection: {0}", ex.Message);
                if (verbose >= 3)
                {
                    Logger.Debug("Stack trace: {0}", ex.StackTrace ?? "No stack trace available");
                }
            }
            _logger!.LogError(ex, "Error during single module collection for: {ModuleId}", moduleId);
            return 1;
        }
    }
    
    /// <summary>
    /// Handle multiple module collection
    /// </summary>
    private static async Task<int> HandleMultipleModuleCollection(string[] moduleIds, int verbose, bool collectOnly = false)
    {
        try
        {
            if (verbose > 0)
            {
                Logger.Info("Initializing modular data collection service for multiple modules...");
            }
            
            var modularService = _serviceProvider!.GetRequiredService<IModularDataCollectionService>();
            var results = new List<BaseModuleData>();
            var errors = new List<string>();
            
            foreach (var moduleId in moduleIds)
            {
                try
                {
                    if (verbose > 0)
                    {
                        Logger.Info("Starting collection for module: {0}", moduleId);
                    }
                    
                    _logger!.LogInformation("Starting collection for module: {ModuleId}", moduleId);
                    
                    var moduleData = await modularService.CollectSingleModuleDataAsync(moduleId);
                    
                    if (moduleData == null)
                    {
                        var errorMsg = $"Module '{moduleId}' not found or failed to collect data";
                        errors.Add(errorMsg);
                        
                        if (verbose > 0)
                        {
                            Logger.Error("❌ {0}", errorMsg);
                        }
                        _logger!.LogError("Module '{ModuleId}' not found or failed to collect data", moduleId);
                        continue;
                    }
                    
                    results.Add(moduleData);
                    
                    if (verbose > 0)
                    {
                        Logger.Info("✅ Successfully collected data for module: {0}", moduleId);
                    }
                }
                catch (Exception ex)
                {
                    var errorMsg = $"Error collecting data for module '{moduleId}': {ex.Message}";
                    errors.Add(errorMsg);
                    
                    if (verbose > 0)
                    {
                        Logger.Error("❌ {0}", errorMsg);
                        if (verbose >= 3)
                        {
                            Logger.Debug("Stack trace: {0}", ex.StackTrace ?? "No stack trace available");
                        }
                    }
                    _logger!.LogError(ex, "Error collecting data for module: {ModuleId}", moduleId);
                }
            }
            
            if (results.Count == 0)
            {
                if (verbose > 0)
                {
                    Logger.Error("❌ No modules collected successfully");
                    Logger.Error("Available modules: applications, hardware, inventory, installs, management, network, printer, profiles, security, system");
                }
                return 1;
            }
            
            // Create unified payloads for successful modules
            var unifiedPayloads = new List<UnifiedDevicePayload>();
            foreach (var moduleData in results)
            {
                var unifiedPayload = await modularService.CreateSingleModuleUnifiedPayloadAsync(moduleData);
                unifiedPayloads.Add(unifiedPayload);
            }
            
            if (verbose > 0)
            {
                Logger.Section("Multiple Module Collection Summary", $"Collected {results.Count} of {moduleIds.Length} modules");
                Logger.Info("Successful modules: {0}", string.Join(", ", results.Select(r => r.ModuleId)));
                if (errors.Any())
                {
                    Logger.Warning("Failed modules: {0}", errors.Count);
                }
                
                Console.WriteLine();
                Logger.Section("JSON Output", "Module data in JSON format");
            }
            
            // Output JSON for each successful module (only in very verbose mode)
            if (verbose >= 3)
            {
                var jsonOptions = new JsonSerializerOptions(ReportMateJsonContext.Default.Options)
                {
                    WriteIndented = true
                };
                
                foreach (var moduleData in results)
                {
                    var jsonData = JsonSerializer.Serialize(moduleData, moduleData.GetType(), jsonOptions);
                    Console.WriteLine($"// Module: {moduleData.ModuleId}");
                    Console.WriteLine(jsonData);
                    Console.WriteLine();
                }
            }
            else if (verbose > 0)
            {
                // Show summary for normal verbose modes
                Logger.Section("Collection Summary", $"Successfully collected data from {results.Count} module(s)");
                foreach (var moduleData in results)
                {
                    var jsonOptions = new JsonSerializerOptions(ReportMateJsonContext.Default.Options)
                    {
                        WriteIndented = true
                    };
                    var jsonData = JsonSerializer.Serialize(moduleData, moduleData.GetType(), jsonOptions);
                    Logger.Info("Module: {0}, Size: {1:N0} chars", moduleData.ModuleId, jsonData.Length);
                }
                Logger.Info("Use -vvv to see full JSON output");
            }
            
            // Handle transmission if not in collect-only mode
            if (!collectOnly)
            {
                if (verbose > 0)
                {
                    Console.WriteLine();
                    Logger.Section("Data Transmission", $"Sending {results.Count} module data to ReportMate API");
                }
                
                var apiService = _serviceProvider!.GetRequiredService<IApiService>();
                int successCount = 0;
                
                for (int i = 0; i < unifiedPayloads.Count; i++)
                {
                    var payload = unifiedPayloads[i];
                    var moduleId = results[i].ModuleId;
                    
                    try
                    {
                        var transmissionResult = await apiService.SendUnifiedPayloadAsync(payload);
                        
                        if (transmissionResult)
                        {
                            successCount++;
                            if (verbose > 0)
                            {
                                Logger.Info("✅ Successfully transmitted data for module: {0}", moduleId);
                            }
                        }
                        else
                        {
                            if (verbose > 0)
                            {
                                Logger.Error("❌ Failed to transmit data for module: {0}", moduleId);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (verbose > 0)
                        {
                            Logger.Error("❌ Transmission error for module {0}: {1}", moduleId, ex.Message);
                        }
                        _logger!.LogError(ex, "Error during transmission for module: {ModuleId}", moduleId);
                    }
                }
                
                if (verbose > 0)
                {
                    if (successCount == unifiedPayloads.Count)
                    {
                        Logger.Info("✅ All transmissions completed successfully ({0}/{1})", successCount, unifiedPayloads.Count);
                        Logger.Info("DASHBOARD: Check your ReportMate dashboard for updated module data");
                    }
                    else
                    {
                        Logger.Warning("⚠️  Partial success: {0}/{1} transmissions completed", successCount, unifiedPayloads.Count);
                        Logger.Info("TIP: Use --transmit-only later to retry failed transmissions");
                    }
                }
                
                return successCount == unifiedPayloads.Count ? 0 : 1;
            }
            else
            {
                if (verbose > 0)
                {
                    Console.WriteLine();
                    Logger.Info("✅ Multiple module collection completed successfully (transmission skipped)");
                    Logger.Info("TIP: Run without --collect-only to both collect and transmit module data");
                    Logger.Info("TIP: Use --transmit-only to send all cached data");
                }
            }
            
            _logger!.LogInformation("Multiple module collection completed successfully for: {Modules}", 
                string.Join(", ", results.Select(r => r.ModuleId)));
            return 0;
        }
        catch (Exception ex)
        {
            if (verbose > 0)
            {
                Logger.Error("Error during multiple module collection: {0}", ex.Message);
                if (verbose >= 3)
                {
                    Logger.Debug("Stack trace: {0}", ex.StackTrace ?? "No stack trace available");
                }
            }
            _logger!.LogError(ex, "Error during multiple module collection for modules: {Modules}", 
                string.Join(", ", moduleIds));
            return 1;
        }
    }
    
    /// <summary>
    /// Handle transmit-only command - sends cached data without collecting new data
    /// </summary>
    private static async Task<int> HandleTransmitOnlyCommand(int verbose)
    {
        try
        {
            if (verbose > 0)
            {
                Logger.Section("Transmit Only Mode", "Sending cached raw module data without collection");
                Logger.Info("Mode: Transmission only (no data collection)");
                Logger.Info("Source: Raw osquery module data from previous collection");
                Logger.Info("Action: Load raw cache files, validate, and transmit to API");
            }
            
            _logger!.LogInformation("ReportMate v{Version} - Transmit Only Mode", 
                System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);
            
            // Find the most recent cache directory
            var baseCacheDir = @"C:\ProgramData\ManagedReports\cache";
            if (!Directory.Exists(baseCacheDir))
            {
                _logger!.LogError("Cache directory not found: {CacheDir}", baseCacheDir);
                if (verbose > 0)
                {
                    Logger.Error("CACHE MISS: Cache directory not found");
                    Logger.Info("ACTION REQUIRED: Run data collection first");
                }
                return 1;
            }

            var cacheDirs = Directory.GetDirectories(baseCacheDir)
                .Where(d => Path.GetFileName(d).Length == 17) // YYYY-MM-DD-HHmmss format
                .OrderByDescending(d => Path.GetFileName(d))
                .ToList();

            if (!cacheDirs.Any())
            {
                _logger!.LogError("No timestamped cache directories found in: {CacheDir}", baseCacheDir);
                if (verbose > 0)
                {
                    Logger.Error("CACHE MISS: No valid cache directories found");
                    Logger.Info("ACTION REQUIRED: Run data collection first");
                }
                return 1;
            }

            var latestCacheDir = cacheDirs.First();
            if (verbose > 0)
            {
                Logger.Info("Using latest cache directory: {0}", Path.GetFileName(latestCacheDir));
            }

            // Load unified payload to get device info
            var unifiedPayloadPath = Path.Combine(latestCacheDir, "event.json");
            if (!File.Exists(unifiedPayloadPath))
            {
                _logger!.LogError("Unified payload not found: {FilePath}", unifiedPayloadPath);
                return 1;
            }

            var unifiedPayloadJson = await File.ReadAllTextAsync(unifiedPayloadPath);
            var unifiedPayload = JsonSerializer.Deserialize<UnifiedDevicePayload>(unifiedPayloadJson, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                TypeInfoResolver = ReportMateJsonContext.Default
            });

            if (unifiedPayload == null)
            {
                _logger!.LogError("Failed to deserialize unified payload");
                return 1;
            }

            if (verbose > 0)
            {
                Logger.Info("Device ID: {0}", unifiedPayload.Metadata.DeviceId);
                Logger.Info("Collection Time: {0:yyyy-MM-dd HH:mm:ss} UTC", unifiedPayload.Metadata.CollectedAt);
            }

            // UNIFIED JSON TRANSMISSION
            // Load and transmit the complete event.json file
            var eventJsonPath = Path.Combine(latestCacheDir, "event.json");
            
            if (!File.Exists(eventJsonPath))
            {
                _logger!.LogError("Event JSON file not found: {EventJsonPath}", eventJsonPath);
                if (verbose > 0)
                {
                    Logger.Error("CACHE MISS: event.json not found");
                    Logger.Info("ACTION REQUIRED: Run data collection first to generate event.json");
                }
                return 1;
            }

            if (verbose > 0)
            {
                Logger.Info("UNIFIED TRANSMISSION: Processing complete event.json...");
                Logger.Info("All module data will be transmitted as a single unified payload");
            }

            // Get API service
            var apiService = _serviceProvider!.GetRequiredService<IApiService>();
            
            // Test API connectivity first
            if (verbose > 0)
            {
                Logger.Info("Testing API connectivity...");
            }
            
            var apiConnected = await apiService.TestConnectivityAsync();
            if (!apiConnected)
            {
                _logger!.LogError("API connectivity test failed");
                if (verbose > 0)
                {
                    Logger.Error("API UNREACHABLE: Cannot connect to ReportMate API");
                    Logger.Info("ACTION REQUIRED: Check network connectivity and API configuration");
                }
                return 1;
            }

            if (verbose > 0)
            {
                Logger.Info("API connectivity confirmed");
                Logger.Info("Starting unified payload transmission...");
            }

            // UNIFIED PAYLOAD TRANSMISSION - Send event.json as-is
            if (verbose > 0)
            {
                Logger.Info("Transmitting unified payload from event.json...");
            }

            var transmissionResult = await apiService.SendUnifiedPayloadAsync(unifiedPayload);
            
            if (transmissionResult)
            {
                if (verbose > 0)
                {
                    Logger.Info("✅ Unified payload transmitted successfully");
                    Logger.Info("Device should be visible in dashboard at /device/{0}", unifiedPayload.Inventory?.SerialNumber ?? unifiedPayload.Metadata.SerialNumber ?? unifiedPayload.Metadata.DeviceId);
                }
                return 0;
            }
            else
            {
                if (verbose > 0)
                {
                    Logger.Error("❌ Unified payload transmission failed");
                    Logger.Info("Check logs for detailed error information");
                }
                return 1;
            }
        }
        catch (Exception ex)
        {
            if (verbose > 0)
            {
                Logger.Error("Error during transmit-only operation: {0}", ex.Message);
                if (verbose >= 3)
                {
                    Logger.Debug("Stack trace: {0}", ex.StackTrace ?? "No stack trace available");
                }
            }
            _logger!.LogError(ex, "Error during transmit-only operation");
            return 1;
        }
    }
}
