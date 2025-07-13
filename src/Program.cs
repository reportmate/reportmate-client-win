#nullable enable
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Services;
using ReportMate.WindowsClient.Configuration;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using NetEscapades.Configuration.Yaml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            Logger.Debug("HKLM\\SOFTWARE\\Policies\\ReportMate (CSP/Group Policy)");
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
            using (var policyKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\ReportMate"))
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
        
        // Add global options to root command
        rootCommand.AddGlobalOption(verboseOption);
        rootCommand.AddOption(forceOption);
        rootCommand.AddOption(collectOnlyOption);
        rootCommand.AddOption(deviceIdOption);
        rootCommand.AddOption(apiUrlOption);

        // Set default handler for root command (when no subcommand is specified)
        // This makes running the binary without any command default to data collection
        rootCommand.SetHandler(HandleRunCommand, forceOption, collectOnlyOption, deviceIdOption, apiUrlOption, verboseOption);

        // Run command - explicit run data collection (optional, since it's the default)
        var runCommand = new Command("run", "Run data collection and send to API (same as default behavior)")
        {
            forceOption,
            collectOnlyOption,
            deviceIdOption,
            apiUrlOption
        };
        runCommand.SetHandler(HandleRunCommand, forceOption, collectOnlyOption, deviceIdOption, apiUrlOption, verboseOption);

        // Test command - validate configuration and connectivity
        var testCommand = new Command("test", "Test configuration and API connectivity");
        testCommand.SetHandler(HandleTestCommand, verboseOption);

        // Modular test command - test the new modular data collection system
        var modularTestCommand = new Command("test-modular", "Test modular data collection system");
        modularTestCommand.SetHandler(HandleModularTestCommand, verboseOption);

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
        rootCommand.AddCommand(testCommand);
        rootCommand.AddCommand(modularTestCommand);
        rootCommand.AddCommand(infoCommand);
        rootCommand.AddCommand(installCommand);
        rootCommand.AddCommand(buildCommand);

        return rootCommand;
    }

    private static async Task<int> HandleRunCommand(bool force, bool collectOnly, string? deviceId, string? apiUrl, int verbose)
    {
        try
        {
            // Set enhanced logger verbose level
            Logger.SetVerboseLevel(verbose);
            
            if (verbose > 0)
            {
                Logger.Section("Command Execution", "Run command with enhanced verbose logging");
                
                var commandData = new Dictionary<string, object?>
                {
                    ["Command"] = "run",
                    ["Force"] = force,
                    ["Collect Only"] = collectOnly,
                    ["Custom Device ID"] = deviceId ?? "NONE (will auto-detect)",
                    ["Custom API URL"] = apiUrl ?? "NONE (using config)",
                    ["Verbose Level"] = $"{verbose} ({GetVerboseLevelName(verbose)})"
                };
                
                Logger.InfoWithData("Command Parameters", commandData);
                Logger.Info("Expected Flow: 1) Detect Serial 2) Check Registration 3) Register if needed 4) {0}", 
                    collectOnly ? "Collect Data (NO TRANSMISSION)" : "Send Data");
            }
            
            _logger!.LogInformation("ReportMate v{Version} - Device Registration & Data Collection", 
                System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);
            
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

    private static async Task<int> HandleTestCommand(int verbose)
    {
        try
        {
            // Set enhanced logger verbose level
            Logger.SetVerboseLevel(verbose);
            
            if (verbose > 0)
            {
                Logger.Section("Test Mode", "Comprehensive ReportMate test with enhanced logging");
            }
            
            _logger!.LogInformation("=== REPORTMATE COMPREHENSIVE TEST STARTING ===");
            _logger!.LogInformation("Running configuration and connectivity tests");
            
            var configService = _serviceProvider!.GetRequiredService<IConfigurationService>();
            var apiService = _serviceProvider!.GetRequiredService<IApiService>();
            var deviceInfoService = _serviceProvider!.GetRequiredService<IDeviceInfoService>();
            
            // Step 1: Test device information collection
            Logger.Info("=== STEP 1: DEVICE INFORMATION COLLECTION ===");
            DeviceInfo deviceInfo;
            try
            {
                deviceInfo = await deviceInfoService.GetBasicDeviceInfoAsync();
                Logger.Info("Device information collected successfully");
                
                var deviceData = new Dictionary<string, object?>
                {
                    ["Device ID"] = deviceInfo.DeviceId,
                    ["Serial Number"] = deviceInfo.SerialNumber,
                    ["Computer Name"] = deviceInfo.ComputerName,
                    ["Operating System"] = deviceInfo.OperatingSystem,
                    ["Manufacturer"] = deviceInfo.Manufacturer,
                    ["Model"] = deviceInfo.Model,
                    ["Client Version"] = deviceInfo.ClientVersion
                };
                
                if (verbose >= 2)
                {
                    deviceData["Domain"] = deviceInfo.Domain;
                    deviceData["Total Memory"] = $"{deviceInfo.TotalMemoryGB}GB";
                    deviceData["Last Seen"] = deviceInfo.LastSeen;
                }
                
                Logger.InfoWithData("Device Information", deviceData);
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to collect device information: {0}", ex.Message);
                return 1;
            }
            
            // Step 2: Test configuration
            Logger.Info("=== STEP 2: CONFIGURATION VALIDATION ===");
            var config = await configService.ValidateConfigurationAsync();
            if (!config.IsValid)
            {
                Logger.Error("Configuration validation failed: {0}", 
                    string.Join(", ", config.Errors));
                return 1;
            }
            Logger.Info("Configuration validation passed");
            
            if (verbose > 0 && config.Warnings.Count > 0)
            {
                Logger.Warning("Configuration warnings: {0}", 
                    string.Join(", ", config.Warnings));
            }
            
            // Step 3: Test API connectivity
            _logger!.LogInformation("=== STEP 3: API CONNECTIVITY TEST ===");
            var apiConnectivity = await apiService.TestConnectivityAsync();
            if (!apiConnectivity)
            {
                _logger!.LogError("API connectivity test failed");
                return 1;
            }
            _logger!.LogInformation("API connectivity test passed");
            
            // Step 4: Test device registration check
            _logger!.LogInformation("=== STEP 4: DEVICE REGISTRATION CHECK ===");
            var isRegistered = await apiService.IsDeviceRegisteredAsync(deviceInfo.DeviceId);
            if (isRegistered)
            {
                _logger!.LogInformation("Device {DeviceId} is already registered", deviceInfo.DeviceId);
            }
            else
            {
                _logger!.LogWarning(" Device {DeviceId} is not registered", deviceInfo.DeviceId);
                _logger!.LogInformation("   This device will be auto-registered on first data collection run");
            }
            
            // Step 5: Test comprehensive data collection (but don't send)
            _logger!.LogInformation("=== STEP 5: DATA COLLECTION TEST ===");
            try
            {
                var dataCollectionService = _serviceProvider!.GetRequiredService<IDataCollectionService>();
                var deviceData = await dataCollectionService.CollectDataAsync();
                
                _logger!.LogInformation("Comprehensive data collection successful");
                _logger!.LogInformation("   Device data request created:");
                _logger!.LogInformation("     - Device: {Device}", deviceData.Device);
                _logger!.LogInformation("     - SerialNumber: {SerialNumber}", deviceData.SerialNumber);
                _logger!.LogInformation("     - Kind: {Kind}", deviceData.Kind);
                _logger!.LogInformation("     - Timestamp: {Timestamp}", deviceData.Ts);
                
                if (deviceData.Payload != null)
                {
                    _logger!.LogInformation("   Payload sections:");
                    if (deviceData.Payload.Device != null) _logger!.LogInformation("     - Device: Dictionary with {Count} items", deviceData.Payload.Device.Count);
                    if (deviceData.Payload.System != null) _logger!.LogInformation("     - System: Dictionary with {Count} items", deviceData.Payload.System.Count);
                    if (deviceData.Payload.Security != null) _logger!.LogInformation("     - Security: Dictionary with {Count} items", deviceData.Payload.Security.Count);
                    if (deviceData.Payload.OsQuery != null) _logger!.LogInformation("     - OsQuery: Dictionary with {Count} items", deviceData.Payload.OsQuery.Count);
                }
            }
            catch (Exception ex)
            {
                _logger!.LogError(ex, "Data collection test failed");
                return 1;
            }
            
            _logger!.LogInformation("=== ALL TESTS PASSED SUCCESSFULLY ===");
            _logger!.LogInformation(" ReportMate client is ready for data collection and reporting");
            _logger!.LogInformation(" Run 'runner.exe run' to perform actual data collection and transmission");
            
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during testing");
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
            Console.WriteLine($"Version: {System.Reflection.Assembly.GetExecutingAssembly().GetName().Version}");
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

    private static async Task<int> HandleModularTestCommand(int verbose)
    {
        try
        {
            if (verbose > 0)
            {
                Logger.Section("Modular Test", "Testing modular data collection system");
            }

            _logger!.LogInformation("🧪 Testing Modular Data Collection System");
            _logger!.LogInformation("===============================================");

            var modularService = _serviceProvider!.GetRequiredService<IModularDataCollectionService>();
            
            _logger!.LogInformation("Starting modular data collection test...");
            
            var payload = await modularService.CollectAllModuleDataAsync();
            
            _logger!.LogInformation($"Modular data collection completed!");
            _logger!.LogInformation($"Device ID: {payload.DeviceId}");
            _logger!.LogInformation($" Collection Time: {payload.CollectedAt:yyyy-MM-dd HH:mm:ss}");
            _logger!.LogInformation($"Platform: {payload.Platform}");
            _logger!.LogInformation($" Client Version: {payload.ClientVersion}");
            
            // Show module data summary
            var moduleCount = 0;
            if (payload.Applications != null) { moduleCount++; _logger!.LogInformation($"  Applications: {payload.Applications.TotalApplications} apps"); }
            if (payload.Hardware != null) { moduleCount++; _logger!.LogInformation($"  Hardware: {payload.Hardware.Processor.Name}"); }
            if (payload.Inventory != null) { moduleCount++; _logger!.LogInformation($"  Inventory: {payload.Inventory.DeviceName}"); }
            if (payload.Installs != null) { moduleCount++; _logger!.LogInformation($"  Installs: Module data collected"); }
            if (payload.Management != null) { moduleCount++; _logger!.LogInformation($"  Management: Module data collected"); }
            if (payload.Network != null) { moduleCount++; _logger!.LogInformation($"  Network: {payload.Network.Interfaces.Count} interfaces"); }
            if (payload.Profiles != null) { moduleCount++; _logger!.LogInformation($"  Profiles: Module data collected"); }
            if (payload.Security != null) { moduleCount++; _logger!.LogInformation($"  Security: Module data collected"); }
            if (payload.System != null) { moduleCount++; _logger!.LogInformation($"  System: {payload.System.OperatingSystem.Name}"); }
            
            _logger!.LogInformation($"Total modules processed: {moduleCount}/9");
            
            // Test loading cached data
            _logger!.LogInformation("Testing cached data loading...");
            var cachedPayload = await modularService.LoadCachedDataAsync();
            if (cachedPayload.DeviceId == payload.DeviceId)
            {
                _logger!.LogInformation("Cached data loaded successfully");
            }
            else
            {
                _logger!.LogWarning("Cached data mismatch or not found");
            }
            
            _logger!.LogInformation("===============================================");
            _logger!.LogInformation(" Modular test completed successfully!");
            
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during modular test");
            return 1;
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
}
