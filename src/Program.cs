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
/// Designed to run as a postflight script after Cimian managed software updates
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
            var isVerbose = args.Contains("--verbose") || args.Contains("-v");
            
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
            
            // Force console output for testing
            if (isVerbose)
            {
                Console.WriteLine("=== REPORTMATE RUNNER STARTING ===");
                Console.WriteLine($"Arguments: {string.Join(" ", args)}");
                Console.WriteLine($"Verbose mode: {isVerbose}");
                Console.WriteLine("=====================================");
                Console.WriteLine("*** RUNNER STARTING - VERBOSE MODE ENABLED ***");
            }
            
            // Build configuration from multiple sources
            var configuration = BuildConfiguration(isVerbose);
            
            if (isVerbose)
            {
                Console.WriteLine("*** CONFIGURATION BUILT ***");
            }
            
            // Setup dependency injection with verbose flag
            _serviceProvider = ConfigureServices(configuration, isVerbose);
            _logger = _serviceProvider.GetRequiredService<ILogger<Program>>();

            _logger.LogError("*** SUPER EARLY DEBUG LOG - RUNNER IS STARTING v2025.7.1.1 ***");
            _logger.LogInformation("ReportMate v{Version} starting", 
                System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);

            // Log command line args
            _logger.LogInformation("Command line args: {Args}", string.Join(" ", args));

            // Create and configure command line interface
            var rootCommand = ConfigureCommandLine();
            
            // Parse and execute commands
            var commandLineBuilder = new CommandLineBuilder(rootCommand)
                .UseDefaults()
                .UseExceptionHandler((exception, context) =>
                {
                    _logger?.LogError(exception, "Unhandled exception occurred");
                    context.ExitCode = 1;
                });

            var parser = commandLineBuilder.Build();
            return await parser.InvokeAsync(args);
        }
        catch (Exception ex)
        {
            // Handle console output for errors in verbose mode
            var isVerbose = args.Contains("--verbose") || args.Contains("-v");
            
            if (isVerbose)
            {
                Console.WriteLine($"FATAL ERROR: {ex.Message}");
                Console.WriteLine($"Stack Trace: {ex.StackTrace}");
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
            var isVerbose = args.Contains("--verbose") || args.Contains("-v");
            if (isVerbose && GetConsoleWindow() != IntPtr.Zero)
            {
                // Give a moment for output to flush
                await Task.Delay(100);
                
                // Don't free console if we attached to parent - let parent handle it
                // Only free if we allocated our own console
            }
        }
    }

    private static IConfiguration BuildConfiguration(bool verbose = false)
    {
        var builder = new ConfigurationBuilder();
        
        // Configuration hierarchy (lowest to highest precedence):
        if (verbose)
        {
            Console.WriteLine("=== CONFIGURATION DECISION TREE ===");
            Console.WriteLine("1. Application defaults: Embedded in binary (no JSON dependency)");
        }
        
        // 2. YAML configuration from ProgramData (runtime/user editable)
        var programDataPath = ConfigurationService.GetWorkingDataDirectory();
        if (verbose)
        {
            Console.WriteLine($"2. YAML configuration from: {programDataPath}");
        }
        if (Directory.Exists(programDataPath))
        {
            builder.SetBasePath(programDataPath)
                   .AddYamlFile("appsettings.yaml", optional: true, reloadOnChange: false);
        }
        
        // 3. Environment variables (prefix: REPORTMATE_)
        if (verbose)
        {
            Console.WriteLine("3. Environment variables with REPORTMATE_ prefix");
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
                if (verbose)
                {
                    Console.WriteLine($"Using API URL from environment: {envApiUrl}");
                }
                builder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ReportMate:ApiUrl"] = envApiUrl
                });
            }
        }
        
        // 5. Windows Registry (highest precedence - CSP/Group Policy)
        if (verbose)
        {
            Console.WriteLine("4. Windows Registry (HIGHEST PRECEDENCE)");
            Console.WriteLine("   - HKLM\\SOFTWARE\\ReportMate (standard)");
            Console.WriteLine("   - HKLM\\SOFTWARE\\Policies\\ReportMate (CSP/Group Policy)");
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
                            if (verbose)
                            {
                                Console.WriteLine($"   Registry: {valueName} -> {configKey}");
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
                            if (verbose)
                            {
                                Console.WriteLine($"   Policy: {valueName} -> {configKey}");
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
            if (verbose)
            {
                Console.WriteLine($"   Warning: Could not read registry: {ex.Message}");
            }
        }

        var config = builder.Build();
        
        // Log the final configuration source for key settings only in verbose mode
        if (verbose)
        {
            Console.WriteLine("\n=== FINAL CONFIGURATION SOURCE ===");
            var finalApiUrl = config["ReportMate:ApiUrl"];
            var deviceId = config["ReportMate:DeviceId"];
            var debugLogging = config["ReportMate:DebugLogging"];
            
            Console.WriteLine($"ApiUrl: {finalApiUrl ?? "NOT SET"}");
            Console.WriteLine($"DeviceId: {deviceId ?? "NOT SET"}");
            Console.WriteLine($"DebugLogging: {debugLogging ?? "NOT SET"}");
            Console.WriteLine("=====================================\n");
        }
        
        return config;
    }

    private static ServiceProvider ConfigureServices(IConfiguration configuration, bool verbose = false)
    {
        var services = new ServiceCollection();

        // Configure Serilog first
        var logDirectory = configuration["ReportMate:LogDirectory"] ?? @"C:\ProgramData\ManagedReports\logs";
        Directory.CreateDirectory(logDirectory);
        
        var loggerConfig = new LoggerConfiguration()
            .MinimumLevel.Information();

        // Enable debug logging if verbose mode is enabled
        if (verbose || configuration.GetValue<bool>("ReportMate:DebugLogging"))
        {
            loggerConfig.MinimumLevel.Debug();
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
        if (!configuration.GetValue<bool>("Development:Enabled"))
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
        if (configuration.GetValue<bool>("Development:Enabled") || verbose)
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
        services.Configure<ReportMateClientConfiguration>(
            configuration.GetSection("ReportMate"));

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
        services.AddScoped<IApiService, ApiService>();
        services.AddScoped<IOsQueryService, OsQueryService>();
        services.AddScoped<IDataCollectionService, DataCollectionService>();
        services.AddScoped<IDeviceInfoService, DeviceInfoService>();
        services.AddScoped<IConfigurationService, ConfigurationService>();

        return services.BuildServiceProvider();
    }

    private static RootCommand ConfigureCommandLine()
    {
        var rootCommand = new RootCommand("ReportMate - Device data collection and reporting");

        // Global options - these are used across all commands
        var verboseOption = new Option<bool>(new[] { "--verbose", "-v" }, "Enable verbose output and detailed logging");
        var deviceIdOption = new Option<string>("--device-id", "Override device ID");
        var apiUrlOption = new Option<string>("--api-url", "Override API URL");
        var forceOption = new Option<bool>("--force", "Force data collection even if recent run detected");
        
        // Add global options to root command
        rootCommand.AddGlobalOption(verboseOption);
        rootCommand.AddOption(forceOption);
        rootCommand.AddOption(deviceIdOption);
        rootCommand.AddOption(apiUrlOption);

        // Set default handler for root command (when no subcommand is specified)
        // This makes running the binary without any command default to data collection
        rootCommand.SetHandler(HandleRunCommand, forceOption, deviceIdOption, apiUrlOption, verboseOption);

        // Run command - explicit run data collection (optional, since it's the default)
        var runCommand = new Command("run", "Run data collection and send to API (same as default behavior)")
        {
            forceOption,
            deviceIdOption,
            apiUrlOption
        };
        runCommand.SetHandler(HandleRunCommand, forceOption, deviceIdOption, apiUrlOption, verboseOption);

        // Test command - validate configuration and connectivity
        var testCommand = new Command("test", "Test configuration and API connectivity");
        testCommand.SetHandler(HandleTestCommand, verboseOption);

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
        rootCommand.AddCommand(infoCommand);
        rootCommand.AddCommand(installCommand);
        rootCommand.AddCommand(buildCommand);

        return rootCommand;
    }

    private static async Task<int> HandleRunCommand(bool force, string? deviceId, string? apiUrl, bool verbose)
    {
        try
        {
            if (verbose)
            {
                _logger!.LogInformation("=== VERBOSE MODE ENABLED ===");
                _logger!.LogInformation("All detailed logging will be displayed");
                _logger!.LogInformation("=== RUNNER COMMAND EXECUTION ===");
                _logger!.LogInformation("Command: run");
                _logger!.LogInformation("Parameters:");
                _logger!.LogInformation("  Force: {Force}", force);
                _logger!.LogInformation("  Custom Device ID: {DeviceId}", deviceId ?? "NONE (will auto-detect)");
                _logger!.LogInformation("  Custom API URL: {ApiUrl}", apiUrl ?? "NONE (using config)");
                _logger!.LogInformation("  Verbose: {Verbose}", verbose);
                _logger!.LogInformation("Expected Flow: 1) Detect Serial 2) Check Registration 3) Register if needed 4) Send Data");
            }
            
            _logger!.LogInformation("ReportMate v{Version} - Device Registration & Data Collection", 
                System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);
            
            var dataCollectionService = _serviceProvider!.GetRequiredService<IDataCollectionService>();
            
            if (verbose)
            {
                _logger!.LogInformation("✅ DataCollectionService retrieved successfully");
                _logger!.LogInformation("🚀 Calling CollectAndSendDataAsync - this will handle registration and data transmission");
            }
            
            var result = await dataCollectionService.CollectAndSendDataAsync(force);
            
            if (result)
            {
                _logger!.LogInformation("✅ Data collection and transmission completed successfully");
                if (verbose)
                {
                    _logger!.LogInformation("✅ DASHBOARD: Check /device/{DeviceId} for new events", deviceId ?? "auto-detected");
                    _logger!.LogInformation("✅ COMPLIANCE: Registration policy enforced successfully");
                }
                return 0;
            }
            else
            {
                _logger!.LogError("❌ Data collection or transmission failed");
                if (verbose)
                {
                    _logger!.LogError("❌ IMPACT: Device may not be registered or API issues detected");
                    _logger!.LogError("❌ ACTION REQUIRED: Check logs above for specific failure reasons");
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

    private static async Task<int> HandleTestCommand(bool verbose)
    {
        try
        {
            if (verbose)
            {
                _logger!.LogInformation("=== VERBOSE TEST MODE ENABLED ===");
            }
            
            _logger!.LogInformation("=== REPORTMATE COMPREHENSIVE TEST STARTING ===");
            _logger!.LogInformation("Running configuration and connectivity tests");
            
            var configService = _serviceProvider!.GetRequiredService<IConfigurationService>();
            var apiService = _serviceProvider!.GetRequiredService<IApiService>();
            var deviceInfoService = _serviceProvider!.GetRequiredService<IDeviceInfoService>();
            
            // Step 1: Test device information collection
            _logger!.LogInformation("=== STEP 1: DEVICE INFORMATION COLLECTION ===");
            DeviceInfo deviceInfo;
            try
            {
                deviceInfo = await deviceInfoService.GetBasicDeviceInfoAsync();
                _logger!.LogInformation("✅ Device information collected successfully");
                _logger!.LogInformation("   Device ID: {DeviceId}", deviceInfo.DeviceId);
                _logger!.LogInformation("   Serial Number: {SerialNumber}", deviceInfo.SerialNumber);
                _logger!.LogInformation("   Computer Name: {ComputerName}", deviceInfo.ComputerName);
                _logger!.LogInformation("   Operating System: {OperatingSystem}", deviceInfo.OperatingSystem);
                _logger!.LogInformation("   Manufacturer: {Manufacturer}", deviceInfo.Manufacturer);
                _logger!.LogInformation("   Model: {Model}", deviceInfo.Model);
                _logger!.LogInformation("   Client Version: {ClientVersion}", deviceInfo.ClientVersion);
                
                if (verbose)
                {
                    _logger!.LogInformation("   Domain: {Domain}", deviceInfo.Domain);
                    _logger!.LogInformation("   Total Memory: {TotalMemoryGB}GB", deviceInfo.TotalMemoryGB);
                    _logger!.LogInformation("   Last Seen: {LastSeen}", deviceInfo.LastSeen);
                }
            }
            catch (Exception ex)
            {
                _logger!.LogError(ex, "❌ Failed to collect device information");
                return 1;
            }
            
            // Step 2: Test configuration
            _logger!.LogInformation("=== STEP 2: CONFIGURATION VALIDATION ===");
            var config = await configService.ValidateConfigurationAsync();
            if (!config.IsValid)
            {
                _logger!.LogError("❌ Configuration validation failed: {Errors}", 
                    string.Join(", ", config.Errors));
                return 1;
            }
            _logger!.LogInformation("✅ Configuration validation passed");
            
            if (verbose && config.Warnings.Count > 0)
            {
                _logger!.LogWarning("⚠️ Configuration warnings: {Warnings}", 
                    string.Join(", ", config.Warnings));
            }
            
            // Step 3: Test API connectivity
            _logger!.LogInformation("=== STEP 3: API CONNECTIVITY TEST ===");
            var apiConnectivity = await apiService.TestConnectivityAsync();
            if (!apiConnectivity)
            {
                _logger!.LogError("❌ API connectivity test failed");
                return 1;
            }
            _logger!.LogInformation("✅ API connectivity test passed");
            
            // Step 4: Test device registration check
            _logger!.LogInformation("=== STEP 4: DEVICE REGISTRATION CHECK ===");
            var isRegistered = await apiService.IsDeviceRegisteredAsync(deviceInfo.DeviceId);
            if (isRegistered)
            {
                _logger!.LogInformation("✅ Device {DeviceId} is already registered", deviceInfo.DeviceId);
            }
            else
            {
                _logger!.LogWarning("⚠️  Device {DeviceId} is not registered", deviceInfo.DeviceId);
                _logger!.LogInformation("   This device will be auto-registered on first data collection run");
            }
            
            // Step 5: Test comprehensive data collection (but don't send)
            _logger!.LogInformation("=== STEP 5: DATA COLLECTION TEST ===");
            try
            {
                var dataCollectionService = _serviceProvider!.GetRequiredService<IDataCollectionService>();
                var deviceData = await dataCollectionService.CollectDataAsync();
                
                _logger!.LogInformation("✅ Comprehensive data collection successful");
                _logger!.LogInformation("   Collected data sections:");
                
                foreach (var kvp in deviceData)
                {
                    _logger!.LogInformation("     - {Section}: {Type}", kvp.Key, kvp.Value?.GetType().Name ?? "null");
                }
            }
            catch (Exception ex)
            {
                _logger!.LogError(ex, "❌ Data collection test failed");
                return 1;
            }
            
            _logger!.LogInformation("=== ALL TESTS PASSED SUCCESSFULLY ===");
            _logger!.LogInformation("🎯 ReportMate client is ready for data collection and reporting");
            _logger!.LogInformation("💡 Run 'runner.exe run' to perform actual data collection and transmission");
            
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during testing");
            return 1;
        }
    }

    private static async Task<int> HandleInfoCommand(bool verbose)
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
            
            if (verbose)
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

    private static async Task<int> HandleInstallCommand(bool verbose)
    {
        try
        {
            if (verbose)
            {
                _logger!.LogInformation("=== VERBOSE INSTALL MODE ===");
            }
            
            _logger!.LogInformation("Installing ReportMate client configuration...");
            
            var configService = _serviceProvider!.GetRequiredService<IConfigurationService>();
            await configService.InstallConfigurationAsync();
            
            _logger!.LogInformation("✅ Installation completed successfully");
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during installation");
            return 1;
        }
    }

    private static Task<int> HandleBuildCommand(bool verbose)
    {
        try
        {
            if (verbose)
            {
                _logger!.LogInformation("=== BUILD COMMAND VERBOSE MODE ===");
                _logger!.LogInformation("This command is used internally by the build script");
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
}
