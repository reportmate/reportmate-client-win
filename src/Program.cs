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
using System.IO;
using System.Threading.Tasks;
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

    public static async Task<int> Main(string[] args)
    {
        try
        {
            // Build configuration from multiple sources
            var configuration = BuildConfiguration();
            
            // Setup dependency injection
            _serviceProvider = ConfigureServices(configuration);
            _logger = _serviceProvider.GetRequiredService<ILogger<Program>>();

            _logger.LogInformation("ReportMate v{Version} starting", 
                System.Reflection.Assembly.GetExecutingAssembly().GetName().Version);

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
        }
    }

    private static IConfiguration BuildConfiguration()
    {
        var builder = new ConfigurationBuilder();
        
        // Configuration hierarchy (lowest to highest precedence):
        
        // 1. Application defaults from Program Files (embedded in binary)
        builder.SetBasePath(ConfigurationService.GetApplicationDirectory());
        builder.AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
               .AddYamlFile("appsettings.yaml", optional: true, reloadOnChange: false);
        
        // 2. Enterprise template configuration from ProgramData (CSP/OMA-URI manageable)
        var programDataPath = ConfigurationService.GetWorkingDataDirectory();
        if (Directory.Exists(programDataPath))
        {
            builder.SetBasePath(programDataPath)
                   .AddJsonFile("appsettings.template.json", optional: true, reloadOnChange: false)
                   .AddYamlFile("appsettings.template.yaml", optional: true, reloadOnChange: false);
        }
        
        // 3. Working configuration from ProgramData (runtime/user editable)
        if (Directory.Exists(programDataPath))
        {
            builder.SetBasePath(programDataPath)
                   .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
                   .AddYamlFile("appsettings.yaml", optional: true, reloadOnChange: false);
        }
        
        // 4. Environment variables (prefix: REPORTMATE_)
        builder.AddEnvironmentVariables("REPORTMATE_");
        
        // 5. Windows Registry (highest precedence - CSP/Group Policy)
        builder.AddWindowsRegistry();

        return builder.Build();
    }

    private static ServiceProvider ConfigureServices(IConfiguration configuration)
    {
        var services = new ServiceCollection();

        // Configure Serilog first
        var logDirectory = configuration["ReportMate:LogDirectory"] ?? @"C:\ProgramData\ManagedReports\logs";
        Directory.CreateDirectory(logDirectory);
        
        var loggerConfig = new LoggerConfiguration()
            .MinimumLevel.Information();

        // Only log to file and event log in production - never to console
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
        else
        {
            // Only add console logging in development mode
            loggerConfig.WriteTo.Console();
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

        // Default command - run data collection
        var runCommand = new Command("run", "Run data collection and send to API (default)")
        {
            new Option<bool>("--force", "Force data collection even if recent run detected"),
            new Option<string>("--device-id", "Override device ID"),
            new Option<string>("--api-url", "Override API URL")
        };
        runCommand.SetHandler(HandleRunCommand);

        // Test command - validate configuration and connectivity
        var testCommand = new Command("test", "Test configuration and API connectivity")
        {
            new Option<bool>("--verbose", "Enable verbose output")
        };
        testCommand.SetHandler(HandleTestCommand);

        // Info command - display system and configuration information
        var infoCommand = new Command("info", "Display system and configuration information");
        infoCommand.SetHandler(HandleInfoCommand);

        // Install command - setup registry and configuration
        var installCommand = new Command("install", "Install and configure ReportMate client")
        {
            new Option<string>("--api-url", "API endpoint URL") { IsRequired = true },
            new Option<string>("--device-id", "Custom device identifier"),
            new Option<string>("--api-key", "API authentication key")
        };
        installCommand.SetHandler(HandleInstallCommand);

        rootCommand.AddCommand(runCommand);
        rootCommand.AddCommand(testCommand);
        rootCommand.AddCommand(infoCommand);
        rootCommand.AddCommand(installCommand);

        // Set default command
        rootCommand.SetHandler(HandleRunCommand);

        return rootCommand;
    }

    private static async Task<int> HandleRunCommand()
    {
        try
        {
            _logger!.LogInformation("Starting data collection run");
            
            var dataCollectionService = _serviceProvider!.GetRequiredService<IDataCollectionService>();
            var result = await dataCollectionService.CollectAndSendDataAsync();
            
            if (result)
            {
                _logger.LogInformation("Data collection completed successfully");
                return 0;
            }
            else
            {
                _logger.LogError("Data collection failed");
                return 1;
            }
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during data collection");
            return 1;
        }
    }

    private static async Task<int> HandleTestCommand()
    {
        try
        {
            _logger!.LogInformation("Running configuration and connectivity tests");
            
            var configService = _serviceProvider!.GetRequiredService<IConfigurationService>();
            var apiService = _serviceProvider.GetRequiredService<IApiService>();
            
            // Test configuration
            var config = await configService.ValidateConfigurationAsync();
            if (!config.IsValid)
            {
                _logger.LogError("Configuration validation failed: {Errors}", 
                    string.Join(", ", config.Errors));
                return 1;
            }
            
            // Test API connectivity
            var apiConnectivity = await apiService.TestConnectivityAsync();
            if (!apiConnectivity)
            {
                _logger.LogError("API connectivity test failed");
                return 1;
            }
            
            _logger.LogInformation("All tests passed successfully");
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during testing");
            return 1;
        }
    }

    private static async Task<int> HandleInfoCommand()
    {
        try
        {
            var deviceInfoService = _serviceProvider!.GetRequiredService<IDeviceInfoService>();
            var configService = _serviceProvider.GetRequiredService<IConfigurationService>();
            
            var deviceInfo = await deviceInfoService.GetBasicDeviceInfoAsync();
            var config = await configService.GetCurrentConfigurationAsync();
            
            Console.WriteLine("=== ReportMate Information ===");
            Console.WriteLine($"Version: {System.Reflection.Assembly.GetExecutingAssembly().GetName().Version}");
            Console.WriteLine($"Device ID: {deviceInfo.DeviceId}");
            Console.WriteLine($"Computer Name: {deviceInfo.ComputerName}");
            Console.WriteLine($"OS Version: {deviceInfo.OperatingSystem}");
            Console.WriteLine($"API URL: {config.ApiUrl}");
            Console.WriteLine($"Last Run: {config.LastRunTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");
            
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error retrieving information");
            return 1;
        }
    }

    private static async Task<int> HandleInstallCommand()
    {
        try
        {
            _logger!.LogInformation("Installing and configuring ReportMate client");
            
            var configService = _serviceProvider!.GetRequiredService<IConfigurationService>();
            await configService.InstallConfigurationAsync();
            
            _logger.LogInformation("Installation completed successfully");
            return 0;
        }
        catch (Exception ex)
        {
            _logger!.LogError(ex, "Error during installation");
            return 1;
        }
    }
}
