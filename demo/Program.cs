using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace ReportMate.Demo
{
    /// <summary>
    /// Demo program to showcase the enhanced 4-level verbose logging system
    /// inspired by Cimian's logging model
    /// </summary>
    public class VerboseLoggingDemo
    {
        public static async Task Main(string[] args)
        {
            Console.WriteLine("Enhanced Verbose Logging Demo for ReportMate");
            Console.WriteLine("============================================");
            Console.WriteLine();
            
            // Parse verbose level from args or default to 2
            var verboseLevel = GetVerboseLevel(args);
            
            Console.WriteLine($"Setting verbose level to: {verboseLevel} ({GetVerboseLevelName(verboseLevel)})");
            Console.WriteLine("Available levels:");
            Console.WriteLine("  0 = Errors only");
            Console.WriteLine("  1 = Errors + Warnings");  
            Console.WriteLine("  2 = Errors + Warnings + Info");
            Console.WriteLine("  3 = All messages (Debug)");
            Console.WriteLine();
            
            // Initialize enhanced logger
            EnhancedLogger.SetVerboseLevel(verboseLevel);
            
            // Demo the enhanced logger
            await DemonstrateEnhancedLogging();
            
            Console.WriteLine();
            Console.WriteLine("Demo completed! Try running with different verbose levels:");
            Console.WriteLine("  VerboseLoggingDemo.exe -v        (Level 1: Errors + Warnings)");
            Console.WriteLine("  VerboseLoggingDemo.exe -vv       (Level 2: Errors + Warnings + Info)");
            Console.WriteLine("  VerboseLoggingDemo.exe -vvv      (Level 3: All messages including Debug)");
            Console.WriteLine("  VerboseLoggingDemo.exe --verbose=2  (Explicit level setting)");
        }
        
        private static async Task DemonstrateEnhancedLogging()
        {
            // Section header
            EnhancedLogger.Section("Enhanced Logging Demo", "Demonstrating 4-level verbose logging with colors");
            
            // Error level (always shown)
            EnhancedLogger.Error("This is an error message (always shown regardless of verbose level)");
            
            // Warning level (shown at verbose 1+)
            EnhancedLogger.Warning("This is a warning message (shown at verbose level 1+)");
            
            // Info level (shown at verbose 2+)
            EnhancedLogger.Info("This is an info message (shown at verbose level 2+)");
            
            // Debug level (shown at verbose 3+)
            EnhancedLogger.Debug("This is a debug message (shown at verbose level 3+ only)");
            
            // Demonstrate structured logging
            var deviceData = new Dictionary<string, object?>
            {
                ["Device ID"] = "TEST-123456",
                ["Operating System"] = "Windows 11 Pro",
                ["Manufacturer"] = "Dell Inc.",
                ["Model"] = "OptiPlex 7090",
                ["Memory"] = "16 GB",
                ["Status"] = "Online"
            };
            
            EnhancedLogger.InfoWithData("Device Information", deviceData);
            
            // Demonstrate progress logging
            EnhancedLogger.Section("Progress Demonstration");
            
            var tasks = new[] { "Collecting hardware info", "Checking network", "Validating config", "Sending data" };
            for (int i = 0; i < tasks.Length; i++)
            {
                EnhancedLogger.Progress(tasks[i], i + 1, tasks.Length, $"Step {i + 1}");
                await Task.Delay(200); // Simulate work
            }
            
            // Demonstrate completion logging with timing
            var stopwatch = Stopwatch.StartNew();
            await Task.Delay(100); // Simulate some work
            stopwatch.Stop();
            
            EnhancedLogger.Completed("Data collection", stopwatch.Elapsed, "4 items processed");
            
            // Show conditional logging based on level
            EnhancedLogger.Section("Conditional Logging");
            
            if (EnhancedLogger.IsLevelEnabled(EnhancedLogger.LogLevel.Debug))
            {
                EnhancedLogger.Debug("Performing detailed diagnostic checks...");
                EnhancedLogger.Debug("Memory usage: {0} MB", GC.GetTotalMemory(false) / 1024 / 1024);
                EnhancedLogger.Debug("Process ID: {0}", Environment.ProcessId);
            }
            
            if (EnhancedLogger.IsLevelEnabled(EnhancedLogger.LogLevel.Info))
            {
                EnhancedLogger.Info("Current verbose level allows info messages");
            }
            
            // Error handling demo
            try
            {
                throw new InvalidOperationException("Demo exception to show error handling");
            }
            catch (Exception ex)
            {
                EnhancedLogger.Error("Caught exception: {0}", ex.Message);
                if (EnhancedLogger.IsLevelEnabled(EnhancedLogger.LogLevel.Debug))
                {
                    EnhancedLogger.Debug("Exception details: {0}", ex.ToString());
                }
            }
            
            // ReportMate-specific demo scenarios
            EnhancedLogger.Section("ReportMate Scenarios");
            
            // Simulate device registration
            EnhancedLogger.Info("Starting device registration...");
            EnhancedLogger.Debug("Detecting device serial number");
            EnhancedLogger.Debug("Found serial: ABC123456789");
            EnhancedLogger.Info("Device registration successful");
            
            // Simulate osquery execution
            EnhancedLogger.Info("Executing osquery modules...");
            var modules = new[] { "system_info", "hardware", "network", "software" };
            foreach (var module in modules)
            {
                EnhancedLogger.Debug("Loading module: {0}", module);
                await Task.Delay(50);
                EnhancedLogger.Info("✓ Module '{0}' completed", module);
            }
            
            // Simulate API transmission
            EnhancedLogger.Info("Transmitting data to ReportMate API...");
            EnhancedLogger.Debug("API endpoint: https://api.reportmate.com/ingest");
            EnhancedLogger.Debug("Payload size: 2.3 KB");
            EnhancedLogger.Info("✓ Data transmission completed");
            
            // Show warnings for common issues
            EnhancedLogger.Warning("Some osquery modules returned partial data");
            EnhancedLogger.Warning("Network latency detected: 250ms");
        }
        
        private static int GetVerboseLevel(string[] args)
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
            
            return 2; // Default verbose level for demo
        }
        
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
    }
}
