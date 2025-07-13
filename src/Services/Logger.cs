#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Multi-level logger with color support, inspired by Cimian's logging model
    /// Supports 4 verbose levels: Error (0), Warning (1), Info (2), Debug (3)
    /// </summary>
    public static class Logger
    {
        private static readonly object _lock = new();
        private static int _verboseLevel = 0;
        private static bool _colorsEnabled = false;
        
        // Log levels (higher numbers = more verbose)
        public enum LogLevel
        {
            Error = 0,    // Only critical errors
            Warning = 1,  // Errors + warnings
            Info = 2,     // Errors + warnings + info
            Debug = 3     // All messages including debug
        }

        // ANSI color codes
        private static readonly Dictionary<LogLevel, string> ColorCodes = new()
        {
            [LogLevel.Error] = "\u001b[31m",    // Red
            [LogLevel.Warning] = "\u001b[33m",  // Yellow
            [LogLevel.Info] = "\u001b[32m",     // Green
            [LogLevel.Debug] = "\u001b[34m"     // Blue
        };

        private static readonly Dictionary<LogLevel, string> LevelNames = new()
        {
            [LogLevel.Error] = "ERROR",
            [LogLevel.Warning] = "WARN",
            [LogLevel.Info] = "INFO",
            [LogLevel.Debug] = "DEBUG"
        };

        private const string ColorReset = "\u001b[0m";

        static Logger()
        {
            EnableColors();
        }

        /// <summary>
        /// Set the verbose level (0-3)
        /// 0 = Errors only
        /// 1 = Errors + Warnings  
        /// 2 = Errors + Warnings + Info
        /// 3 = All messages (including Debug)
        /// </summary>
        public static void SetVerboseLevel(int level)
        {
            _verboseLevel = Math.Max(0, Math.Min(3, level));
        }

        /// <summary>
        /// Enable ANSI colors for Windows console if supported
        /// </summary>
        private static void EnableColors()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var handle = GetStdHandle(-11); // STD_OUTPUT_HANDLE
                    if (GetConsoleMode(handle, out var mode))
                    {
                        // Enable virtual terminal processing (0x0004)
                        mode |= 0x0004;
                        _colorsEnabled = SetConsoleMode(handle, mode);
                    }
                }
                catch
                {
                    _colorsEnabled = false;
                }
            }
            else
            {
                // Non-Windows platforms typically support ANSI colors
                _colorsEnabled = true;
            }
        }

        /// <summary>
        /// Log an error message (always shown regardless of verbose level)
        /// </summary>
        public static void Error(string message, params object[] args)
        {
            LogMessage(LogLevel.Error, message, args);
        }

        /// <summary>
        /// Log a warning message (shown at verbose level 1+)
        /// </summary>
        public static void Warning(string message, params object[] args)
        {
            LogMessage(LogLevel.Warning, message, args);
        }

        /// <summary>
        /// Log an informational message (shown at verbose level 2+)
        /// </summary>
        public static void Info(string message, params object[] args)
        {
            LogMessage(LogLevel.Info, message, args);
        }

        /// <summary>
        /// Log a debug message (shown at verbose level 3+)
        /// </summary>
        public static void Debug(string message, params object[] args)
        {
            LogMessage(LogLevel.Debug, message, args);
        }

        /// <summary>
        /// Log a message with key-value pairs (structured logging)
        /// </summary>
        public static void InfoWithData(string message, Dictionary<string, object?> data)
        {
            if ((int)LogLevel.Info > _verboseLevel) return;

            lock (_lock)
            {
                LogMessage(LogLevel.Info, message);
                
                if (data.Count > 0)
                {
                    foreach (var kvp in data)
                    {
                        var valueStr = kvp.Value?.ToString() ?? "null";
                        LogMessage(LogLevel.Info, "  {0}: {1}", kvp.Key, valueStr);
                    }
                }
            }
        }

        /// <summary>
        /// Log an operation with progress indication
        /// </summary>
        public static void Progress(string operation, int current, int total, string? detail = null)
        {
            if ((int)LogLevel.Info > _verboseLevel) return;

            var percentage = (double)current / total * 100;
            var progressBar = CreateProgressBar(percentage, 20);
            var detailText = detail != null ? $" | {detail}" : "";
            
            LogMessage(LogLevel.Info, "[{0:D2}/{1:D2}] {2} {3:F0}% {4}{5}", 
                current, total, progressBar, percentage, operation, detailText);
        }

        /// <summary>
        /// Log a section header for better organization
        /// </summary>
        public static void Section(string title, string? subtitle = null)
        {
            if ((int)LogLevel.Info > _verboseLevel) return;

            lock (_lock)
            {
                Console.WriteLine();
                LogMessage(LogLevel.Info, "=== {0} ===", title.ToUpper());
                if (!string.IsNullOrEmpty(subtitle))
                {
                    LogMessage(LogLevel.Info, "    {0}", subtitle);
                }
                LogMessage(LogLevel.Info, new string('─', Math.Min(60, title.Length + 8)));
            }
        }

        /// <summary>
        /// Log a completion message with timing
        /// </summary>
        public static void Completed(string operation, TimeSpan duration, string? result = null)
        {
            var durationText = duration.TotalSeconds < 1 
                ? $"{duration.TotalMilliseconds:F0}ms" 
                : $"{duration.TotalSeconds:F1}s";
            
            var resultText = result != null ? $" | {result}" : "";
            Info("✓ {0} completed in {1}{2}", operation, durationText, resultText);
        }

        /// <summary>
        /// Core logging method
        /// </summary>
        private static void LogMessage(LogLevel level, string message, params object[] args)
        {
            if ((int)level > _verboseLevel) return;

            lock (_lock)
            {
                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var levelName = LevelNames[level];
                var formattedMessage = args.Length > 0 ? string.Format(message, args) : message;

                var logLine = $"[{timestamp}] {levelName,-5} {formattedMessage}";

                // Add color if enabled and not redirected
                if (_colorsEnabled && !Console.IsOutputRedirected && ColorCodes.TryGetValue(level, out var colorCode))
                {
                    Console.WriteLine($"{colorCode}{logLine}{ColorReset}");
                }
                else
                {
                    Console.WriteLine(logLine);
                }

                // Force flush for real-time output
                Console.Out.Flush();
            }
        }

        /// <summary>
        /// Create a visual progress bar
        /// </summary>
        private static string CreateProgressBar(double percentage, int width)
        {
            var filled = (int)(percentage / 100 * width);
            var empty = width - filled;
            return $"[{new string('█', filled)}{new string('░', empty)}]";
        }

        /// <summary>
        /// Get current verbose level for external checks
        /// </summary>
        public static int GetVerboseLevel() => _verboseLevel;

        /// <summary>
        /// Check if a specific log level is enabled
        /// </summary>
        public static bool IsLevelEnabled(LogLevel level) => (int)level <= _verboseLevel;

        // Windows API for console colors
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll")]
        private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll")]
        private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    }
}
