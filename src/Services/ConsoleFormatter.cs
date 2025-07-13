#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Enhanced console formatter for human legible verbose output
    /// </summary>
    public static class ConsoleFormatter
    {
        private static readonly object _lock = new();
        private static bool _isVerbose = false;
        
        // Color scheme
        private static readonly Dictionary<string, ConsoleColor> Colors = new()
        {
            ["header"] = ConsoleColor.Cyan,
            ["section"] = ConsoleColor.Yellow,
            ["success"] = ConsoleColor.Green,
            ["warning"] = ConsoleColor.DarkYellow,
            ["error"] = ConsoleColor.Red,
            ["info"] = ConsoleColor.White,
            ["debug"] = ConsoleColor.Gray,
            ["progress"] = ConsoleColor.DarkBlue,
            ["accent"] = ConsoleColor.Magenta
        };

        public static void SetVerboseMode(bool verbose)
        {
            _isVerbose = verbose;
        }

        public static void WriteHeader(string text)
        {
            if (!_isVerbose) return;
            
            lock (_lock)
            {
                Console.WriteLine();
                WriteColoredLine("═══════════════════════════════════════════════════════════════════", "accent");
                WriteColoredLine($"  {text.ToUpper()}", "header");
                WriteColoredLine("═══════════════════════════════════════════════════════════════════", "accent");
                Console.WriteLine();
            }
        }

        public static void WriteSection(string title, string? subtitle = null)
        {
            if (!_isVerbose) return;
            
            lock (_lock)
            {
                Console.WriteLine();
                WriteColoredLine($">> {title}", "section");
                if (!string.IsNullOrEmpty(subtitle))
                {
                    WriteColoredLine($"   {subtitle}", "info");
                }
                WriteColoredLine("─────────────────────────────────────────────────────────────", "accent");
            }
        }

        public static void WriteSuccess(string message)
        {
            if (!_isVerbose) return;
            WriteColoredLine($"[OK] {message}", "success");
        }

        public static void WriteInfo(string message, int indent = 0)
        {
            if (!_isVerbose) return;
            var prefix = new string(' ', indent * 2);
            WriteColoredLine($"{prefix}• {message}", "info");
        }

        public static void WriteWarning(string message)
        {
            if (!_isVerbose) return;
            WriteColoredLine($"[WARN] {message}", "warning");
        }

        public static void WriteError(string message)
        {
            if (!_isVerbose) return;
            WriteColoredLine($"[ERROR] {message}", "error");
        }

        public static void WriteDebug(string message)
        {
            if (!_isVerbose) return;
            WriteColoredLine($"  → {message}", "debug");
        }

        public static void WriteProgress(string operation, string detail = "")
        {
            if (!_isVerbose) return;
            var message = string.IsNullOrEmpty(detail) ? $"[...] {operation}..." : $"[...] {operation}: {detail}";
            WriteColoredLine(message, "progress");
        }

        public static void WriteKeyValue(string key, object? value, int indent = 1)
        {
            if (!_isVerbose) return;
            
            var prefix = new string(' ', indent * 2);
            var valueStr = value?.ToString() ?? "Not Set";
            
            lock (_lock)
            {
                Console.Write(prefix);
                WriteColored($"{key}: ", "accent");
                WriteColored(valueStr, "info");
                Console.WriteLine();
            }
        }

        public static void WriteQueryProgress(string queryName, int current, int total, string? result = null)
        {
            if (!_isVerbose) return;
            
            var percentage = (double)current / total * 100;
            var progressBar = CreateProgressBar(percentage, 20);
            var resultText = result != null ? $" | {result}" : "";
            
            WriteColoredLine($"[{current:D2}/{total:D2}] {progressBar} {percentage:F0}% {queryName}{resultText}", "progress");
        }

        public static void WriteModuleSummary(string moduleName, int queryCount, TimeSpan duration)
        {
            if (!_isVerbose) return;
            
            var durationText = duration.TotalSeconds < 1 
                ? $"{duration.TotalMilliseconds:F0}ms" 
                : $"{duration.TotalSeconds:F1}s";
                
            WriteColoredLine($"  [OK] {moduleName}: {queryCount} queries completed in {durationText}", "success");
        }

        public static void WriteCollectionSummary(Dictionary<string, object> summary)
        {
            if (!_isVerbose) return;
            
            WriteSection("Collection Summary");
            
            foreach (var kvp in summary)
            {
                WriteKeyValue(kvp.Key, kvp.Value);
            }
        }

        public static void WriteSeparator()
        {
            if (!_isVerbose) return;
            WriteColoredLine("─────────────────────────────────────────────────────────────", "accent");
        }

        private static void WriteColoredLine(string text, string colorKey)
        {
            if (!_isVerbose) return;
            
            lock (_lock)
            {
                var originalColor = Console.ForegroundColor;
                
                if (Colors.TryGetValue(colorKey, out var color))
                {
                    Console.ForegroundColor = color;
                }
                
                Console.WriteLine(text);
                Console.ForegroundColor = originalColor;
            }
        }

        private static void WriteColored(string text, string colorKey)
        {
            if (!_isVerbose) return;
            
            var originalColor = Console.ForegroundColor;
            
            if (Colors.TryGetValue(colorKey, out var color))
            {
                Console.ForegroundColor = color;
            }
            
            Console.Write(text);
            Console.ForegroundColor = originalColor;
        }

        private static string CreateProgressBar(double percentage, int width)
        {
            var filled = (int)(percentage / 100 * width);
            var empty = width - filled;
            
            return $"[{new string('#', filled)}{new string('.', empty)}]";
        }
    }

    internal static class StringExtensions
    {
        public static string Repeat(this string input, int count)
        {
            if (count <= 0) return string.Empty;
            return string.Concat(Enumerable.Repeat(input, count));
        }
    }
}
