using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

class Program 
{
    static void Main()
    {
        Console.WriteLine("Testing Unicode Normalization for WiFi SSIDs - Enhanced Version");
        Console.WriteLine("================================================================");
        
        // Test the specific issue: RodΓÇÖs iPhone should become Rod's iPhone
        var testCases = new[]
        {
            "RodΓÇÖs iPhone",    // The problematic case from the network.json
            "Rod's iPhone",      // What it should be
            "Rod\\u0393\\u00C7\\u00D6s iPhone", // JSON escaped version
            "TestΓÇÖNetwork",    // Another test case
            "Company'ΓÇÖs WiFi", // Mixed case
        };
        
        Console.WriteLine("Testing various Unicode normalization cases:");
        Console.WriteLine("==========================================");
        
        foreach (var testInput in testCases)
        {
            Console.WriteLine($"\nOriginal: {testInput}");
            var normalized = NormalizeUnicodeString(testInput);
            Console.WriteLine($"Normalized: {normalized}");
            Console.WriteLine($"Changed: {testInput != normalized}");
        }
        
        // Test JSON serialization with the new encoder settings
        var wifiNetwork = new { Ssid = NormalizeUnicodeString("RodΓÇÖs iPhone"), SignalStrength = 85 };
        
        // Test with default encoder (should escape Unicode)
        var defaultOptions = new JsonSerializerOptions
        {
            WriteIndented = true
        };
        
        var defaultJson = JsonSerializer.Serialize(wifiNetwork, defaultOptions);
        Console.WriteLine($"\nJSON with Default Encoder:\n{defaultJson}");
        
        // Test with relaxed encoder (should NOT escape Unicode)
        var relaxedOptions = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        };
        
        var relaxedJson = JsonSerializer.Serialize(wifiNetwork, relaxedOptions);
        Console.WriteLine($"\nJSON with Relaxed Encoder:\n{relaxedJson}");
        
        // Demonstrate the fix
        Console.WriteLine("\n=== SOLUTION DEMONSTRATION ===");
        Console.WriteLine("Problem: WiFi networks would show 'RodΓÇÖs iPhone'");
        Console.WriteLine($"Solution: WiFi networks now show '{NormalizeUnicodeString("RodΓÇÖs iPhone")}'");
        
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }
    
    static string? NormalizeUnicodeString(string? input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        try
        {
            var result = input;
            
            // Fix common UTF-8 to Windows-1252 encoding issues first
            // These happen when UTF-8 bytes are incorrectly decoded as Windows-1252
            var encodingFixes = new Dictionary<string, string>
            {
                { "ΓÇÖ", "'" },  // Right single quotation mark (U+2019)
                { "ΓÇÿ", "'" },  // Left single quotation mark (U+2018)  
                { "Γǣ", "\"" }, // Left double quotation mark (U+201C)
                { "ΓÇ¥", "\"" }, // Right double quotation mark (U+201D)
                { "ΓÇô", "–" },  // En dash (U+2013)
                { "ΓÇö", "—" },  // Em dash (U+2014)
                { "ΓÇª", "…" },  // Horizontal ellipsis (U+2026)
                { "Γé¼", "€" },  // Euro sign (U+20AC)
                { "Γé░", "°" },  // Degree sign (U+00B0)
            };

            foreach (var fix in encodingFixes)
            {
                result = result.Replace(fix.Key, fix.Value);
            }
            
            // Alternative approach: Try to detect and fix double-encoded UTF-8
            // This happens when UTF-8 text is decoded as Latin-1, then encoded as UTF-8 again
            try
            {
                var bytes = System.Text.Encoding.GetEncoding("ISO-8859-1").GetBytes(result);
                var utf8Attempt = System.Text.Encoding.UTF8.GetString(bytes);
                
                // Only use the UTF-8 interpretation if it looks more reasonable
                // (contains common punctuation that was likely mangled)
                if (utf8Attempt.Contains("'") || utf8Attempt.Contains("'") || 
                    utf8Attempt.Contains(""") || utf8Attempt.Contains(""") ||
                    utf8Attempt.Contains("–") || utf8Attempt.Contains("—"))
                {
                    result = utf8Attempt;
                    Console.WriteLine($"Applied UTF-8 double-encoding fix: '{input}' -> '{result}'");
                }
            }
            catch
            {
                // If the double-encoding fix fails, continue with the current result
            }
            
            // Handle JSON-style Unicode escape sequences like \u0393\u00C7\u00D6
            if (result.Contains("\\u"))
            {
                result = Regex.Replace(result, @"\\u([0-9A-Fa-f]{4})", 
                    match => {
                        try 
                        {
                            var code = Convert.ToInt32(match.Groups[1].Value, 16);
                            return char.ConvertFromUtf32(code);
                        }
                        catch
                        {
                            return match.Value; // Return original if conversion fails
                        }
                    });
            }
            
            // Handle other common escape sequences
            try
            {
                result = Regex.Unescape(result);
            }
            catch
            {
                // If Unescape fails, continue with the current result
            }
            
            // Normalize the Unicode string to composed form (NFC) for consistent representation
            result = result.Normalize(System.Text.NormalizationForm.FormC);
            
            // Clean up any remaining problematic characters or sequences
            result = result.Trim();
            
            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to normalize Unicode string: {input} - {ex.Message}");
            return input;
        }
    }
}
