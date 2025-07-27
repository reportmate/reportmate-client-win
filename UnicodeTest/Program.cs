using System;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

class Program 
{
    static void Main()
    {
        Console.WriteLine("Testing Unicode Normalization for WiFi SSIDs");
        Console.WriteLine("==============================================");
        
        // Test the Unicode normalization similar to what's in NetworkModuleProcessor
        var testInput = "Rod\\u0393\\u00C7\\u00D6s iPhone";
        Console.WriteLine($"Original: {testInput}");
        
        var normalized = NormalizeUnicodeString(testInput);
        Console.WriteLine($"Normalized: {normalized}");
        
        // Test JSON serialization with the new encoder settings
        var wifiNetwork = new { Ssid = normalized, SignalStrength = 85 };
        
        // Test with default encoder (should escape Unicode)
        var defaultOptions = new JsonSerializerOptions
        {
            WriteIndented = true
        };
        
        var defaultJson = JsonSerializer.Serialize(wifiNetwork, defaultOptions);
        Console.WriteLine($"\nJSON with Default Encoder (should show escapes):\n{defaultJson}");
        
        // Test with relaxed encoder (should NOT escape Unicode)
        var relaxedOptions = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        };
        
        var relaxedJson = JsonSerializer.Serialize(wifiNetwork, relaxedOptions);
        Console.WriteLine($"\nJSON with Relaxed Encoder (should show Unicode directly):\n{relaxedJson}");
        
        // Demonstrate the fix
        Console.WriteLine("\n=== DEMONSTRATION ===");
        Console.WriteLine("Before fix: WiFi networks would show 'Rod\\u0393\\u00C7\\u00D6s iPhone'");
        Console.WriteLine($"After fix: WiFi networks now show '{normalized}'");
        
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }
    
    static string? NormalizeUnicodeString(string? input)
    {
        if (string.IsNullOrEmpty(input)) return input;

        try
        {
            var result = input;
            
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
            Console.WriteLine($"Failed to normalize Unicode string: {input}, Error: {ex.Message}");
            return input;
        }
    }
}
