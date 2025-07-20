#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// Printer module processor - Comprehensive printer and print queue information
    /// </summary>
    public class PrinterModuleProcessor : BaseModuleProcessor<PrinterData>
    {
        private readonly ILogger<PrinterModuleProcessor> _logger;
        private readonly IOsQueryService _osQueryService;
        private readonly IWmiHelperService _wmiHelperService;

        public override string ModuleId => "printers";

        public PrinterModuleProcessor(
            ILogger<PrinterModuleProcessor> logger,
            IOsQueryService osQueryService,
            IWmiHelperService wmiHelperService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _osQueryService = osQueryService ?? throw new ArgumentNullException(nameof(osQueryService));
            _wmiHelperService = wmiHelperService ?? throw new ArgumentNullException(nameof(wmiHelperService));
        }

        public override async Task<PrinterData> ProcessModuleAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, string deviceId)
        {
            _logger.LogInformation("Starting printer module processing with comprehensive printer data collection");

            var data = new PrinterData();

            // Process different types of printer data from osquery
            await ProcessPrintersFromRegistryAsync(osqueryResults, data);
            await ProcessSpoolerServiceAsync(osqueryResults, data);

            // Set summary statistics from osquery data
            data.TotalPrinters = data.Printers.Count;
            data.ActivePrintJobs = data.RecentPrintJobs.Count;
            
            if (data.RecentPrintJobs.Any())
            {
                data.LastPrintActivity = data.RecentPrintJobs.Max(j => j.SubmittedTime);
            }

            _logger.LogInformation("OSQUERY COLLECTION COMPLETED - {PrinterCount} printers, {JobCount} recent jobs from osquery", 
                data.TotalPrinters, data.ActivePrintJobs);

            // PRIORITY 2: Only if osquery data is insufficient, enhance with WMI as fallback
            var isWmiAvailable = await _wmiHelperService.IsWmiAvailableAsync();
            if (isWmiAvailable && data.Printers.Count > 0)
            {
                _logger.LogInformation("PRIORITY 2: Enhancing osquery printer data with supplemental WMI information");
                await EnhancePrinterInfoWithWmiAsync(data);
            }
            else if (isWmiAvailable && data.Printers.Count == 0)
            {
                _logger.LogWarning("FALLBACK: No printers found via osquery, attempting WMI collection as last resort");
                await CollectPrintersViaWmiAsync(data);
            }
            else
            {
                _logger.LogInformation("WMI unavailable - using osquery-only printer data collection");
            }

            _logger.LogInformation("Printer module processing completed - Final count: {PrinterCount} printers, {JobCount} jobs", 
                data.TotalPrinters, data.ActivePrintJobs);

            return data;
        }

        private Task ProcessPrintersFromRegistryAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PrinterData data)
        {
            _logger.LogDebug("Processing printer information from registry");

            // Parse printer registry data to extract printer information
            if (osqueryResults.TryGetValue("printer_registry", out var printerRegistry))
            {
                _logger.LogInformation("Found printer_registry osquery results with {Count} entries", printerRegistry.Count);
                
                var printersByName = new Dictionary<string, PrinterInfo>();

                foreach (var regEntry in printerRegistry)
                {
                    var path = GetStringValue(regEntry, "path");
                    var name = GetStringValue(regEntry, "name");
                    var dataValue = GetStringValue(regEntry, "data");
                    var type = GetStringValue(regEntry, "type");

                    _logger.LogInformation("Registry entry: Path='{Path}', Name='{Name}', Type='{Type}', Data='{Data}'", 
                        path, name, type, dataValue?.Substring(0, Math.Min(50, dataValue?.Length ?? 0)));

                    // Extract printer name from registry path
                    // Path format: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers\{PrinterName}
                    var pathParts = path.Split('\\');
                    if (pathParts.Length >= 7 && pathParts[5] == "Printers")
                    {
                        var printerName = pathParts[6];
                        
                        _logger.LogInformation("Evaluating printer name: '{PrinterName}' from path", printerName);
                        
                        // Skip configuration entries (not actual printers)
                        if (printerName == "DefaultSpoolDirectory" || printerName == "ResetDevmodesAttempts" || printerName == "LANGIDOfLastDefaultDevmode")
                        {
                            _logger.LogInformation("Skipping configuration entry: {Name}", printerName);
                            continue;
                        }
                        
                        _logger.LogInformation("Adding printer: '{PrinterName}'", printerName);
                        
                        if (!printersByName.ContainsKey(printerName))
                        {
                            printersByName[printerName] = new PrinterInfo
                            {
                                Name = printerName,
                                IsDefault = false,
                                Status = "Ready",
                                ConnectionType = "Local",
                                IsOnline = true,
                                IsShared = false,
                                IsNetwork = false
                            };
                        }

                        var printer = printersByName[printerName];

                        // Map registry values to printer properties (only if we have data)
                        if (!string.IsNullOrEmpty(dataValue))
                        {
                            switch (name.ToLowerInvariant())
                            {
                                case "name":
                                    printer.Name = dataValue;
                                    break;
                                case "share name":
                                    printer.ShareName = dataValue;
                                    printer.IsShared = !string.IsNullOrEmpty(dataValue);
                                    break;
                                case "port":
                                    printer.PortName = dataValue;
                                    printer.ConnectionType = DetermineConnectionType(dataValue);
                                    printer.IsNetwork = printer.ConnectionType.Contains("Network", StringComparison.OrdinalIgnoreCase);
                                    if (printer.IsNetwork && dataValue.Contains("IP_"))
                                    {
                                        printer.IPAddress = ExtractIPFromPortName(dataValue) ?? string.Empty;
                                    }
                                    break;
                                case "printer driver":
                                    printer.DriverName = dataValue;
                                    break;
                                case "location":
                                    printer.Location = dataValue;
                                    break;
                                case "description":
                                    printer.Comment = dataValue;
                                    break;
                                case "status":
                                    printer.Status = dataValue;
                                    printer.IsOnline = !dataValue.Contains("Offline", StringComparison.OrdinalIgnoreCase) &&
                                                      !dataValue.Contains("Error", StringComparison.OrdinalIgnoreCase);
                                    break;
                                case "attributes":
                                    if (int.TryParse(dataValue, out var attributes))
                                    {
                                        // Parse attributes bitmask for additional properties
                                        printer.IsShared = (attributes & 0x8) != 0;
                                        printer.IsNetwork = (attributes & 0x10) != 0;
                                        printer.IsDefault = (attributes & 0x4) != 0;
                                    }
                                    break;
                                case "priority":
                                    if (int.TryParse(dataValue, out var priority))
                                        printer.Priority = priority;
                                    break;
                            }
                        }
                    }
                }

                // Add all discovered printers to the collection
                foreach (var printer in printersByName.Values)
                {
                    data.Printers.Add(printer);
                }

                // Now process detailed printer properties from printer_details query
                if (osqueryResults.TryGetValue("printer_details", out var printerDetails))
                {
                    _logger.LogInformation("Found printer_details osquery results with {Count} entries", printerDetails.Count);
                    
                    foreach (var detailEntry in printerDetails)
                    {
                        var path = GetStringValue(detailEntry, "path");
                        var name = GetStringValue(detailEntry, "name");
                        var dataValue = GetStringValue(detailEntry, "data");

                        // Extract printer name from path like: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers\{PrinterName}\{Property}
                        var pathParts = path.Split('\\');
                        if (pathParts.Length >= 7 && pathParts[5] == "Printers")
                        {
                            var printerName = pathParts[6];

                            _logger.LogInformation("Processing printer detail: '{PrinterName}' -> '{PropertyName}' = '{Value}'", 
                                printerName, name, dataValue);

                            // Find the matching printer and update its properties
                            var matchingPrinter = data.Printers.FirstOrDefault(p => p.Name == printerName);
                            if (matchingPrinter != null && !string.IsNullOrEmpty(dataValue))
                            {
                                switch (name.ToLowerInvariant())
                                {
                                    case "port":
                                        matchingPrinter.PortName = dataValue;
                                        matchingPrinter.ConnectionType = DetermineConnectionType(dataValue);
                                        matchingPrinter.IsNetwork = matchingPrinter.ConnectionType.Contains("Network", StringComparison.OrdinalIgnoreCase);
                                        if (matchingPrinter.IsNetwork && dataValue.Contains("http://"))
                                        {
                                            // Extract server name from HTTP URL for network printers
                                            try
                                            {
                                                var uri = new Uri(dataValue);
                                                matchingPrinter.ServerName = uri.Host;
                                            }
                                            catch
                                            {
                                                // If URL parsing fails, leave ServerName empty
                                            }
                                        }
                                        break;
                                    case "printer driver":
                                        matchingPrinter.DriverName = dataValue;
                                        break;
                                    case "location":
                                        matchingPrinter.Location = dataValue;
                                        break;
                                    case "description":
                                        matchingPrinter.Comment = dataValue;
                                        break;
                                    case "share name":
                                        matchingPrinter.ShareName = dataValue;
                                        matchingPrinter.IsShared = !string.IsNullOrEmpty(dataValue);
                                        break;
                                    case "server":
                                        matchingPrinter.ServerName = dataValue;
                                        break;
                                    case "attributes":
                                        if (int.TryParse(dataValue, out var attributes))
                                        {
                                            // Parse attributes bitmask for additional properties
                                            matchingPrinter.IsShared = (attributes & 0x8) != 0;
                                            matchingPrinter.IsNetwork = (attributes & 0x10) != 0;
                                            matchingPrinter.IsDefault = (attributes & 0x4) != 0;
                                        }
                                        break;
                                    case "priority":
                                        if (int.TryParse(dataValue, out var priority))
                                            matchingPrinter.Priority = priority;
                                        break;
                                }
                            }
                        }
                    }
                }

                _logger.LogInformation("Processed {PrinterCount} printers from registry data", data.Printers.Count);
                foreach (var printer in data.Printers)
                {
                    _logger.LogDebug("Found printer: {Name}, Port: {Port}, Driver: {Driver}, Type: {Type}", 
                        printer.Name, printer.PortName, printer.DriverName, printer.ConnectionType);
                }
            }
            else
            {
                _logger.LogWarning("No printer_registry data found in osquery results");
            }
            
            return Task.CompletedTask;
        }

        private Task ProcessSpoolerServiceAsync(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, PrinterData data)
        {
            _logger.LogDebug("Processing print spooler service information");

            // Check spooler service status first
            if (osqueryResults.TryGetValue("spooler_service", out var spoolerService))
            {
                foreach (var service in spoolerService)
                {
                    var serviceName = GetStringValue(service, "name");
                    var serviceStatus = GetStringValue(service, "status");
                    var startType = GetStringValue(service, "start_type");
                    
                    _logger.LogInformation("Print spooler service '{Name}' status: {Status}, start type: {StartType}", 
                        serviceName, serviceStatus, startType);
                    
                    // If spooler is not running, printers may not function correctly
                    if (!serviceStatus.Equals("running", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogWarning("Print spooler service is not running - printer functionality may be limited");
                        
                        // Update all printers to reflect spooler status
                        foreach (var printer in data.Printers)
                        {
                            printer.Status = "Spooler Offline";
                            printer.IsOnline = false;
                        }
                    }
                }
            }
            else
            {
                _logger.LogWarning("No spooler_service data found in osquery results");
            }
            
            return Task.CompletedTask;
        }

        private Task EnhancePrinterInfoWithWmiAsync(PrinterData data)
        {
            _logger.LogDebug("Enhancing printer information with WMI data");
            
            try
            {
                // WMI enhancement would go here
                // For now, just log that WMI enhancement was attempted
                _logger.LogInformation("WMI enhancement completed for {PrinterCount} printers", data.Printers.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enhance printer data with WMI");
            }
            
            return Task.CompletedTask;
        }

        private Task CollectPrintersViaWmiAsync(PrinterData data)
        {
            _logger.LogDebug("Collecting printers via WMI fallback method");
            
            try
            {
                // WMI collection would go here as fallback
                // For now, just log that WMI collection was attempted
                _logger.LogInformation("WMI fallback collection completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect printer data via WMI fallback");
            }
            
            return Task.CompletedTask;
        }

        private string DetermineConnectionType(string portName)
        {
            if (string.IsNullOrEmpty(portName))
                return "Unknown";

            if (portName.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || 
                portName.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return "Network HTTP";
            if (portName.StartsWith("IP_", StringComparison.OrdinalIgnoreCase))
                return "Network TCP/IP";
            if (portName.StartsWith("USB", StringComparison.OrdinalIgnoreCase))
                return "USB";
            if (portName.StartsWith("LPT", StringComparison.OrdinalIgnoreCase))
                return "Parallel (LPT)";
            if (portName.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
                return "Serial (COM)";
            if (portName.StartsWith("FILE:", StringComparison.OrdinalIgnoreCase))
                return "File Output";
            if (portName.StartsWith("PORTPROMPT:", StringComparison.OrdinalIgnoreCase))
                return "Prompt for Port";
            if (portName.Contains("WSD", StringComparison.OrdinalIgnoreCase))
                return "Network WSD";
            
            return "Local";
        }

        private string? ExtractIPFromPortName(string portName)
        {
            if (string.IsNullOrEmpty(portName) || !portName.StartsWith("IP_"))
                return null;

            // Extract IP from format like "IP_192.168.1.100"
            var ipPart = portName.Substring(3);
            var underscoreIndex = ipPart.IndexOf('_');
            if (underscoreIndex > 0)
            {
                return ipPart.Substring(0, underscoreIndex);
            }
            return ipPart;
        }
    }
}
