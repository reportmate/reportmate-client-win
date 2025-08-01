#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;

namespace ReportMate.WindowsClient.Services
{
    /// <summary>
    /// Factory for creating module processors
    /// </summary>
    public interface IModuleProcessorFactory
    {
        /// <summary>
        /// Get all available module processors
        /// </summary>
        IEnumerable<IModuleProcessor<BaseModuleData>> GetAllProcessors();

        /// <summary>
        /// Get a specific module processor by module ID
        /// </summary>
        IModuleProcessor<BaseModuleData>? GetProcessor(string moduleId);

        /// <summary>
        /// Get enabled module processors based on configuration
        /// </summary>
        IEnumerable<IModuleProcessor<BaseModuleData>> GetEnabledProcessors();

        /// <summary>
        /// Get module processor for a specific data type
        /// </summary>
        IModuleProcessor<T>? GetProcessor<T>() where T : BaseModuleData;
    }

    public class ModuleProcessorFactory : IModuleProcessorFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<ModuleProcessorFactory> _logger;
        private readonly Dictionary<string, Type> _processorTypes;
        private readonly Dictionary<Type, Type> _dataTypeToProcessorType;

        public ModuleProcessorFactory(IServiceProvider serviceProvider, ILogger<ModuleProcessorFactory> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            
            // Register all module processor types
            _processorTypes = new Dictionary<string, Type>
            {
                ["applications"] = typeof(ApplicationsModuleProcessor),
                ["display"] = typeof(DisplayModuleProcessor),
                ["hardware"] = typeof(HardwareModuleProcessor),
                ["inventory"] = typeof(InventoryModuleProcessor),
                ["installs"] = typeof(InstallsModuleProcessor),
                ["management"] = typeof(ManagementModuleProcessor),
                ["network"] = typeof(NetworkModuleProcessor),
                ["printer"] = typeof(PrinterModuleProcessor),
                ["profiles"] = typeof(ProfilesModuleProcessor),
                ["security"] = typeof(SecurityModuleProcessor),
                ["system"] = typeof(SystemModuleProcessor)
            };

            // Register data type to processor type mappings
            _dataTypeToProcessorType = new Dictionary<Type, Type>
            {
                [typeof(ApplicationsData)] = typeof(ApplicationsModuleProcessor),
                [typeof(DisplayData)] = typeof(DisplayModuleProcessor),
                [typeof(HardwareData)] = typeof(HardwareModuleProcessor),
                [typeof(InventoryData)] = typeof(InventoryModuleProcessor),
                [typeof(InstallsData)] = typeof(InstallsModuleProcessor),
                [typeof(ManagementData)] = typeof(ManagementModuleProcessor),
                [typeof(NetworkData)] = typeof(NetworkModuleProcessor),
                [typeof(PrinterData)] = typeof(PrinterModuleProcessor),
                [typeof(ProfilesData)] = typeof(ProfilesModuleProcessor),
                [typeof(SecurityData)] = typeof(SecurityModuleProcessor),
                [typeof(SystemData)] = typeof(SystemModuleProcessor)
            };
        }

        public IEnumerable<IModuleProcessor<BaseModuleData>> GetAllProcessors()
        {
            var processors = new List<IModuleProcessor<BaseModuleData>>();

            foreach (var processorType in _processorTypes.Values)
            {
                try
                {
                    var processor = _serviceProvider.GetService(processorType);
                    if (processor != null)
                    {
                        // Create a wrapper that implements IModuleProcessor<BaseModuleData>
                        var wrapper = new ModuleProcessorWrapper(processor);
                        processors.Add(wrapper);
                        _logger.LogDebug("Created processor wrapper for type {ProcessorType}", processorType.Name);
                    }
                    else
                    {
                        _logger.LogWarning("Failed to create processor of type {ProcessorType}", processorType.Name);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error creating processor of type {ProcessorType}", processorType.Name);
                }
            }

            _logger.LogInformation("Created {ProcessorCount} processor wrappers", processors.Count);
            return processors;
        }

        public IModuleProcessor<BaseModuleData>? GetProcessor(string moduleId)
        {
            if (!_processorTypes.TryGetValue(moduleId, out var processorType))
            {
                _logger.LogWarning("No processor found for module ID: {ModuleId}", moduleId);
                return null;
            }

            try
            {
                var processor = _serviceProvider.GetService(processorType);
                if (processor != null)
                {
                    return new ModuleProcessorWrapper(processor);
                }
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating processor for module {ModuleId}", moduleId);
                return null;
            }
        }

        public IEnumerable<IModuleProcessor<BaseModuleData>> GetEnabledProcessors()
        {
            // For now, return all processors. In the future, this could be configured
            // via configuration files or module enable/disable settings.
            var enabledModules = new[]
            {
                "applications",
                "display",
                "hardware", 
                "inventory",
                "installs",
                "management",
                "network",
                "printer",
                "profiles",
                "security",
                "system"
            };

            return enabledModules
                .Select(GetProcessor)
                .Where(p => p != null)
                .Cast<IModuleProcessor<BaseModuleData>>();
        }

        public IModuleProcessor<T>? GetProcessor<T>() where T : BaseModuleData
        {
            if (!_dataTypeToProcessorType.TryGetValue(typeof(T), out var processorType))
            {
                _logger.LogWarning("No processor found for data type: {DataType}", typeof(T).Name);
                return null;
            }

            try
            {
                return _serviceProvider.GetService(processorType) as IModuleProcessor<T>;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating processor for data type {DataType}", typeof(T).Name);
                return null;
            }
        }
    }

    /// <summary>
    /// Wrapper to convert typed module processors to IModuleProcessor<BaseModuleData>
    /// </summary>
    internal class ModuleProcessorWrapper : IModuleProcessor<BaseModuleData>
    {
        private readonly object _processor;
        private readonly Type _processorType;
        private readonly MethodInfo _processMethod;
        private readonly MethodInfo _validateMethod;
        private readonly MethodInfo _generateEventsMethod;

        public string ModuleId { get; }

        public ModuleProcessorWrapper(object processor)
        {
            _processor = processor ?? throw new ArgumentNullException(nameof(processor));
            _processorType = processor.GetType();

            // Get the ModuleId property
            var moduleIdProperty = _processorType.GetProperty("ModuleId");
            ModuleId = moduleIdProperty?.GetValue(processor)?.ToString() ?? "unknown";

            // Get the ProcessModuleAsync method
            _processMethod = _processorType.GetMethod("ProcessModuleAsync") 
                ?? throw new InvalidOperationException($"ProcessModuleAsync method not found on {_processorType.Name}");

            // Get the ValidateModuleDataAsync method
            _validateMethod = _processorType.GetMethod("ValidateModuleDataAsync")
                ?? throw new InvalidOperationException($"ValidateModuleDataAsync method not found on {_processorType.Name}");

            // Get the GenerateEventsAsync method
            _generateEventsMethod = _processorType.GetMethod("GenerateEventsAsync")
                ?? throw new InvalidOperationException($"GenerateEventsAsync method not found on {_processorType.Name}");
        }

        public async Task<BaseModuleData> ProcessModuleAsync(
            Dictionary<string, List<Dictionary<string, object>>> osqueryResults,
            string deviceId)
        {
            try
            {
                var result = _processMethod.Invoke(_processor, new object[] { osqueryResults, deviceId });
                
                if (result is Task task)
                {
                    await task;
                    var resultProperty = task.GetType().GetProperty("Result");
                    return (BaseModuleData)resultProperty?.GetValue(task)!;
                }
                
                return (BaseModuleData)result!;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error invoking ProcessModuleAsync on {_processorType.Name}", ex);
            }
        }

        public async Task<bool> ValidateModuleDataAsync(BaseModuleData data)
        {
            try
            {
                var result = _validateMethod.Invoke(_processor, new object[] { data });
                
                if (result is Task<bool> task)
                {
                    return await task;
                }
                
                return (bool)result!;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error invoking ValidateModuleDataAsync on {_processorType.Name}", ex);
            }
        }

        public async Task<List<ReportMateEvent>> GenerateEventsAsync(BaseModuleData data)
        {
            try
            {
                var result = _generateEventsMethod.Invoke(_processor, new object[] { data });
                
                if (result is Task<List<ReportMateEvent>> task)
                {
                    return await task;
                }
                
                return (List<ReportMateEvent>)result!;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error invoking GenerateEventsAsync on {_processorType.Name}", ex);
            }
        }

        public string GetCacheFilePath(string cacheDirectory, string deviceId)
        {
            // Use reflection to call the method on the wrapped processor
            var method = _processorType.GetMethod("GetCacheFilePath");
            if (method != null)
            {
                return (string)method.Invoke(_processor, new object[] { cacheDirectory, deviceId })!;
            }
            
            // Fallback implementation
            return Path.Combine(cacheDirectory, $"{ModuleId}_{deviceId}.json");
        }
    }
}
