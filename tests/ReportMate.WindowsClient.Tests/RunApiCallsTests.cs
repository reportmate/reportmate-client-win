using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using ReportMate.WindowsClient.Configuration;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;
using Xunit;

namespace ReportMate.WindowsClient.Tests;

/// <summary>
/// What a scheduled run asks of the API.
///
/// A device credential may be an ingest-only API key, which the API refuses on every
/// read route. The runner used to check its registration with GET /api/v1/device/{id}
/// before sending, so every run on such a device logged a 403 error. The submission to
/// /api/v1/events creates the device on its own, so a run sends the payload and nothing
/// else.
/// </summary>
public class RunApiCallsTests
{
    [Fact]
    public async Task RunSendsThePayloadAndMakesNoOtherApiCall()
    {
        var api = new RecordingApiService();
        var service = new DataCollectionService(
            NullLogger<DataCollectionService>.Instance,
            new ConfigurationBuilder().Build(),
            new UnusedDeviceInfoService(),
            api,
            new ValidConfigurationService(),
            new StubModularDataCollectionService());

        var result = await service.CollectAndSendDataAsync(forceCollection: true);

        Assert.True(result);
        Assert.Equal(new[] { nameof(IApiService.SendUnifiedPayloadAsync) }, api.Calls);
    }

    private sealed class RecordingApiService : IApiService
    {
        public List<string> Calls { get; } = new();

        public Task<bool> SendDeviceDataAsync(DeviceDataRequest deviceData)
        {
            Calls.Add(nameof(SendDeviceDataAsync));
            return Task.FromResult(true);
        }

        public Task<bool> SendUnifiedPayloadAsync(UnifiedDevicePayload payload)
        {
            Calls.Add(nameof(SendUnifiedPayloadAsync));
            return Task.FromResult(true);
        }

        public Task<bool> TestConnectivityAsync()
        {
            Calls.Add(nameof(TestConnectivityAsync));
            return Task.FromResult(true);
        }
    }

    private sealed class ValidConfigurationService : IConfigurationService
    {
        public Task<ConfigurationValidationResult> ValidateConfigurationAsync()
            => Task.FromResult(new ConfigurationValidationResult { IsValid = true });

        public Task<CurrentConfiguration> GetCurrentConfigurationAsync()
            => throw new NotSupportedException();

        public Task InstallConfigurationAsync() => throw new NotSupportedException();

        public Task UpdateLastRunTimeAsync() => Task.CompletedTask;

        public Task<bool> IsRecentRunAsync() => Task.FromResult(false);
    }

    private sealed class UnusedDeviceInfoService : IDeviceInfoService
    {
        public Task<DeviceInfo> GetBasicDeviceInfoAsync() => throw new NotSupportedException();

        public Task<Dictionary<string, object>> GetComprehensiveDeviceDataAsync()
            => throw new NotSupportedException();
    }

    private sealed class StubModularDataCollectionService : IModularDataCollectionService
    {
        public Task<UnifiedDevicePayload> CollectAllModuleDataAsync()
            => Task.FromResult(new UnifiedDevicePayload
            {
                Metadata = new EventMetadata { DeviceId = "TEST-DEVICE", SerialNumber = "TEST-SERIAL" }
            });

        public Task<T?> CollectModuleDataAsync<T>(string moduleId) where T : BaseModuleData
            => throw new NotSupportedException();

        public Task<BaseModuleData?> CollectSingleModuleDataAsync(string moduleId)
            => throw new NotSupportedException();

        public Task<UnifiedDevicePayload> CreateSingleModuleUnifiedPayloadAsync(BaseModuleData moduleData)
            => throw new NotSupportedException();

        public Task<UnifiedDevicePayload> CreateUnifiedPayloadAsync(IReadOnlyList<BaseModuleData> modules)
            => throw new NotSupportedException();

        public Task<UnifiedDevicePayload> CreateHelloPayloadAsync() => throw new NotSupportedException();

        public Task SaveModuleDataLocallyAsync<T>(string moduleId, T data) where T : BaseModuleData
            => throw new NotSupportedException();

        public Task<UnifiedDevicePayload> LoadCachedDataAsync() => throw new NotSupportedException();

        public Task<bool> ValidateModuleDataAsync(string moduleId, object data)
            => throw new NotSupportedException();
    }
}
