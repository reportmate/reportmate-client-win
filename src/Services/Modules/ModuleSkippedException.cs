#nullable enable
using System;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>A module chose not to collect on this run. This is expected and is not a failure.</summary>
    public sealed class ModuleSkippedException : Exception
    {
        public ModuleSkippedException(string message) : base(message) { }
    }
}
