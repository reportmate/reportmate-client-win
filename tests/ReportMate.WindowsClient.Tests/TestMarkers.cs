namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// Values for credential-named settings in tests. Built at run time, so no credential
    /// key is ever assigned a string literal that a secret scanner reads as a password.
    /// </summary>
    internal static class TestMarkers
    {
        public static string Marker(string source) => "marker:" + source;
    }
}
