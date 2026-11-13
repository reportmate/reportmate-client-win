using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class SystemBinaryInventoryTests
    {
        [Theory]
        [InlineData("3.12.4150.1013", "3.12.4150.1013")]
        [InlineData("2.47.1.windows.1", "2.47.1.windows.1")]
        [InlineData(" 2.4.62 ", "2.4.62")]
        [InlineData("OpenSSH_for_Windows_9.5p1", "9.5p1")]
        [InlineData("", null)]
        [InlineData(null, null)]
        public void NormalizesVersionResourceStrings(string? raw, string? expected)
        {
            Assert.Equal(expected, SystemBinaryInventory.NormalizeVersion(raw));
        }

        [Theory]
        [InlineData("\"C:\\Apache24\\bin\\httpd.exe\" -k runservice", "C:\\Apache24\\bin\\httpd.exe")]
        [InlineData("C:\\nginx\\nginx.exe -p C:\\nginx", "C:\\nginx\\nginx.exe")]
        [InlineData("", null)]
        public void ReadsTheExecutableFromAServiceImagePath(string imagePath, string? expected)
        {
            Assert.Equal(expected, SystemBinaryInventory.ServiceExecutable(imagePath));
        }

        [Fact]
        public void TheDeepestInstallFolderOwnsTheBinary()
        {
            var products = new[]
            {
                ("C:\\Program Files\\", "Too broad", (string?)"1"),
                ("C:\\Program Files\\Git", "Git", "2.47.1"),
                ("C:\\Program Files\\Git\\mingw64", "Nested", "1"),
            };
            Assert.Equal(("Nested", (string?)"1"), SystemBinaryInventory.OwningProduct("C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe", products));
            Assert.Equal(("Git", (string?)"2.47.1"), SystemBinaryInventory.OwningProduct("C:\\Program Files\\Git\\cmd\\git.exe", products));
            Assert.Null(SystemBinaryInventory.OwningProduct("D:\\tools\\node.exe", products));
        }
    }
}
