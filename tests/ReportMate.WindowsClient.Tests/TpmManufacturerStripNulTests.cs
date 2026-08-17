#nullable enable
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// Get-Tpm reports ManufacturerIdTxt as a fixed-width 4-byte field padded
    /// with NUL, so Infineon arrives as "IFX\0" and Nuvoton as "NTC\0". The
    /// server stores modules as JSON, which cannot represent that character,
    /// and one bad value failed the write for the entire module — silently,
    /// because the check-in still returned success. 171 machines lost a month
    /// of identity data before anyone noticed, so these pin the strip.
    /// </summary>
    public class TpmManufacturerStripNulTests
    {
        [Theory]
        [InlineData("IFX\0", "IFX")]
        [InlineData("NTC\0", "NTC")]
        [InlineData("IFX\0\0\0", "IFX")]
        [InlineData("\0IFX", "IFX")]
        public void StripsNulPadding(string input, string expected)
        {
            Assert.Equal(expected, IdentityModuleProcessor.StripNul(input));
        }

        [Theory]
        [InlineData("INTC")]
        [InlineData("AMD")]
        [InlineData("")]
        public void LeavesCleanValuesUnchanged(string input)
        {
            Assert.Equal(input, IdentityModuleProcessor.StripNul(input));
        }

        [Fact]
        public void NullBecomesEmpty()
        {
            Assert.Equal(string.Empty, IdentityModuleProcessor.StripNul(null));
        }

        [Fact]
        public void InteriorTextIsPreserved()
        {
            Assert.Equal("AB", IdentityModuleProcessor.StripNul("A\0B"));
        }
    }
}
