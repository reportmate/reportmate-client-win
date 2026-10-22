#nullable enable
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// The API decides which certificates an admin has to act on, and it needs signals
    /// osquery alone does not give: the CA flag and key usage from osquery, and the
    /// private key, friendly name, template and extended key usages that only the
    /// certificate store knows. These pin the mapping and the JSON names the API reads.
    /// </summary>
    public class CertificateMappingTests
    {
        private static readonly DateTime Now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static List<Dictionary<string, object>> Rows()
        {
            var path = Path.Combine(Fixtures.Dir, "osquery-certificates.json");
            var options = new JsonSerializerOptions { ReadCommentHandling = JsonCommentHandling.Skip };
            return JsonSerializer.Deserialize<List<Dictionary<string, object>>>(File.ReadAllText(path), options)!;
        }

        [Fact]
        public void MapsCaFlagAndKeyUsage()
        {
            var rows = Rows();
            var root = SecurityModuleProcessor.MapCertificateRow(rows[0], Now);
            var device = SecurityModuleProcessor.MapCertificateRow(rows[1], Now);
            var legacy = SecurityModuleProcessor.MapCertificateRow(rows[2], Now);

            Assert.True(root.IsCA);
            Assert.Equal("Certificate Sign, CRL Sign", root.KeyUsage);
            Assert.False(device.IsCA);
            Assert.Equal("Digital Signature, Key Encipherment", device.KeyUsage);
            Assert.Null(legacy.IsCA);
            Assert.Null(legacy.KeyUsage);
        }

        [Fact]
        public void KeepsExistingFieldsAndStatus()
        {
            var rows = Rows();
            var root = SecurityModuleProcessor.MapCertificateRow(rows[0], Now);
            var legacy = SecurityModuleProcessor.MapCertificateRow(rows[2], Now);

            Assert.Equal("Root", root.StoreName);
            Assert.Equal("LocalMachine", root.StoreLocation);
            Assert.Equal(4096, root.KeyLength);
            Assert.True(root.IsSelfSigned);
            Assert.True(root.IsOsTrustedRoot);
            Assert.Equal("Valid", root.Status);
            Assert.Equal("Expired", legacy.Status);
            Assert.False(legacy.IsOsTrustedRoot);
        }

        [Theory]
        [InlineData("My", true)]
        [InlineData("Personal", true)]
        [InlineData("personal", true)]
        [InlineData("Root", false)]
        [InlineData("", false)]
        public void RecognisesPersonalStoreNames(string store, bool expected)
        {
            Assert.Equal(expected, SecurityModuleProcessor.IsPersonalStore(store));
        }

        [Theory]
        [InlineData("1", true)]
        [InlineData("0", false)]
        [InlineData("-1", null)]
        [InlineData("", null)]
        public void ParsesOsqueryFlags(string value, bool? expected)
        {
            Assert.Equal(expected, SecurityModuleProcessor.ParseOsqueryFlag(value));
        }

        [Fact]
        public void ReadsTemplateNameKeyAndUsagesFromTheStoreCertificate()
        {
            using var cert = SampleCertificate(includeV1Template: true);
            var info = new CertificateInfo();

            SecurityModuleProcessor.ApplyStoreDetails(info, cert);

            Assert.True(info.HasPrivateKey);
            Assert.Equal("SAMPLEMachine", info.TemplateName);
            Assert.NotNull(info.EnhancedKeyUsages);
            Assert.Contains(info.EnhancedKeyUsages!, u => u == "Client Authentication" || u == "1.3.6.1.5.5.7.3.2");
        }

        [Fact]
        public void FallsBackToTheTemplateInformationOid()
        {
            using var cert = SampleCertificate(includeV1Template: false);

            var template = SecurityModuleProcessor.ReadTemplateName(cert);

            Assert.Equal("1.3.6.1.4.1.311.21.8.1.2.3", template);
        }

        [Fact]
        public void LeavesCertificatesWithoutExtensionsAlone()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=SAMPLE Plain", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
            var info = new CertificateInfo();

            SecurityModuleProcessor.ApplyStoreDetails(info, cert);

            Assert.Null(info.TemplateName);
            Assert.Null(info.EnhancedKeyUsages);
            Assert.Null(info.FriendlyName);
        }

        [Fact]
        public void SerializesNewFieldsInCamelCase()
        {
            var info = SecurityModuleProcessor.MapCertificateRow(Rows()[1], Now);
            info.FriendlyName = "SAMPLE Device Identity";
            info.HasPrivateKey = true;
            info.TemplateName = "SAMPLEMachine";
            info.EnhancedKeyUsages = new List<string> { "Client Authentication" };

            var json = JsonSerializer.Serialize(info, ReportMateJsonContext.Default.CertificateInfo);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            Assert.False(root.GetProperty("isCA").GetBoolean());
            Assert.Equal("Digital Signature, Key Encipherment", root.GetProperty("keyUsage").GetString());
            Assert.Equal("SAMPLE Device Identity", root.GetProperty("friendlyName").GetString());
            Assert.True(root.GetProperty("hasPrivateKey").GetBoolean());
            Assert.Equal("SAMPLEMachine", root.GetProperty("templateName").GetString());
            Assert.Equal("Client Authentication", root.GetProperty("enhancedKeyUsages")[0].GetString());
            Assert.Equal("Personal", root.GetProperty("storeName").GetString());
            Assert.Equal("LocalMachine", root.GetProperty("storeLocation").GetString());
        }

        [Fact]
        public void OmitsStoreFieldsThatWereNeverRead()
        {
            var info = SecurityModuleProcessor.MapCertificateRow(Rows()[0], Now);

            var json = JsonSerializer.Serialize(info, ReportMateJsonContext.Default.CertificateInfo);
            using var doc = JsonDocument.Parse(json);

            Assert.False(doc.RootElement.TryGetProperty("hasPrivateKey", out _));
            Assert.False(doc.RootElement.TryGetProperty("friendlyName", out _));
            Assert.False(doc.RootElement.TryGetProperty("enhancedKeyUsages", out _));
            Assert.False(doc.RootElement.TryGetProperty("class", out _));
            Assert.False(doc.RootElement.TryGetProperty("displayName", out _));
            Assert.False(doc.RootElement.TryGetProperty("issuerName", out _));
            Assert.False(doc.RootElement.TryGetProperty("notAfterEpoch", out _));
            Assert.False(doc.RootElement.TryGetProperty("templateName", out _));
            Assert.True(doc.RootElement.GetProperty("isCA").GetBoolean());
        }

        [Fact]
        public void ReadsApiStampedFieldsBack()
        {
            const string json = "{\"commonName\":\"SAMPLE-DEVICE-01\",\"class\":\"actionable\",\"displayName\":\"SAMPLE-DEVICE-01\",\"issuerName\":\"SAMPLE Issuing CA\",\"notAfterEpoch\":2524608000}";

            var info = JsonSerializer.Deserialize(json, ReportMateJsonContext.Default.CertificateInfo)!;

            Assert.Equal("actionable", info.Class);
            Assert.Equal("SAMPLE-DEVICE-01", info.DisplayName);
            Assert.Equal("SAMPLE Issuing CA", info.IssuerName);
            Assert.Equal(2524608000, info.NotAfterEpoch);
            Assert.Null(info.HasPrivateKey);
            Assert.Null(info.IsCA);
        }

        private static X509Certificate2 SampleCertificate(bool includeV1Template)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=SAMPLE-DEVICE-01", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, critical: false));

            if (includeV1Template)
            {
                var writer = new AsnWriter(AsnEncodingRules.DER);
                writer.WriteCharacterString(UniversalTagNumber.BMPString, "SAMPLEMachine");
                request.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.311.20.2", writer.Encode(), critical: false));
            }

            var info = new AsnWriter(AsnEncodingRules.DER);
            using (info.PushSequence())
            {
                info.WriteObjectIdentifier("1.3.6.1.4.1.311.21.8.1.2.3");
                info.WriteInteger(100);
                info.WriteInteger(4);
            }
            request.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.311.21.7", info.Encode(), critical: false));

            return request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(365));
        }
    }
}
