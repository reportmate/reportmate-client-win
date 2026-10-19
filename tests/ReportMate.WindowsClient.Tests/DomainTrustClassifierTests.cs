#nullable enable
using System;
using System.Text.Json;
using ReportMate.WindowsClient.Models;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class DomainTrustClassifierTests
    {
        private static readonly DomainTrustEvidence ChannelDownDcUp = new()
        {
            SecureChannelValid = false,
            DcFound = true,
            ScQueryStatus = "NERR_Success",
            MachineKerberos = true,
        };

        [Fact]
        public void Passing_secure_channel_is_healthy()
        {
            var e = new DomainTrustEvidence { SecureChannelValid = true, DcFound = true, ScQueryStatus = "NERR_Success" };
            Assert.Equal(DomainTrustStatus.Healthy, DomainTrustClassifier.Classify(e));
            Assert.False(DomainTrustClassifier.ShouldAttemptRepair(e));
        }

        // A laptop off the corporate network: Test-ComputerSecureChannel says False, but
        // that is the network, not the trust.
        [Fact]
        public void No_dc_found_is_unreachable_not_broken()
        {
            var e = new DomainTrustEvidence { SecureChannelValid = false, DcFound = false, MachineKerberos = false };
            Assert.Equal(DomainTrustStatus.Unreachable, DomainTrustClassifier.Classify(e));
            Assert.False(DomainTrustClassifier.IsDcReachable(e));
            Assert.False(DomainTrustClassifier.ShouldAttemptRepair(e));
        }

        [Fact]
        public void No_logon_servers_without_kerberos_is_unreachable()
        {
            var e = new DomainTrustEvidence
            {
                SecureChannelValid = false,
                DcFound = true,
                ScQueryStatus = "ERROR_NO_LOGON_SERVERS",
                MachineKerberos = false,
            };
            Assert.Equal(DomainTrustStatus.Unreachable, DomainTrustClassifier.Classify(e));
        }

        // A lab workstation whose Netlogon channel dropped at a patch reboot: Netlogon
        // reports no logon servers, yet the machine still gets Kerberos tickets.
        [Fact]
        public void No_logon_servers_with_kerberos_is_reachable_and_repairable()
        {
            var e = ChannelDownDcUp with { ScQueryStatus = "ERROR_NO_LOGON_SERVERS" };
            Assert.True(DomainTrustClassifier.IsDcReachable(e));
            Assert.True(DomainTrustClassifier.ShouldAttemptRepair(e));
        }

        [Fact]
        public void Channel_down_with_kerberos_working_is_degraded_until_repaired()
        {
            Assert.True(DomainTrustClassifier.ShouldAttemptRepair(ChannelDownDcUp));
            Assert.Equal(DomainTrustStatus.Degraded, DomainTrustClassifier.Classify(ChannelDownDcUp));
        }

        [Fact]
        public void Successful_repair_is_healthy_and_flagged_repaired()
        {
            var e = ChannelDownDcUp with
            {
                RepairAttempted = true,
                ScVerifyStatus = "NERR_Success",
                SecureChannelValidAfterRepair = true,
            };
            Assert.Equal(DomainTrustStatus.Healthy, DomainTrustClassifier.Classify(e));
            Assert.True(DomainTrustClassifier.Repaired(e));
        }

        [Fact]
        public void Failed_repair_with_kerberos_working_stays_degraded()
        {
            var e = ChannelDownDcUp with
            {
                RepairAttempted = true,
                ScVerifyStatus = "ERROR_NO_LOGON_SERVERS",
                SecureChannelValidAfterRepair = false,
            };
            Assert.Equal(DomainTrustStatus.Degraded, DomainTrustClassifier.Classify(e));
            Assert.False(DomainTrustClassifier.Repaired(e));
        }

        [Fact]
        public void Repair_reporting_a_trust_error_is_broken()
        {
            var e = ChannelDownDcUp with
            {
                RepairAttempted = true,
                ScVerifyStatus = "ERROR_NO_TRUST_SAM_ACCOUNT",
                SecureChannelValidAfterRepair = false,
            };
            Assert.Equal(DomainTrustStatus.Broken, DomainTrustClassifier.Classify(e));
        }

        [Fact]
        public void Dc_reachable_channel_down_and_kerberos_failing_is_broken()
        {
            var e = ChannelDownDcUp with { MachineKerberos = false };
            Assert.Equal(DomainTrustStatus.Broken, DomainTrustClassifier.Classify(e));
            Assert.False(DomainTrustClassifier.ShouldAttemptRepair(e));
        }

        [Fact]
        public void Kerberos_check_that_gave_no_answer_is_never_broken()
        {
            var e = ChannelDownDcUp with { MachineKerberos = null };
            Assert.Equal(DomainTrustStatus.Unknown, DomainTrustClassifier.Classify(e));
            Assert.False(DomainTrustClassifier.ShouldAttemptRepair(e));
        }

        [Fact]
        public void Probe_failure_is_unknown_never_broken()
        {
            var e = new DomainTrustEvidence { ProbeFailed = true, SecureChannelValid = false, DcFound = true, MachineKerberos = false };
            Assert.Equal(DomainTrustStatus.Unknown, DomainTrustClassifier.Classify(e));
        }

        [Fact]
        public void Secure_channel_test_with_no_answer_is_unknown_when_a_dc_answers()
        {
            var e = ChannelDownDcUp with { SecureChannelValid = null };
            Assert.Equal(DomainTrustStatus.Unknown, DomainTrustClassifier.Classify(e));
            Assert.False(DomainTrustClassifier.ShouldAttemptRepair(e));
        }

        [Fact]
        public void Repair_is_throttled_to_once_per_six_hours()
        {
            var now = new DateTime(2026, 10, 19, 12, 0, 0, DateTimeKind.Utc);
            Assert.True(DomainTrustClassifier.RepairAllowed(null, now));
            Assert.False(DomainTrustClassifier.RepairAllowed(now.AddHours(-5), now));
            Assert.True(DomainTrustClassifier.RepairAllowed(now.AddHours(-6), now));
            // A stamp from the future (clock moved back) must not block repairs forever.
            Assert.True(DomainTrustClassifier.RepairAllowed(now.AddHours(3), now));
        }

        [Fact]
        public void Sc_query_status_is_parsed()
        {
            const string ok = "Flags: 30 HAS_IP  HAS_TIMESERV\r\nTrusted DC Name \\\\dc01.example.test\r\nTrusted DC Connection Status Status = 0 0x0 NERR_Success\r\nThe command completed successfully\r\n";
            const string down = "Flags: 0\r\nTrusted DC Name\r\nTrusted DC Connection Status Status = 1311 0x51f ERROR_NO_LOGON_SERVERS\r\nThe command completed successfully\r\n";
            const string failed = "I_NetLogonControl failed: Status = 1311 0x51f ERROR_NO_LOGON_SERVERS\r\n";

            Assert.Equal("NERR_Success", DomainTrustClassifier.ParseScQuery(ok));
            Assert.Equal("ERROR_NO_LOGON_SERVERS", DomainTrustClassifier.ParseScQuery(down));
            Assert.Equal("ERROR_NO_LOGON_SERVERS", DomainTrustClassifier.ParseScQuery(failed));
            Assert.True(DomainTrustClassifier.IsNoLogonServers(DomainTrustClassifier.ParseScQuery(failed)));
            Assert.Null(DomainTrustClassifier.ParseScQuery(""));
        }

        [Fact]
        public void Sc_verify_prefers_the_trust_verification_status()
        {
            const string output = "Flags: b0 HAS_IP  HAS_TIMESERV\r\nTrusted DC Name \\\\dc01.example.test\r\nTrusted DC Connection Status Status = 0 0x0 NERR_Success\r\nTrust Verification Status = 1787 0x6fb ERROR_NO_TRUST_SAM_ACCOUNT\r\nThe command completed successfully\r\n";
            var status = DomainTrustClassifier.ParseScVerify(output);
            Assert.Equal("ERROR_NO_TRUST_SAM_ACCOUNT", status);
            Assert.True(DomainTrustClassifier.IsTrustFailure(status));
        }

        [Fact]
        public void Dsgetdc_returns_the_dc_name_or_null()
        {
            const string found = "           DC: \\\\dc01.example.test\r\n      Address: \\\\192.0.2.10\r\n     Dom Name: example.test\r\nThe command completed successfully\r\n";
            const string missing = "Getting DC name failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN\r\n";
            Assert.Equal("dc01.example.test", DomainTrustClassifier.ParseDsGetDc(found));
            Assert.Null(DomainTrustClassifier.ParseDsGetDc(missing));
            Assert.Null(DomainTrustClassifier.ParseDsGetDc(null));
        }

        [Fact]
        public void Klist_ticket_retrieval_is_parsed()
        {
            const string ok = "Current LogonId is 0:0x3e7\r\nA ticket to krbtgt/EXAMPLE.TEST has been retrieved successfully.\r\n\r\nCached Tickets: (1)\r\n#0>\tClient: HOST$ @ EXAMPLE.TEST\r\n\tServer: krbtgt/EXAMPLE.TEST @ EXAMPLE.TEST\r\n";
            const string fail = "Current LogonId is 0:0x3e7\r\nError calling API LsaCallAuthenticationPackage (GetTicket substatus): 0x51f\r\n\r\nklist failed with 0xc000005e/-1073741730: There are currently no logon servers available to service the logon request.\r\n";
            Assert.True(DomainTrustClassifier.ParseKlistKrbtgt(ok, 0));
            Assert.False(DomainTrustClassifier.ParseKlistKrbtgt(fail, 1));
            Assert.Null(DomainTrustClassifier.ParseKlistKrbtgt(null, null));
        }

        [Fact]
        public void Dsreg_domain_joined_is_tri_state()
        {
            Assert.True(DomainTrustClassifier.ParseDsregDomainJoined("     AzureAdJoined : YES\r\n  EnterpriseJoined : NO\r\n      DomainJoined : YES\r\n        DomainName : EXAMPLE\r\n"));
            Assert.False(DomainTrustClassifier.ParseDsregDomainJoined("      DomainJoined : NO\r\n"));
            Assert.Null(DomainTrustClassifier.ParseDsregDomainJoined("  EnterpriseJoined : NO\r\n"));
            Assert.Null(DomainTrustClassifier.ParseDsregDomainJoined(null));
        }

        [Theory]
        [InlineData(true, null, true)]
        [InlineData(null, true, true)]
        [InlineData(false, true, true)]
        [InlineData(true, false, true)]
        [InlineData(false, false, false)]
        [InlineData(false, null, false)]
        [InlineData(null, false, false)]
        [InlineData(null, null, null)]
        public void Either_witness_saying_joined_wins_and_no_answer_stays_unknown(bool? wmi, bool? dsreg, bool? expected)
        {
            Assert.Equal(expected, DomainTrustClassifier.CombineJoinState(wmi, dsreg));
        }

        // Null fields are omitted, so an unknown join state or channel test simply drops the
        // key, which every existing reader already treats like the old default.
        [Fact]
        public void Unknown_join_state_and_channel_result_are_omitted_from_the_payload()
        {
            var data = new IdentityData();
            data.DirectoryServices.ActiveDirectory.IsDomainJoined = null;
            data.DomainTrust.SecureChannelValid = null;

            var json = JsonSerializer.Serialize(data, ReportMateJsonContext.Default.IdentityData);
            using var doc = JsonDocument.Parse(json);
            var ad = doc.RootElement.GetProperty("directoryServices").GetProperty("activeDirectory");
            Assert.False(ad.TryGetProperty("isDomainJoined", out _));
            Assert.False(doc.RootElement.GetProperty("domainTrust").TryGetProperty("secureChannelValid", out _));
            Assert.True(doc.RootElement.GetProperty("domainTrust").TryGetProperty("repairAttempted", out _));
        }
    }
}
