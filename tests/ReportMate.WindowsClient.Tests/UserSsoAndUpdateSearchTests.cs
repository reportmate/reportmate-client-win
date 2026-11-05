#nullable enable
using System;
using System.Text;
using System.Text.Json;
using ReportMate.WindowsClient.Models.Modules;
using ReportMate.WindowsClient.Services;
using ReportMate.WindowsClient.Services.Modules;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// The SSO State of dsregcmd is per user, and an empty pending-update list is only
    /// evidence of "nothing pending" when the search behind it succeeded. Both used to be
    /// reported as a confident false. The dsregcmd text here is hand-written in the tool's
    /// published layout, not captured from any machine.
    /// </summary>
    public class UserSsoAndUpdateSearchTests
    {
        private const string SignedInUser = @"
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : YES
      AzureAdPrtUpdateTime : 2026-11-04 18:05:09.000 UTC
      AzureAdPrtExpiryTime : 2026-11-18 18:05:08.000 UTC
       AzureAdPrtAuthority : https://login.example.com/00000000-0000-0000-0000-000000000000
             EnterprisePrt : NO
    EnterprisePrtAuthority :
                 OnPremTgt : YES
                  CloudTgt : YES
         KerbTopLevelNames : .example.com

+----------------------------------------------------------------------+
| Diagnostic Data                                                      |
+----------------------------------------------------------------------+

        AadRecoveryEnabled : NO
";

        private const string NoPrt = @"
+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : NO
       AzureAdPrtAuthority :
             EnterprisePrt : NO
    EnterprisePrtAuthority :

+----------------------------------------------------------------------+
| Diagnostic Data                                                      |
+----------------------------------------------------------------------+
";

        [Fact]
        public void ReadsThePrtAndTicketsOfASignedInUser()
        {
            var state = new UserSsoState();

            Assert.True(DsregStatus.ReadSsoState(SignedInUser, state));

            Assert.True(state.EntraPrt);
            Assert.Equal(new DateTime(2026, 11, 4, 18, 5, 9, DateTimeKind.Utc), state.EntraPrtUpdateTime);
            Assert.Equal(new DateTime(2026, 11, 18, 18, 5, 8, DateTimeKind.Utc), state.EntraPrtExpiryTime);
            Assert.Equal(DateTimeKind.Utc, state.EntraPrtExpiryTime!.Value.Kind);
            Assert.False(state.EnterprisePrt);
            Assert.True(state.OnPremTgt);
            Assert.True(state.CloudTgt);
            Assert.StartsWith("https://login.example.com/", state.EntraPrtAuthority);
        }

        [Fact]
        public void TicketsTheToolDidNotPrintAreUnknownNotFalse()
        {
            var state = new UserSsoState();

            Assert.True(DsregStatus.ReadSsoState(NoPrt, state));

            Assert.False(state.EntraPrt);
            Assert.Null(state.EntraPrtExpiryTime);
            Assert.Null(state.EntraPrtAuthority);
            Assert.Null(state.OnPremTgt);
            Assert.Null(state.CloudTgt);
        }

        [Fact]
        public void OutputWithoutAnSsoSectionIsNotRead()
        {
            var state = new UserSsoState();

            Assert.False(DsregStatus.ReadSsoState("| Device State |\n AzureAdJoined : YES\n", state));
            Assert.Null(state.EntraPrt);
        }

        [Fact]
        public void OnlyTheSsoSectionIsRead()
        {
            var sso = DsregStatus.Section(SignedInUser, "SSO State");

            Assert.False(sso.ContainsKey("AzureAdJoined"));
            Assert.False(sso.ContainsKey("AadRecoveryEnabled"));
        }

        [Fact]
        public void DecodesUtf16AndUtf8ToolOutput()
        {
            const string text = "AzureAdPrt : YES";

            Assert.Equal(text, UserSessionProcess.Decode(Encoding.UTF8.GetBytes(text)));
            Assert.Equal(text, UserSessionProcess.Decode(Encoding.Unicode.GetBytes(text)));
        }

        private static UpdateSearchInfo Outcome(string json)
        {
            using var doc = JsonDocument.Parse(json);
            return SystemModuleProcessor.UpdateSearchOutcome(doc.RootElement, new DateTime(2026, 11, 4, 0, 0, 0, DateTimeKind.Utc));
        }

        [Theory]
        [InlineData(2)]
        [InlineData(3)]
        public void ACompletedSearchSucceeded(int code)
        {
            var outcome = Outcome($"{{\"PendingCount\":0,\"Updates\":[],\"ResultCode\":{code}}}");

            Assert.Equal("succeeded", outcome.Status);
            Assert.Null(outcome.Error);
            Assert.NotNull(outcome.CheckedAt);
        }

        [Fact]
        public void AnAgentErrorIsAFailedSearchWithTheError()
        {
            var outcome = Outcome("{\"PendingCount\":0,\"Updates\":[],\"Error\":\"Exception from HRESULT (0x8024402C)\"}");

            Assert.Equal("failed", outcome.Status);
            Assert.Contains("0x8024402C", outcome.Error);
        }

        [Theory]
        [InlineData("{\"PendingCount\":0,\"Updates\":[],\"ResultCode\":4}")]
        [InlineData("{\"PendingCount\":0,\"Updates\":[],\"ResultCode\":5}")]
        [InlineData("{\"PendingCount\":0,\"Updates\":[]}")]
        public void AnythingElseIsAFailedSearch(string json)
        {
            var outcome = Outcome(json);

            Assert.Equal("failed", outcome.Status);
            Assert.False(string.IsNullOrEmpty(outcome.Error));
        }
    }
}
