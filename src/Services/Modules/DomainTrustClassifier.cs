#nullable enable
using System;
using System.Text.RegularExpressions;

namespace ReportMate.WindowsClient.Services.Modules
{
    /// <summary>
    /// The values <c>domainTrust.trustStatus</c> can take.
    /// </summary>
    public static class DomainTrustStatus
    {
        /// <summary>The secure channel test passed, either as found or after a repair.</summary>
        public const string Healthy = "Healthy";

        /// <summary>
        /// A domain controller answers and the machine still gets Kerberos tickets, but the
        /// Netlogon secure channel is down and a repair did not bring it back (or was throttled).
        /// </summary>
        public const string Degraded = "Degraded";

        /// <summary>
        /// A domain controller answers, the secure channel fails, and the machine cannot get
        /// Kerberos tickets either, or the channel reset reported a password or trust error.
        /// This is the only state that means the computer account needs attention.
        /// </summary>
        public const string Broken = "Broken";

        /// <summary>No domain controller could be reached, so the trust could not be tested.</summary>
        public const string Unreachable = "Unreachable";

        /// <summary>The checks did not produce an answer.</summary>
        public const string Unknown = "Unknown";

        /// <summary>The device is not joined to an on-premises domain.</summary>
        public const string NotApplicable = "Not Applicable";
    }

    /// <summary>
    /// What the trust checks found on one run. Every nullable field is null when its check
    /// could not run or gave no answer, which is different from the check failing.
    /// </summary>
    public sealed record DomainTrustEvidence
    {
        /// <summary>Test-ComputerSecureChannel before any repair.</summary>
        public bool? SecureChannelValid { get; init; }

        /// <summary>Whether a forced DC locator query (nltest /dsgetdc /force) returned a DC.</summary>
        public bool DcFound { get; init; }

        /// <summary>Symbolic status from nltest /sc_query, e.g. NERR_Success or ERROR_NO_LOGON_SERVERS.</summary>
        public string? ScQueryStatus { get; init; }

        /// <summary>Whether the machine account could obtain a krbtgt ticket.</summary>
        public bool? MachineKerberos { get; init; }

        /// <summary>Whether nltest /sc_verify was run this time.</summary>
        public bool RepairAttempted { get; init; }

        /// <summary>Symbolic status from nltest /sc_verify, when it was run.</summary>
        public string? ScVerifyStatus { get; init; }

        /// <summary>Test-ComputerSecureChannel after the repair, when one was attempted.</summary>
        public bool? SecureChannelValidAfterRepair { get; init; }

        /// <summary>The collector itself failed, so none of the evidence can be trusted.</summary>
        public bool ProbeFailed { get; init; }
    }

    /// <summary>
    /// Turns the evidence from the trust checks into a status, and decides whether a
    /// secure-channel repair is warranted. Kept free of I/O so it can be tested directly.
    /// </summary>
    /// <remarks>
    /// Test-ComputerSecureChannel returning False only says the Netlogon secure channel is
    /// down. A workstation whose channel dropped at a patch reboot (no DC answered at that
    /// moment) keeps getting Kerberos tickets and works normally, yet the old classifier
    /// called it Broken, as it did every laptop off the corporate network. Broken is now
    /// reserved for a DC that answers but refuses the machine.
    /// </remarks>
    public static class DomainTrustClassifier
    {
        /// <summary>Repairs are attempted at most once in this window.</summary>
        public static readonly TimeSpan RepairInterval = TimeSpan.FromHours(6);

        private static readonly string[] TrustFailureStatuses =
        {
            "ERROR_NO_TRUST_SAM_ACCOUNT",
            "ERROR_NO_TRUST_LSA_SECRET",
            "ERROR_TRUSTED_RELATIONSHIP_FAILURE",
            "ERROR_TRUSTED_DOMAIN_FAILURE",
            "ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT",
            "ERROR_ACCESS_DENIED",
            "ERROR_WRONG_PASSWORD",
            "ERROR_LOGON_FAILURE",
            "STATUS_ACCESS_DENIED",
            "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
            "STATUS_NO_TRUST_SAM_ACCOUNT",
        };

        /// <summary>
        /// A DC is reachable when the locator finds one, unless Netlogon reports no logon
        /// servers and the machine cannot get a Kerberos ticket either.
        /// </summary>
        public static bool IsDcReachable(DomainTrustEvidence e) =>
            e.DcFound && !(IsNoLogonServers(e.ScQueryStatus) && e.MachineKerberos != true);

        /// <summary>
        /// Only a channel that is down while a DC answers and Kerberos still works is worth
        /// re-establishing: the machine password is evidently still good.
        /// </summary>
        public static bool ShouldAttemptRepair(DomainTrustEvidence e) =>
            !e.ProbeFailed
            && e.SecureChannelValid == false
            && IsDcReachable(e)
            && e.MachineKerberos == true;

        /// <summary>Whether enough time has passed since the last repair attempt.</summary>
        public static bool RepairAllowed(DateTime? lastAttemptUtc, DateTime nowUtc)
        {
            if (lastAttemptUtc is null) return true;
            // A stamp from the future (clock moved back) must not block repairs forever.
            if (lastAttemptUtc.Value > nowUtc) return true;
            return nowUtc - lastAttemptUtc.Value >= RepairInterval;
        }

        public static bool Repaired(DomainTrustEvidence e) =>
            e.RepairAttempted && e.SecureChannelValid != true && e.SecureChannelValidAfterRepair == true;

        public static string Classify(DomainTrustEvidence e)
        {
            if (e.ProbeFailed) return DomainTrustStatus.Unknown;
            if (e.SecureChannelValid == true) return DomainTrustStatus.Healthy;
            if (Repaired(e)) return DomainTrustStatus.Healthy;
            if (!IsDcReachable(e)) return DomainTrustStatus.Unreachable;
            if (e.SecureChannelValid is null) return DomainTrustStatus.Unknown;
            if (e.RepairAttempted && IsTrustFailure(e.ScVerifyStatus)) return DomainTrustStatus.Broken;
            return e.MachineKerberos switch
            {
                true => DomainTrustStatus.Degraded,
                false => DomainTrustStatus.Broken,
                null => DomainTrustStatus.Unknown,
            };
        }

        public static bool IsNoLogonServers(string? status) =>
            !string.IsNullOrEmpty(status)
            && (status.Equals("ERROR_NO_LOGON_SERVERS", StringComparison.OrdinalIgnoreCase)
                || status.Equals("STATUS_NO_LOGON_SERVERS", StringComparison.OrdinalIgnoreCase)
                || status == "1311");

        public static bool IsTrustFailure(string? status)
        {
            if (string.IsNullOrEmpty(status)) return false;
            foreach (var s in TrustFailureStatuses)
            {
                if (status.Equals(s, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        // --- nltest / klist output parsing ---

        private static readonly Regex DcLine =
            new(@"^\s*DC:\s*\\\\(?<dc>\S+)", RegexOptions.Multiline | RegexOptions.IgnoreCase);

        private static readonly Regex FailedStatus =
            new(@"failed:\s*Status\s*=\s*(?<num>-?\d+)\s+0x[0-9a-fA-F]+\s*(?<name>[A-Z_a-z0-9]*)", RegexOptions.IgnoreCase);

        /// <summary>The DC name from <c>nltest /dsgetdc</c>, or null when none was found.</summary>
        public static string? ParseDsGetDc(string? output)
        {
            if (string.IsNullOrWhiteSpace(output)) return null;
            var m = DcLine.Match(output);
            return m.Success ? m.Groups["dc"].Value.Trim() : null;
        }

        /// <summary>The status nltest gives on the line that starts with <paramref name="label"/>.</summary>
        /// <remarks>
        /// <c>/sc_query</c> prints "Trusted DC Connection Status Status = 0 0x0 NERR_Success",
        /// <c>/sc_verify</c> adds "Trust Verification Status = 0 0x0 NERR_Success", and a call
        /// that fails outright prints "I_NetLogonControl failed: Status = 1311 0x51f ERROR_NO_LOGON_SERVERS".
        /// </remarks>
        public static string? ParseNltestStatus(string? output, string label)
        {
            if (string.IsNullOrWhiteSpace(output)) return null;

            var labelled = new Regex(
                Regex.Escape(label) + @"(?:\s+Status)?\s*=\s*(?<num>-?\d+)\s+0x[0-9a-fA-F]+\s*(?<name>[A-Z_a-z0-9]*)",
                RegexOptions.IgnoreCase);
            var m = labelled.Match(output);
            if (!m.Success) m = FailedStatus.Match(output);
            if (!m.Success) return null;

            var name = m.Groups["name"].Value;
            return string.IsNullOrEmpty(name) ? m.Groups["num"].Value : name;
        }

        public static string? ParseScQuery(string? output) =>
            ParseNltestStatus(output, "Trusted DC Connection Status");

        /// <summary>The trust verification status, falling back to the connection status.</summary>
        public static string? ParseScVerify(string? output) =>
            ParseNltestStatus(output, "Trust Verification Status")
            ?? ParseNltestStatus(output, "Trusted DC Connection Status");

        /// <summary>
        /// Whether <c>klist -li 0x3e7 get krbtgt/&lt;domain&gt;</c> produced a ticket for the
        /// machine's logon session. Null when there was no output to judge.
        /// </summary>
        public static bool? ParseKlistKrbtgt(string? output, int? exitCode)
        {
            if (string.IsNullOrWhiteSpace(output)) return exitCode is null ? null : false;

            if (output.Contains("Error calling API", StringComparison.OrdinalIgnoreCase)
                || output.Contains("klist failed", StringComparison.OrdinalIgnoreCase))
                return false;

            if (output.Contains("retrieved successfully", StringComparison.OrdinalIgnoreCase))
                return true;

            return exitCode == 0 && output.Contains("krbtgt/", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>dsregcmd's <c>DomainJoined : YES|NO</c>, or null when the line is absent.</summary>
        public static bool? ParseDsregDomainJoined(string? dsregOutput)
        {
            if (string.IsNullOrEmpty(dsregOutput)) return null;
            var m = Regex.Match(dsregOutput, @"^\s*DomainJoined\s*:\s*(?<v>\w+)", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            if (!m.Success) return null;
            var v = m.Groups["v"].Value;
            if (v.Equals("YES", StringComparison.OrdinalIgnoreCase)) return true;
            if (v.Equals("NO", StringComparison.OrdinalIgnoreCase)) return false;
            return null;
        }

        /// <summary>
        /// Two witnesses to the join: WMI's PartOfDomain and dsregcmd's DomainJoined. Either
        /// one saying yes is enough; it is only "not joined" when one says no and neither says
        /// yes; with no answer from either it stays unknown.
        /// </summary>
        public static bool? CombineJoinState(bool? wmiPartOfDomain, bool? dsregDomainJoined)
        {
            if (wmiPartOfDomain == true || dsregDomainJoined == true) return true;
            if (wmiPartOfDomain == false || dsregDomainJoined == false) return false;
            return null;
        }
    }
}
