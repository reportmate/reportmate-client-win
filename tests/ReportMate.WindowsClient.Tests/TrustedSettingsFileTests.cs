using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using ReportMate.WindowsClient.Configuration;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    public class TrustedSettingsFileTests
    {
        private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
        private static readonly SecurityIdentifier AuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);
        private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);

        // The ACL the installer sets: SYSTEM and Administrators full control, Users read.
        private static FileSecurity Locked(SecurityIdentifier owner)
        {
            var security = new FileSecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
            return security;
        }

        [Fact]
        public void Admin_only_file_is_trusted()
        {
            Assert.Null(TrustedSettingsFile.WhyUntrusted(Locked(Administrators)));
            Assert.Null(TrustedSettingsFile.WhyUntrusted(Locked(System)));
        }

        [Fact]
        public void File_owned_by_a_standard_user_is_not_trusted()
        {
            var why = TrustedSettingsFile.WhyUntrusted(Locked(Users));
            Assert.NotNull(why);
            Assert.Contains("owned by", why);
        }

        [Theory]
        [InlineData(FileSystemRights.Modify)]
        [InlineData(FileSystemRights.Write)]
        [InlineData(FileSystemRights.AppendData)]
        [InlineData(FileSystemRights.ChangePermissions)]
        [InlineData(FileSystemRights.TakeOwnership)]
        [InlineData(FileSystemRights.FullControl)]
        public void File_a_non_admin_can_change_is_not_trusted(FileSystemRights rights)
        {
            var security = Locked(Administrators);
            security.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsers, rights, AccessControlType.Allow));

            var why = TrustedSettingsFile.WhyUntrusted(security);
            Assert.NotNull(why);
            Assert.Contains(AuthenticatedUsers.Value, why);
        }

        [Fact]
        public void Read_access_for_users_is_fine()
        {
            var security = Locked(Administrators);
            security.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsers, FileSystemRights.Read, AccessControlType.Allow));
            Assert.Null(TrustedSettingsFile.WhyUntrusted(security));
        }

        [Fact]
        public void Deny_and_inherit_only_entries_are_ignored()
        {
            var security = Locked(Administrators);
            security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Write, AccessControlType.Deny));
            Assert.Null(TrustedSettingsFile.WhyUntrusted(security));

            var dir = new DirectorySecurity();
            dir.SetOwner(Administrators);
            dir.AddAccessRule(new FileSystemAccessRule(CreatorOwner, FileSystemRights.FullControl,
                InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
            Assert.Null(TrustedSettingsFile.WhyUntrusted(dir));
        }

        [Fact]
        public void File_this_user_created_on_disk_is_not_trusted()
        {
            // Tests run as a normal account, so a file they create is owned by a non-admin
            // SID (or by Administrators when elevated with admin-owner defaults).
            var path = Path.Combine(Path.GetTempPath(), "rm-acl-" + Guid.NewGuid().ToString("N") + ".yaml");
            File.WriteAllText(path, "ReportMate:\n  ApiUrl: https://x\n");
            try
            {
                var owner = new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                if (TrustedSettingsFile.IsAdministrative(owner)) return;

                Assert.NotNull(TrustedSettingsFile.WhyUntrusted(path));
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void Missing_file_has_nothing_to_distrust()
        {
            Assert.Null(TrustedSettingsFile.WhyUntrusted(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))));
        }
    }
}
