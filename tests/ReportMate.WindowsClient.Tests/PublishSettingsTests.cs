#nullable enable
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Xunit;

namespace ReportMate.WindowsClient.Tests
{
    /// <summary>
    /// The runner is published trimmed, and trimming turns off built-in COM interop unless
    /// the project asks for it. System.Management needs it: without it, ManagementPath's
    /// type initializer throws in the released exe while every unit test still passes.
    /// </summary>
    public class PublishSettingsTests
    {
        private static XDocument RunnerProject()
        {
            var dir = new DirectoryInfo(System.AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "src", "ReportMate.WindowsClient.csproj")))
                dir = dir.Parent;
            Assert.NotNull(dir);
            return XDocument.Load(Path.Combine(dir!.FullName, "src", "ReportMate.WindowsClient.csproj"));
        }

        private static string? Property(XDocument project, string name) =>
            project.Descendants(name).Select(e => e.Value.Trim()).LastOrDefault();

        [Fact]
        public void TrimmedRunnerKeepsBuiltInComInteropForWmi()
        {
            var project = RunnerProject();

            if (Property(project, "PublishTrimmed") == "true")
                Assert.Equal("true", Property(project, "BuiltInComInteropSupport"));
        }

        [Fact]
        public void TrimmedRunnerRootsSystemManagement()
        {
            var project = RunnerProject();

            Assert.Contains(project.Descendants("TrimmerRootAssembly"),
                e => (string?)e.Attribute("Include") == "System.Management");
        }
    }
}
