# ReportMate Windows client wiki

The Windows client collects device inventory and status on Windows endpoints and sends it to the ReportMate API. It runs on its own from scheduled tasks or as a postflight step after Cimian's managed software update, and its reports become one record per device per module that the dashboard, native apps and CLI read.

## Read first

- [Project setup, installation and configuration](../README.md)
- [Build system and packaging](../BUILD.md)
- [Build system guide](../build/guide.md)
- [Deployment guide](../docs/DEPLOYMENT.md)
- [Setup guide](../docs/setup-guide.md)
- [Client authentication](../docs/CLIENT_AUTHENTICATION.md)

## Architecture

The client is a C# console application targeting .NET 10 on Windows. Its project is [ReportMate.WindowsClient.csproj](../src/ReportMate.WindowsClient.csproj) and it builds `managedreportsrunner.exe`. [Program.cs](../src/Program.cs) defines the command line: `run`, `transmit`, `info`, `install`, `build` and `version`, plus options such as `--run-module`, `--collect-only`, `--transmit-only` and `--hello`.

Collection is modular. Each module has a processor in [src/Services/Modules](../src/Services/Modules) and a data model in [src/Models/Modules](../src/Models/Modules). Processors combine osquery results with WMI, registry and PowerShell sources. The osquery queries for each module ship as JSON files in [build/resources/osquery/modules](../build/resources/osquery/modules), and [enabled-modules.json](../build/resources/osquery/enabled-modules.json) lists the modules that run. [module-schedules.json](../build/resources/module-schedules.json) sets how often each module runs, and the install scripts in [build/resources](../build/resources) register the scheduled tasks.

[ApiService.cs](../src/Services/ApiService.cs) posts the collected payload as JSON to the API's `/api/v1/device` endpoint. Settings come from the configuration classes in [src/Configuration](../src/Configuration), which read the shipped [appsettings.yaml](../src/appsettings.yaml), files under `C:\ProgramData\ManagedReports` and the policy registry keys described by the [ADMX template](../resources/ReportMate.admx). Code shared with the app, such as settings writes, log reading and secret storage, lives in [src/Shared](../src/Shared).

[src/App](../src/App) is the Managed Reports Runner window, with Prefs, Run and Logs pages. Policy-managed settings are read-only there, and saving an unmanaged setting asks for elevation. [usagetracker](../usagetracker) is a small companion process that runs in the signed-in user's session and records foreground and active time per application, which the client reads at collection time.

## Development and verification

Use the [README](../README.md) and [BUILD.md](../BUILD.md) for setup and build options. [build.ps1](../build.ps1) is the single build script. It needs PowerShell 7 and the .NET SDK, regenerates the module version file before compiling, and produces MSI, NUPKG and ZIP packages unless told to skip them.

A local build without signing or packaging matches what CI runs:

```powershell
.\build.ps1 -NoSign -SkipMSI -SkipNUPKG -SkipZIP -Configuration Release
```

Unit tests live in [tests/ReportMate.WindowsClient.Tests](../tests/ReportMate.WindowsClient.Tests) and run after the build, because the test project references generated source:

```powershell
dotnet test tests\ReportMate.WindowsClient.Tests\ReportMate.WindowsClient.Tests.csproj --configuration Release
```

The [CI workflow](../.github/workflows/ci.yml) runs on every pull request and push to `main`: it validates the ADMX and ADML policy templates, builds, and runs the tests. The [release workflow](../.github/workflows/release.yml) runs on version tags, builds unsigned packages stamped with the tag's version, checks that every package carries that version and the app, and publishes a GitHub release. Organizations sign the binaries and MSI with their own certificate before deployment.

To check a change against a real API, run one module and send it to a test endpoint, for example `managedreportsrunner.exe run --run-module hardware --api-url https://reportmate.example.com -vv`.

## Documentation ownership

Keep this wiki as the entry point and update the linked pages where the facts belong. Collection behaviour belongs in the module processors and their osquery JSON, packaging in [BUILD.md](../BUILD.md), and settings in the README's configuration sections and the policy template. Examples use fictional data. Deployment inventories, credentials, passphrases, signing certificates and organization-specific operations belong with their deployment owner.
