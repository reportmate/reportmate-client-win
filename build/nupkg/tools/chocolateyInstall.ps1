$ErrorActionPreference = 'Stop'

# Installation paths
$programFilesLocation = 'C:\Program Files\ReportMate\'
$programDataLocation = 'C:\ProgramData\ManagedReports\'
$managedInstallsLocation = 'C:\ProgramData\ManagedInstalls\'

# Create directories if they don't exist
if ($programFilesLocation) { 
    New-Item -ItemType Directory -Force -Path $programFilesLocation | Out-Null 
}
if ($programDataLocation) { 
    New-Item -ItemType Directory -Force -Path $programDataLocation | Out-Null 
}
if ($managedInstallsLocation) { 
    New-Item -ItemType Directory -Force -Path $managedInstallsLocation | Out-Null 
}

$payloadRoot = Join-Path $PSScriptRoot '..\payload'
$payloadRoot = [System.IO.Path]::GetFullPath($payloadRoot)

Write-Host "Installing ReportMate from payload: $payloadRoot"

# Copy executable and version files to Program Files
$programFilesFiles = @('runner.exe', 'version.txt', 'module-schedules.json', 'install-tasks.ps1', 'uninstall-tasks.ps1')
foreach ($file in $programFilesFiles) {
    $sourcePath = Join-Path $payloadRoot $file
    if (Test-Path $sourcePath) {
        $destPath = Join-Path $programFilesLocation $file
        Copy-Item -LiteralPath $sourcePath -Destination $destPath -Force
        Write-Host "Copied $file to Program Files"
        
        if (-not (Test-Path -LiteralPath $destPath)) {
            Write-Error "Failed to copy $file to Program Files"
            exit 1
        }
    }
}

# Copy data directory contents to ProgramData
$dataPayloadPath = Join-Path $payloadRoot 'data'
if (Test-Path $dataPayloadPath) {
    Write-Host "Copying data files to ProgramData..."
    Get-ChildItem -Path $dataPayloadPath -Recurse | ForEach-Object {
        $fullName = $_.FullName
        $fullName = [Management.Automation.WildcardPattern]::Escape($fullName)
        $relative = $fullName.Substring($dataPayloadPath.Length).TrimStart('\','/')
        $dest = Join-Path $programDataLocation $relative
        
        if ($_.PSIsContainer) {
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
        } else {
            Copy-Item -LiteralPath $fullName -Destination $dest -Force
            if (-not (Test-Path -LiteralPath $dest)) {
                Write-Error "Failed to copy data file $fullName"
                exit 1
            }
        }
    }
    Write-Host "Data files copied successfully"
} else {
    Write-Warning "No data payload directory found at: $dataPayloadPath"
}

Write-Host "ReportMate chocolatey installation completed successfully"

# Clean up executable from payload after installation
$exePayloadPath = Join-Path $payloadRoot 'runner.exe'
if (Test-Path $exePayloadPath) {
    try {
        Remove-Item $exePayloadPath -Force
        Write-Host "Cleaned up runner.exe from payload"
    } catch {
        Write-Verbose "Could not remove runner.exe from payload: $_"
    }
}

