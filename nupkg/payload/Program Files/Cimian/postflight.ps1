# ReportMate Cimian Postflight Script
# Simple postflight script that runs ReportMate after Cimian's managedsoftwareupdate.exe
# Mirrors the MunkiReport/Munki integration pattern

param(
    [switch]$Verbose = $false,
    [switch]$Force = $false,
    [string]$LogPath = "C:\ProgramData\ManagedReports\logs\postflight.log"
)

# Configuration
$ReportMateExe = "C:\Program Files\ReportMate\runner.exe"
$MaxLogSizeMB = 10
$ErrorActionPreference = "Continue"

# Create log directory
$LogDir = Split-Path $LogPath -Parent
if (-not (Test-Path $LogDir)) {
    try {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    } catch {
        # Fallback to temp directory if we can't create the log directory
        $LogPath = "$env:TEMP\reportmate-postflight.log"
    }
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to console if verbose
    if ($Verbose) {
        Write-Host $LogMessage
    }
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $LogMessage -Encoding UTF8
    } catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

# Rotate log file if too large
function Rotate-LogFile {
    if (Test-Path $LogPath) {
        $LogFile = Get-Item $LogPath
        if ($LogFile.Length -gt ($MaxLogSizeMB * 1MB)) {
            Write-Log "Rotating log file (size: $([math]::Round($LogFile.Length / 1MB, 2)) MB)" "INFO"
            $BackupPath = $LogPath + ".old"
            if (Test-Path $BackupPath) {
                Remove-Item $BackupPath -Force
            }
            Move-Item $LogPath $BackupPath
        }
    }
}

# Main execution
try {
    Rotate-LogFile
    
    Write-Log "=== ReportMate Postflight Script Started ===" "INFO"
    Write-Log "Running after Cimian managedsoftwareupdate.exe" "INFO"
    
    # Check if ReportMate is installed
    if (-not (Test-Path $ReportMateExe)) {
        Write-Log "WARNING: ReportMate not installed at $ReportMateExe" "WARN"
        Write-Log "Please install ReportMate Windows client" "WARN"
        exit 0
    }
    
    Write-Log "ReportMate executable found: $ReportMateExe" "INFO"
    
    # Prepare ReportMate arguments
    $Arguments = @("run")
    if ($Force) {
        $Arguments += "--force"
    }
    if ($Verbose) {
        $Arguments += "--verbose"
    }
    
    Write-Log "Executing ReportMate with arguments: $($Arguments -join ' ')" "INFO"
    
    # Execute ReportMate
    $StartTime = Get-Date
    $Process = Start-Process -FilePath $ReportMateExe -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime
    
    Write-Log "ReportMate execution completed in $([math]::Round($Duration.TotalSeconds, 2)) seconds" "INFO"
    
    if ($Process.ExitCode -eq 0) {
        Write-Log "ReportMate data collection completed successfully" "INFO"
    } else {
        Write-Log "ERROR: ReportMate failed with exit code $($Process.ExitCode)" "ERROR"
        
        # Try to get additional diagnostic information
        try {
            $InfoProcess = Start-Process -FilePath $ReportMateExe -ArgumentList @("info") -Wait -PassThru -RedirectStandardOutput "$env:TEMP\reportmate-info.txt" -NoNewWindow
            
            if (Test-Path "$env:TEMP\reportmate-info.txt") {
                $InfoOutput = Get-Content "$env:TEMP\reportmate-info.txt" -Raw
                Write-Log "ReportMate diagnostic info:`n$InfoOutput" "INFO"
                Remove-Item "$env:TEMP\reportmate-info.txt" -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log "Could not retrieve ReportMate diagnostic information: $_" "WARN"
        }
    }
    
    Write-Log "=== ReportMate Postflight Script Completed ===" "INFO"
    
    # Exit with the same code as ReportMate for upstream processing
    exit $Process.ExitCode
    
} catch {
    Write-Log "FATAL ERROR: Unhandled exception in postflight script: $_" "ERROR"
    exit 1
}
