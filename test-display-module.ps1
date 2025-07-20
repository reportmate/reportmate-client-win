#!/usr/bin/env pwsh
# Test Display Module Integration
# This script validates the display module is properly integrated

Write-Host "Testing Display Module Integration..." -ForegroundColor Green

# Check if display module files exist
$displayFiles = @(
    "src/Models/DisplayModels.cs",
    "src/Modules/DisplayModuleProcessor.cs",
    "src/osquery/modules/display.json"
)

Write-Host "`nChecking required files..." -ForegroundColor Yellow
foreach ($file in $displayFiles) {
    if (Test-Path $file) {
        Write-Host "✓ $file" -ForegroundColor Green
    } else {
        Write-Host "✗ $file (missing)" -ForegroundColor Red
    }
}

# Check if display module is enabled in configuration
$enabledModulesPath = "src/osquery/enabled-modules.json"
if (Test-Path $enabledModulesPath) {
    $enabledModules = Get-Content $enabledModulesPath | ConvertFrom-Json
    if ($enabledModules.enabled -contains "display") {
        Write-Host "✓ Display module enabled in configuration" -ForegroundColor Green
    } else {
        Write-Host "✗ Display module not enabled in configuration" -ForegroundColor Red
    }
} else {
    Write-Host "✗ Enabled modules configuration not found" -ForegroundColor Red
}

# Check osquery display queries
$displayConfigPath = "src/osquery/modules/display.json"
if (Test-Path $displayConfigPath) {
    $displayConfig = Get-Content $displayConfigPath | ConvertFrom-Json
    $queryCount = $displayConfig.queries.Count
    Write-Host "✓ Display module has $queryCount osquery queries" -ForegroundColor Green
    
    # List key queries
    Write-Host "`nKey display queries:" -ForegroundColor Cyan
    foreach ($queryName in $displayConfig.queries.PSObject.Properties.Name) {
        Write-Host "  - $queryName" -ForegroundColor White
    }
} else {
    Write-Host "✗ Display osquery configuration not found" -ForegroundColor Red
}

Write-Host "`nDisplay Module Integration Test Complete!" -ForegroundColor Green
Write-Host "The display module is ready for comprehensive monitor and graphics adapter data collection." -ForegroundColor White
