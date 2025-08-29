# Production Configuration Template
# Copy this file to production-config.ps1 and customize for your environment

# =================================================================
# REPORTMATE PRODUCTION CONFIGURATION
# =================================================================
# Customize these values for your ReportMate deployment

# 🌐 API Configuration
$PROD_API_URL = "https://reportmate.yourdomain.com"           # Your ReportMate API endpoint
$PROD_PASSPHRASE = "YOUR-SECURE-PASSPHRASE-2025"             # Your client authentication passphrase

# 🏷️ Device Identification
$DEVICE_ID_PREFIX = "CORP"                                   # Prefix for device IDs (optional)
$DEVICE_ID_SUFFIX = ""                                       # Suffix for device IDs (optional)

# ⏰ Collection Settings
$COLLECTION_INTERVAL = 3600                                  # Data collection interval (seconds) - 3600 = 1 hour
$LOG_LEVEL = "Information"                                   # Logging level: Error, Warning, Information, Debug

# 🔧 Advanced Settings
$API_TIMEOUT_SECONDS = 300                                   # API request timeout (seconds) - 300 = 5 minutes
$MAX_RETRY_ATTEMPTS = 3                                      # Maximum retry attempts for failed API requests
$VALIDATE_SSL_CERT = $true                                   # Validate SSL certificates (set to $false for testing only)

# 🎯 osquery Configuration
$OSQUERY_PATH = "C:\Program Files\osquery\osqueryi.exe"     # Path to osquery executable

# =================================================================
# DEPLOYMENT CONFIGURATION
# =================================================================

# Auto-deploy configuration during package installation
$AUTO_CONFIGURE = $true                                      # Set to $false to disable automatic configuration

# Force configuration (overwrite existing settings)
$FORCE_CONFIGURATION = $true                                 # Set to $false to prompt before overwriting

# Test connectivity after configuration
$TEST_CONNECTIVITY = $true                                   # Set to $false to skip connectivity test

# =================================================================
# EXAMPLE CONFIGURATIONS FOR DIFFERENT ENVIRONMENTS
# =================================================================

<#
# Example 1: Production Environment
$PROD_API_URL = "https://reportmate.company.com"
$PROD_PASSPHRASE = "PROD-COMPANY-RM-2025-SECURE"
$DEVICE_ID_PREFIX = "PROD"
$COLLECTION_INTERVAL = 3600  # 1 hour
$LOG_LEVEL = "Information"

# Example 2: Development Environment
$PROD_API_URL = "https://reportmate-dev.company.com"
$PROD_PASSPHRASE = "DEV-COMPANY-RM-2025-TEST"
$DEVICE_ID_PREFIX = "DEV"
$COLLECTION_INTERVAL = 1800  # 30 minutes
$LOG_LEVEL = "Debug"

# Example 3: Test Environment
$PROD_API_URL = "https://reportmate-test.company.com"
$PROD_PASSPHRASE = "TEST-COMPANY-RM-2025-STAGING"
$DEVICE_ID_PREFIX = "TEST"
$COLLECTION_INTERVAL = 900   # 15 minutes
$LOG_LEVEL = "Debug"
$VALIDATE_SSL_CERT = $false  # For testing with self-signed certificates

# Example 4: Emily Carr University
$PROD_API_URL = "https://reportmate.ecuad.ca"
$PROD_PASSPHRASE = "ECUAD-RM-2025-PROD-SECURE"
$DEVICE_ID_PREFIX = "ECUAD"
$COLLECTION_INTERVAL = 7200  # 2 hours
$LOG_LEVEL = "Information"
#>

# =================================================================
# SECURITY NOTES
# =================================================================
<#
1. PASSPHRASE SECURITY:
   - Use strong, unique passphrases for each environment
   - Consider using a secure key management system
   - Rotate passphrases regularly

2. SSL/TLS:
   - Always use HTTPS in production
   - Validate SSL certificates in production
   - Only disable SSL validation for testing

3. ACCESS CONTROL:
   - Limit access to this configuration file
   - Use Group Policy or MDM for centralized deployment
   - Monitor configuration changes

4. LOGGING:
   - Use appropriate log levels for each environment
   - Monitor logs for security events
   - Ensure log files are properly secured
#>

# =================================================================
# VALIDATION
# =================================================================

# Validate required configuration
if ([string]::IsNullOrWhiteSpace($PROD_API_URL)) {
    throw "PROD_API_URL is required and cannot be empty"
}

if (-not $PROD_API_URL.StartsWith("https://") -and -not $PROD_API_URL.StartsWith("http://")) {
    throw "PROD_API_URL must start with https:// or http://"
}

if ([string]::IsNullOrWhiteSpace($PROD_PASSPHRASE)) {
    Write-Warning "PROD_PASSPHRASE is empty - ReportMate will run without authentication"
}

if ($COLLECTION_INTERVAL -lt 60 -or $COLLECTION_INTERVAL -gt 86400) {
    throw "COLLECTION_INTERVAL must be between 60 and 86400 seconds"
}

if ($LOG_LEVEL -notin @("Error", "Warning", "Information", "Debug")) {
    throw "LOG_LEVEL must be one of: Error, Warning, Information, Debug"
}

Write-Output "Configuration validation passed ✅"
