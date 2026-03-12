# MDM Data Collection - Quick Reference

## PowerShell Commands for MDM Data

### 1. dsregcmd - Device Registration Status
```powershell
# Full device registration and enrollment status
dsregcmd /status

# Debug mode with additional details
dsregcmd /status /debug
```

**Output Sections:**
- Device State (Entra/Domain joined)
- Device Details (Device ID, certificates)
- Tenant Details (MDM URLs, tenant info)
- User State (Windows Hello, WAM)
- SSO State (PRT tokens)
- Diagnostic Data

---

### 2. MdmDiagnosticsTool - Comprehensive MDM Report
```powershell
# Generate full MDM diagnostic report
MdmDiagnosticsTool.exe -out C:\MDMDiag

# Specific areas only
MdmDiagnosticsTool.exe -out C:\MDMDiag -area "DeviceEnrollment;DeviceProvisioning;Autopilot"

# Available areas:
# - DeviceEnrollment
# - DeviceProvisioning  
# - Autopilot
# - TPM
# - DeviceManagement
```

**Outputs:**
- XML files with complete CSP state
- HTML report for viewing
- Event logs related to enrollment

---

### 3. BitLocker Status & Recovery Keys
```powershell
# Get encryption status for all volumes
Get-BitLockerVolume

# Check if recovery keys are escrowed to Entra ID
$vol = Get-BitLockerVolume -MountPoint C:
$vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }

# Check registry for backup status
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\BitLocker\RecoveryKey\*" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
```

---

### 4. Health Attestation
```powershell
# Query Health Attestation WMI
$ns = 'root/cimv2/mdm/dmmap'
Get-CimInstance -Namespace $ns -ClassName MDM_HealthAttestation_Status01_01

# Individual security features
Get-CimInstance -Namespace $ns -ClassName MDM_DeviceStatus_DeviceGuard01
Get-CimInstance -Namespace $ns -ClassName MDM_Policy_Result01_DeviceGuard02
```

**Key Properties:**
- SecureBootEnabled
- BitLockerStatus
- CodeIntegrityEnabled
- BootDebuggingEnabled
- LastUpdateTime

---

### 5. Autopilot Information
```powershell
# Check Autopilot configuration
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot" -ErrorAction SilentlyContinue

# Enrollment Status Page tracking
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\*" -ErrorAction SilentlyContinue

# Get device hardware hash (for Autopilot registration)
$serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
$hash = (Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName MDM_DevDetail_Ext01).DeviceHardwareData
```

---

### 6. Intune Management Extension Status
**Note:** Commonly abbreviated as IME

```powershell
# Check Intune Management Extension service status
Get-Service -Name IntuneManagementExtension

# View recent Intune Management Extension logs
Get-Content "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log" -Tail 50

# Check Intune Management Extension app deployments
$regPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
Get-ChildItem $regPath -Recurse | ForEach-Object {
    Get-ItemProperty $_.PSPath -Name ComplianceStateMessage -ErrorAction SilentlyContinue
}
```

---

### 7. Co-Management Status
```powershell
# Check if ConfigMgr client is installed
Test-Path "C:\Windows\CCM\CcmExec.exe"

# Get ConfigMgr client version
$client = Get-WmiObject -Namespace root/ccm -Class SMS_Client -ErrorAction SilentlyContinue
$client.ClientVersion

# Check Co-Management workloads
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP\Provider\MS DM Server\CoManagement\WMIBridge" -ErrorAction SilentlyContinue

# Get current workload authority
Get-CimInstance -Namespace root/ccm/ClientSDK -ClassName CCM_ClientUtilities -ErrorAction SilentlyContinue
```

---

### 8. Compliance Evaluation Details
```powershell
# Get device compliance policies
$ns = 'root/cimv2/mdm/dmmap'
Get-CimInstance -Namespace $ns -ClassName MDM_DeviceStatus_* | Select-Object -Property *

# Check specific compliance settings
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceCompliance" -ErrorAction SilentlyContinue

# View compliance evaluation logs
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" -MaxEvents 50
```

---

### 9. Enrollment Registry Keys
```powershell
# Get all enrollments
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{
        EnrollmentID = $_.PSChildName
        ProviderID = $props.ProviderID
        UPN = $props.UPN
        EnrollmentState = $props.EnrollmentState
        AADTenantID = $props.AADTenantID
    }
}

# MDM device IDs
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*" -ErrorAction SilentlyContinue | 
    Select-Object DeviceClientId, ServerURL

# Intune device identification
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments\*" | ForEach-Object {
    Get-ItemProperty $_.PSPath | Select-Object DeviceID, ObjectId, IntuneDeviceID
}
```

---

### 10. Applied MDM Policies (Configuration Profiles)
```powershell
# List all policy areas managed by MDM
$policyPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device"
Get-ChildItem $policyPath -Name

# Get settings for a specific policy area
Get-ItemProperty "$policyPath\BitLocker" -ErrorAction SilentlyContinue
Get-ItemProperty "$policyPath\Defender" -ErrorAction SilentlyContinue
Get-ItemProperty "$policyPath\DeviceLock" -ErrorAction SilentlyContinue
Get-ItemProperty "$policyPath\Update" -ErrorAction SilentlyContinue

# List all CSPs available
Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName * -List | 
    Select-Object -Property CimClassName | Sort-Object
```

---

### 11. Windows Hello for Business
```powershell
# Check NGC (Next Generation Credentials) status
certutil -verifykeys

# Get NGC container info
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Cryptography\DPAPI\NGC" -ErrorAction SilentlyContinue

# Check PIN setup
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ErrorAction SilentlyContinue

# List enrolled biometrics
Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName MDM_PassportForWork_*
```

---

### 12. Windows Update Configuration
```powershell
# Get Windows Update settings
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"

# Check update deferral policies
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update"

# Delivery Optimization settings
Get-DeliveryOptimizationStatus
Get-DeliveryOptimizationPerfSnap
```

---

### 13. Conditional Access / Device Trust
```powershell
# Check PRT (Primary Refresh Token) status - included in dsregcmd
dsregcmd /status | Select-String -Pattern "PRT"

# Check device compliance for Conditional Access
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AAD" -ErrorAction SilentlyContinue

# View authentication events
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624 or EventID=4625]]" -MaxEvents 10
```

---

### 14. Network Profiles Deployed via MDM
```powershell
# VPN profiles
Get-VpnConnection -AllUserConnection

# Wi-Fi profiles
netsh wlan show profiles

# Get specific Wi-Fi profile details
$profiles = netsh wlan show profiles | Select-String -Pattern "All User Profile" | ForEach-Object {
    $name = $_.Line.Split(':')[1].Trim()
    netsh wlan show profile name="$name" key=clear
}

# Proxy settings from MDM
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
```

---

### 15. Device Certificates (MDM and Authentication)
```powershell
# List all device certificates (LocalMachine store)
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Issuer, NotAfter, Thumbprint

# MDM-specific certificates
Get-ChildItem Cert:\LocalMachine\My | 
    Where-Object { $_.Issuer -like "*Intune*" -or $_.Issuer -like "*MDM*" }

# Entra ID/Azure AD device certificate
Get-ChildItem Cert:\LocalMachine\My | 
    Where-Object { $_.Subject -like "*-*-*-*-*" -and $_.Issuer -like "*Microsoft*" }

# Check certificate thumbprint from dsregcmd
dsregcmd /status | Select-String -Pattern "Thumbprint"
```

---

## WMI/CIM Namespaces for MDM

### Primary MDM Namespace:
```powershell
$ns = 'root/cimv2/mdm/dmmap'

# List all MDM classes
Get-CimClass -Namespace $ns | Select-Object CimClassName
```

### Key MDM Classes:
```powershell
# Device details
Get-CimInstance -Namespace $ns -ClassName MDM_DevDetail_Ext01

# BitLocker
Get-CimInstance -Namespace $ns -ClassName MDM_BitLocker_*

# Defender
Get-CimInstance -Namespace $ns -ClassName MDM_Defender_*

# Windows Hello
Get-CimInstance -Namespace $ns -ClassName MDM_PassportForWork_*

# Policy results
Get-CimInstance -Namespace $ns -ClassName MDM_Policy_Result01_*

# Device configuration
Get-CimInstance -Namespace $ns -ClassName MDM_DeviceManageability_*
```

---

## Event Logs for MDM Troubleshooting

### Key Event Log Channels:
```powershell
# Device Management logs
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" -MaxEvents 50

# Autopilot logs
Get-WinEvent -LogName "Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin" -MaxEvents 50

# MDM enrollment events
Get-WinEvent -LogName "Microsoft-Windows-AAD/Operational" -MaxEvents 50

# Windows Update events
Get-WinEvent -LogName "Microsoft-Windows-WindowsUpdateClient/Operational" -MaxEvents 50

# BitLocker events
Get-WinEvent -LogName "Microsoft-Windows-BitLocker/BitLocker Management" -MaxEvents 50
```

### Specific Event IDs:
- **75** - Device enrollment succeeded
- **76** - Device enrollment failed
- **300** - MDM sync started
- **400** - Policy application started
- **500** - Configuration profile applied

---

## File Locations

### Intune Management Extension Logs:
```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\
├── IntuneManagementExtension.log (main log)
├── IntuneManagementExtension-*.log (rotated logs)
└── AgentExecutor.log (script execution)
```
```

### Autopilot Logs:
```
C:\Windows\Logs\Autopilot\
├── AutopilotDDSZTDFile.json
└── *.etl (event trace logs)
```

### MDM Diagnostics Output:
```
# Generated by MdmDiagnosticsTool
C:\MDMDiag\
├── MDMDiagReport.xml
├── MDMDiagReport.html
├── RegistryDump\
└── EventLogs\
```

---

## Quick Diagnostic Script

Save this as `Get-MDMStatus.ps1`:

```powershell
#Requires -RunAsAdministrator

Write-Host "=== MDM Status Report ===" -ForegroundColor Cyan

# 1. Device Registration
Write-Host "`n[Device Registration]" -ForegroundColor Yellow
dsregcmd /status | Select-String "AzureAdJoined|DomainJoined|EnterpriseJoined"

# 2. Enrollment Status
Write-Host "`n[MDM Enrollment]" -ForegroundColor Yellow
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    if ($props.ProviderID) {
        Write-Host "  Provider: $($props.ProviderID)"
        Write-Host "  UPN: $($props.UPN)"
        Write-Host "  State: $($props.EnrollmentState)"
    }
}

# 3. Device IDs
Write-Host "`n[Device Identification]" -ForegroundColor Yellow
$deviceId = (dsregcmd /status | Select-String "DeviceId").ToString().Split(':')[1].Trim()
Write-Host "  Device ID: $deviceId"

# 4. Autopilot
Write-Host "`n[Autopilot]" -ForegroundColor Yellow
$autopilot = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot" -ErrorAction SilentlyContinue
if ($autopilot) {
    Write-Host "  Configured: Yes"
    Write-Host "  Tenant: $($autopilot.CloudAssignedTenantId)"
} else {
    Write-Host "  Configured: No"
}

# 5. BitLocker
Write-Host "`n[BitLocker]" -ForegroundColor Yellow
$volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
foreach ($vol in $volumes) {
    Write-Host "  $($vol.MountPoint): $($vol.VolumeStatus) - $($vol.EncryptionPercentage)%"
}

# 6. Compliance Policies
Write-Host "`n[Compliance Policies]" -ForegroundColor Yellow
$compPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceCompliance"
if (Test-Path $compPath) {
    $props = Get-ItemProperty $compPath -ErrorAction SilentlyContinue
    $count = ($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }).Count
    Write-Host "  Applied: $count settings"
} else {
    Write-Host "  Applied: None"
}

# 7. Configuration Profiles
Write-Host "`n[Configuration Profiles]" -ForegroundColor Yellow
$policyPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device"
$areas = Get-ChildItem $policyPath -Name -ErrorAction SilentlyContinue
Write-Host "  Policy Areas: $($areas.Count)"

# 8. Co-Management
Write-Host "`n[Co-Management]" -ForegroundColor Yellow
if (Test-Path "C:\Windows\CCM\CcmExec.exe") {
    $client = Get-WmiObject -Namespace root/ccm -Class SMS_Client -ErrorAction SilentlyContinue
    Write-Host "  ConfigMgr: Yes (v$($client.ClientVersion))"
    $coMgmt = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP" -Name Provider -ErrorAction SilentlyContinue
    Write-Host "  Co-Managed: $(if ($coMgmt) { 'Yes' } else { 'No' })"
} else {
    Write-Host "  ConfigMgr: No"
}

Write-Host "`n=== End Report ===" -ForegroundColor Cyan
```

Run with:
```powershell
.\Get-MDMStatus.ps1
```

---

## Integration with ReportMate

The data collected from these commands is now available in:

1. **Backend (C#):** `MdmDiagnosticsService.cs`
2. **Data Collection:** `ManagementModuleProcessor.cs`
3. **Frontend:** Ready to extend `Management.tsx`

**Next Steps:**
1. Call `MdmDiagnosticsService` from `ManagementModuleProcessor`
2. Add to `ManagementData.Metadata["MdmDiagnostics"]`
3. Update TypeScript types in frontend
4. Create UI components to display the new data
