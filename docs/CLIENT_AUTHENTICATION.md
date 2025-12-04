# ReportMate Client Authentication

ReportMate supports optional passphrase-based authentication to restrict which clients can submit data to the API.

## Authentication Modes

1. **Open Access** - No authentication required (default for development/testing)
2. **Passphrase Authentication** - Clients must provide a valid passphrase

## Server Configuration

### Environment Variable

Configure accepted passphrases on the server:

```bash
CLIENT_PASSPHRASES="passphrase1,passphrase2,passphrase3"
```

Multiple passphrases can be comma-separated to support key rotation.

### Azure Deployment

For Azure deployments, configure in Terraform:

```hcl
client_passphrases = "your-secure-passphrase"
```

### Security Notes

- If `CLIENT_PASSPHRASES` is empty or not set, the server accepts all requests (open mode)
- If passphrases are configured, only clients with valid passphrases can submit data
- Passphrases are case-sensitive

## Client Configuration

### Configuration File

Set the passphrase in `C:\ProgramData\ManagedReports\appsettings.yaml`:

```yaml
ReportMate:
  ApiUrl: "https://reportmate.ecuad.ca"
  Passphrase: "your-secure-passphrase"
```

### Environment Variable

```powershell
$env:REPORTMATE_PASSPHRASE = "your-secure-passphrase"
```

### Registry (for MDM/GPO)

Configure via registry at `HKLM\SOFTWARE\Config\ReportMate`:

```
Value: Passphrase
Type: REG_SZ
Data: your-secure-passphrase
```

### MDM/Intune (OMA-URI)

```
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Config/ReportMate/Passphrase
Data type: String
Value: your-secure-passphrase
```

## API Response Codes

| Status Code | Description |
|-------------|-------------|
| 200/202 | Request accepted successfully |
| 400 | Invalid request payload |
| 401 | Unauthorized - invalid or missing passphrase |
| 500 | Internal server error |

## Best Practices

### Strong Passphrases

Use passphrases that are:
- At least 16 characters
- Random or high-entropy
- Different for production vs development

### Key Rotation

To rotate passphrases with zero downtime:

1. Add the new passphrase to the server configuration:
   ```bash
   CLIENT_PASSPHRASES="old-passphrase,new-passphrase"
   ```

2. Deploy the new passphrase to all clients

3. Remove the old passphrase after all clients are updated:
   ```bash
   CLIENT_PASSPHRASES="new-passphrase"
   ```

### Secure Distribution

Distribute passphrases via:
- MDM/Intune OMA-URI settings
- Group Policy registry preferences
- Configuration management tools (Ansible, SCCM)

Avoid:
- Hardcoding in scripts that are version-controlled
- Including in installation packages
- Email or other insecure channels

## Testing Authentication

### Test Valid Passphrase

```powershell
# Client will include passphrase from configuration
sudo pwsh -c "& 'C:\Program Files\ReportMate\runner.exe' -vv --collect-only"
sudo pwsh -c "& 'C:\Program Files\ReportMate\runner.exe' -vv --transmit-only"
```

### Verify in Logs

Check server logs for authentication status:
- Successful: "Passphrase validated"
- Failed: "Invalid passphrase" or 401 response

## Disabling Authentication

To disable authentication and allow all clients:

1. Remove or empty the `CLIENT_PASSPHRASES` environment variable on the server
2. Restart the API service

Note: This is only recommended for development or testing environments.

## Migration from Open to Authenticated

1. **Phase 1**: Deploy passphrase to all clients via MDM/GPO
2. **Phase 2**: Verify clients are reporting with passphrase in logs
3. **Phase 3**: Enable server-side authentication by setting `CLIENT_PASSPHRASES`
4. **Phase 4**: Monitor for 401 errors indicating misconfigured clients

### Rollback Plan

If issues occur after enabling authentication:
1. Set `CLIENT_PASSPHRASES=""` on the server to restore open access
2. Investigate and fix client configurations
3. Re-enable authentication
