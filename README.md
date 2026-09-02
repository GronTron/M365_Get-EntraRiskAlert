# M365_Get-EntraRiskAlert

This script connects to Microsoft Graph and checks for Microsoft Entra risk alerts. It can track the latest alert state, compare against a saved state file, and send email notifications when new or updated risk events are detected.

Script was 95% coded by CoPilot, debugged and tested by myself. 

## Usage

```powershell
.\Get-EntraRiskAlert.ps1
```

The script will run using the configured values for your tenant, application registration, certificate, SMTP settings, and log location.

## Prerequisites

- Requires PowerShell 5.1
- Install the Microsoft Graph PowerShell module: https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0
-- Requires Microsoft.Graph.Authentication for Graph authentication but otherwise uses the Graph API to run queries.
- Create an app registration with these permissions (admin consent required):
  - `AuditLog.Read.All`
  - `IdentityRiskEvent.Read.All`
- Create a self-signed certificate and upload it to the app registration.

```powershell
$certname = "EntraAlertsCert"

$cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256

$mypwd = ConvertTo-SecureString -String "CERT PRIVATE KEY PW" -Force -AsPlainText

Export-Certificate -Cert $cert -FilePath "<FILEPATH>\$certname.cer"

Export-PfxCertificate -Cert $cert -FilePath "FILEPATH>\$certname.pfx" -Password $mypwd
```

- Install the `.pfx` certificate in the Personal certificate store on the machine where the script will run.

## Setup Instructions

1. Copy the folder and its contents to the desired location for the script and data.
2. Edit the script and update the values for:
   - `TenantID`
   - `ClientID`
   - `Thumbprint`
   - `StateFilePath`
   - `EmailFrom`
   - `EmailTo`
   - `SmtpServer`
   - `LogFolder`