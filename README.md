# Graph-UTCM

The unified tenant configuration management (UTCM) APIs allow administrators to control and manage configuration settings across a single workload or multiple workloads within the organization.

## Description
This PowerShell script can be used to create a snapshot of a tenant for baseline configuration, create a configuration monitor, and get configuration drift.

## Requirements
1. The script requires an application registration in Entra ID that has the Graph API permission for ConfigurationMonitoring.ReadWrite.All.
2. The script requires addition Graph API permissions to use the AssignPermissions operation that include: Application.Read.All, AppRoleAssignment.ReadWrite.All, Directory.Read.All, and RoleManagement.ReadWrite.Directory

## Usage
Create a snapshot for the Exchange configuration in the tenant:
```powershell
.\Graph-UTCM.ps1 -OAuthClientId 2e542266-a1b2-4567-8901-abcdccd61976 -OAuthTenantId 9101fc97-a2e6-2255-a2d5-83e051e52057 -OAuthCertificate 7765BEC834A02FB0DF8686D13186ABC8BE265917 -CertificateStore CurrentUser -Operation CreateSnapshot -Resource Exchange
```
Check the status of the snapshot:
```powershell
.\Graph-UTCM.ps1 -OAuthClientId 2e542266-a1b2-4567-8901-abcdccd61976 -OAuthTenantId 9101fc97-a2e6-2255-a2d5-83e051e52057 -OAuthCertificate 7765BEC834A02FB0DF8686D13186ABC8BE265917 -CertificateStore CurrentUser -Operation GetSnapshot -SnapshotJobId d8982fef-3331-497f-8b8b-47a119a2285e
```
Create a configuration monitor
```powershell
.\Graph-UTCM.ps1 -OAuthClientId 2e542266-a1b2-4567-8901-abcdccd61976 -OAuthTenantId 9101fc97-a2e6-2255-a2d5-83e051e52057 -OAuthCertificate 7765BEC834A02FB0DF8686D13186ABC8BE265917 -CertificateStore CurrentUser -Operation CreateConfigurationMonitor -SnapshotJobId d8982fef-3331-497f-8b8b-47a119a2285e
```
Check for configuration drifts
```powershell
.\Graph-UTCM.ps1 -OAuthClientId 2e542266-a1b2-4567-8901-abcdccd61976 -OAuthTenantId 9101fc97-a2e6-2255-a2d5-83e051e52057 -OAuthCertificate 7765BEC834A02FB0DF8686D13186ABC8BE265917 -CertificateStore CurrentUser -Operation ListMonitoringResults
```
Get the configuration drifts
```powershell
.\Graph-UTCM.ps1 -OAuthClientId 2e542266-a1b2-4567-8901-abcdccd61976 -OAuthTenantId 9101fc97-a2e6-2255-a2d5-83e051e52057 -OAuthCertificate 7765BEC834A02FB0DF8686D13186ABC8BE265917 -CertificateStore CurrentUser -Operation GetConfigurationDrift -ConfigurationDriftId 660819fc-1c38-459b-bb8f-47019ec5068f
```

## Parameters

**AzureEnvironment** - The AzureEnvironment parameter specifies the cloud environment for the tenant.

**PermissionType** - The PermissionType parameter specifies whether the app registrations uses delegated or application permissions

**OAuthClientId** - The OAuthClientId parameter is the Azure Application Id that this script uses to obtain the OAuth token.  Must be registered in Azure AD.

**OAuthTenantId** - The OAuthTenantId paramter is the tenant Id where the application is registered (Must be in the same tenant as mailbox being accessed).

**OAuthRedirectUri** - The OAuthRedirectUri parameter is the redirect Uri of the Azure registered application.

**OAuthClientSecret** - The OAuthClientSecret parameter is the the secret for the registered application.

**OAuthCertificate** - The OAuthCertificate parameter is the certificate for the registerd application. Certificate auth requires MSAL libraries to be available.

**CertificateStore** - The CertificateStore parameter specifies the certificate store where the certificate is loaded.

**Scope** - The Scope parameter specifies the permissions requested for delegated authentication.

**Operation** - The Operation parameter specifies the operation being performed by the script.

**SnapshotJobId** - The SnapshotJobId parameter specifies the Id the for the snapshot being queried.

**ConfigurationMonitorId** - The ConfigurationMonitorId parameter specifies the GUID of the configuration monitor.

**ConfigurationDriftId** - The ConfigurationDriftId parameter specifies the GUID of the configuration drift.
    
**Resource** - The Resource parameter specifies the workload configuration within the organization being managed.

**Name** - The Name parameter specifies the name of the snapshot to create.

**BaselineObject** - The BaselineObject parameter specifies the baseline object used to create the monitor.

**OutputPath** - The OutputPath parameter specifies the path for the configuration snapshot export.