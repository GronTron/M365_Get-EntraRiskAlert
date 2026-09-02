#Requires -Version 5.1

#region Configuration

$TenantId  = "<TENANT_ID>"
$ClientId  = "<CLIENT_ID>"
$Thumbprint = "<THUMBPRINT>"

$StateFilePath = "<FILEPATH>\Get-EntraRiskAlerts\ProcessedDetections.json"

$EmailFrom = "<SENDER_EMAIL_ADDRESS>"
$EmailTo = "<RECIPIENT_EMAIL_ADDRESS>"
$SmtpServer = "<SMTP_SERVER_ADDRESS>"

$script:SignInCache = @{}

#endregion

#region Logging

$EnableDebugLogging = $false

$LogFolder = "<FILEPATH>\Get-EntraRiskAlerts\Logs"

$LogFile = Join-Path `
    $LogFolder `
    "Get-EntraRiskAlerts_$((Get-Date).ToString('yyyyMMdd')).log"
    
# Ensure log folder exists
if (-not (Test-Path $LogFolder)) {

	New-Item `
		-Path $LogFolder `
		-ItemType Directory `
		-Force |
		Out-Null
	}
	
# Remove logs older than 30 days
Get-ChildItem `
    -Path $LogFolder `
    -Filter "*.log" `
    -ErrorAction SilentlyContinue |
Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddDays(-30)
} |
Remove-Item `
    -Force `
    -ErrorAction SilentlyContinue

function Write-Log {

    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )

    if (
        $Level -eq 'DEBUG' -and
        -not $EnableDebugLogging
    ) {
        return
    }

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $LogEntry = "$TimeStamp [$Level] $Message"

    switch ($Level) {

        'ERROR' {
            Write-Host $LogEntry -ForegroundColor Red
        }
        'WARN' {
            Write-Host $LogEntry -ForegroundColor Yellow
        }
        'DEBUG' {
            Write-Host $LogEntry -ForegroundColor Cyan
        }
        default {
            Write-Host $LogEntry
        }
    }

    Add-Content `
        -Path $LogFile `
        -Value $LogEntry `
        -Encoding UTF8
}

function Get-EntraRiskDetections {

    $Uri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"

    $Results = @()

    do {

        Write-Verbose "Requesting $Uri"

        $Response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $Uri `
            -ErrorAction Stop

        $Results += $Response.value

        $Uri = $Response.'@odata.nextLink'

    } while ($Uri)

    foreach ($Item in $Results) {
    
    	Write-Log `
		    -Level "DEBUG" `
		    -Message (
		        "Raw Detection: Id=[{0}] User=[{1}] CorrelationId=[{2}]" -f
		        $Item.id,
		        $Item.userPrincipalName,
		        $Item.correlationId
    			)

        [PSCustomObject]@{
            Id                = $Item.id
            UserDisplayName   = $Item.userDisplayName
            UserPrincipalName = $Item.userPrincipalName
            RiskLevel         = $Item.riskLevel
            RiskState         = $Item.riskState
            RiskEventType     = $Item.riskEventType
            DetectionType     = $Item.detectionTimingType
            RiskDetail        = $Item.riskDetail
            IPAddress         = $Item.ipAddress
            City              = $Item.location.city
            State             = $Item.location.state
            CountryOrRegion   = $Item.location.countryOrRegion
            ActivityDateTime  = $Item.activityDateTime
            DetectedDateTime  = $Item.detectedDateTime
            LastUpdated       = $Item.lastUpdatedDateTime
            CorrelationId     = $Item.correlationId

            AdditionalInfo    = $Item.additionalInfo
        }
    }
}

function Get-RiskAdditionalInfo {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$AdditionalInfo
    )

    $Properties = @{}

    # Return an empty object when no additional information exists.
    if ($null -eq $AdditionalInfo) {
        return [PSCustomObject]$Properties
    }

    # Return an empty object when a string is empty or whitespace.
    if (
        ($AdditionalInfo -is [string]) -and
        ($AdditionalInfo.Trim().Length -eq 0)
    ) {
        return [PSCustomObject]$Properties
    }

    try {
        if ($AdditionalInfo -is [string]) {
            # Graph commonly returns additionalInfo as a JSON string.
            $Items = $AdditionalInfo |
                ConvertFrom-Json -ErrorAction Stop
        }
        else {
            # It may already be an object or collection.
            $Items = $AdditionalInfo
        }

        foreach ($Item in @($Items)) {
            $Key = $Item.Key

            if (
                ($null -ne $Key) -and
                ($Key.ToString().Trim().Length -gt 0)
            ) {
                $Properties[$Key.ToString()] = $Item.Value
            }
        }
    }
    catch {
        Write-Log `
            -Level "WARN" `
            -Message "Unable to parse additionalInfo: $($_.Exception.Message)"
    }

    return [PSCustomObject]$Properties
}

function Get-ProcessedDetectionIds {

    param(
        [string]$Path
    )

    if (Test-Path $Path) {

        try {

            $Ids = Get-Content `
                -Path $Path `
                -Raw |
                ConvertFrom-Json

            @(
                $Ids |
                ForEach-Object {

                    if ($_ -is [string]) {

                        $_

                    }
                    elseif ($_ -and $_.value) {

                        @($_.value)
                    }
                }
            ) |
            Where-Object { $_ } |
            Select-Object -Unique
        }
        catch {

            Write-Log `
                -Level "ERROR" `
                -Message "Unable to read state file."

            @()
        }
    }
    else {

        @()
    }
}

function Save-ProcessedDetectionIds {

    param(
        [string]$Path,
        [array]$Ids
    )
    $Folder = Split-Path $Path -Parent

    if (-not (Test-Path $Folder)) {

        New-Item `
            -Path $Folder `
            -ItemType Directory `
            -Force |
            Out-Null
    }

		$CleanIds = @(
		    $Ids |
		    ForEach-Object {
		
		        if ($_ -is [string]) {
		
		            $_
		
		        }
		    }
		) |
		Sort-Object -Unique
		
		$CleanIds = $CleanIds |
		Select-Object -Last 5000
		
		$TempFile = "$Path.tmp"
		
		$CleanIds |
		    ConvertTo-Json |
		    Set-Content `
		        -Path $TempFile `
		        -Encoding UTF8
		        
		Move-Item `
			-Path $TempFile `
			-Destination $Path `
			-Force
}

function Send-EntraRiskAlert {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Detections,

        [Parameter(Mandatory)]
        [string]$From,

        [Parameter(Mandatory)]
        [string[]]$To,

        [Parameter(Mandatory)]
        [string]$SmtpServer
    )

    if ($Detections.Count -eq 0) {
        Write-Log -Message "No detections to alert on."
        return $false
    }

    $HighCount = @(
        $Detections | Where-Object {$_.RiskLevel -eq "high"}
    ).Count

    $MediumCount = @(
        $Detections | Where-Object {$_.RiskLevel -eq "medium"}
    ).Count

    $SubjectSeverity = if ($HighCount -gt 0) {
        "HIGH"
    }
    elseif ($MediumCount -gt 0) {
        "MEDIUM"
    }
    else {
        "NEW"
    }

    $Subject = "[Entra Risk Alert] - [$SubjectSeverity] - $($Detections.Count) New Detection(s)"

    $HtmlBody = New-RiskDetectionHtmlBody -Detections $Detections

    try {

        Send-MailMessage `
            -From $From `
            -To $To `
            -Subject $Subject `
            -Body $HtmlBody `
            -BodyAsHtml `
            -SmtpServer $SmtpServer `
            -ErrorAction Stop

        Write-Log `
            -Level "INFO" `
            -Message "Risk alert email sent successfully."

        return $true
    }
    catch {

        Write-Log `
            -Level "ERROR" `
            -Message "Failed sending alert email: $($_.Exception.Message)"

        return $false
    }
}

	function Get-SignInByCorrelationId {
	    [CmdletBinding()]
	    param(
	        [AllowNull()]
	        [string]$CorrelationId,
	
	        [AllowNull()]
	        [object]$ActivityDateTime
	    )
	
	    $EmptyResult = [PSCustomObject]@{
	    SignInFound             = $false
	    SignInId                = $null
	    SignInDateTime          = $null
	    SignInStatus            = $null
	    SignInErrorCode         = $null
	    SignInFailureReason     = $null
	    SignInIPAddress         = $null
	    AppDisplayName          = $null
	    ResourceDisplayName     = $null
	    ClientAppUsed           = $null
	    Browser                 = $null
	    OperatingSystem         = $null
	    DeviceId                = $null
	    DeviceDisplayName       = $null
	    IsManaged               = $null
	    IsCompliant             = $null
	    ConditionalAccessStatus = $null
	}
	
	$CacheKey = $CorrelationId.ToString().ToLowerInvariant()
	
	if ($script:SignInCache.ContainsKey($CacheKey)) {
	
	    Write-Log `
	        -Level "DEBUG" `
	        -Message "Using cached sign-in for CorrelationId [$CorrelationId]"
	
	    return $script:SignInCache[$CacheKey]
	}

    try {

        $FilterParts = @(
    "correlationId eq '$CorrelationId'"
)

if ($null -ne $ActivityDateTime) {

    try {

        $ActivityUtc = ([datetime]$ActivityDateTime).ToUniversalTime()

        $WindowStart = $ActivityUtc.AddHours(-2).ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )

        $WindowEnd = $ActivityUtc.AddHours(2).ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )

        $FilterParts += "createdDateTime ge $WindowStart"
        $FilterParts += "createdDateTime le $WindowEnd"

        Write-Log `
            -Level "DEBUG" `
            -Message "Using sign-in search window $WindowStart to $WindowEnd"

    }
    catch {

        Write-Log `
            -Level "WARN" `
            -Message "Unable to create date filter for CorrelationId [$CorrelationId]"
    }
}

$Filter = $FilterParts -join " and "

$EncodedFilter = [System.Uri]::EscapeDataString($Filter)

        $SelectProperties = @(
            "id"
            "createdDateTime"
            "ipAddress"
            "appDisplayName"
            "resourceDisplayName"
            "clientAppUsed"
            "conditionalAccessStatus"
            "status"
            "deviceDetail"
        ) -join ","

        $Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns" +
            "?`$filter=$EncodedFilter" +
            "&`$orderby=createdDateTime desc" +
            "&`$top=1" +
            "&`$select=$SelectProperties"

        $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {

            Write-Log `
                -Level "INFO" `
                -Message "Querying sign-in logs for CorrelationId [$CorrelationId]."
                
            Write-Log `
			    -Level "DEBUG" `
			    -Message "Sign-in filter: $Filter"

			Write-Log `
			    -Level "DEBUG" `
			    -Message "Sign-in URI: $Uri"

            $Response = Invoke-MgGraphRequest `
                -Method GET `
                -Uri $Uri `
                -ErrorAction Stop
        }
        finally {

            $Stopwatch.Stop()

            $ElapsedSeconds = [math]::Round($Stopwatch.Elapsed.TotalSeconds,3)

            Write-Log `
                -Level "INFO" `
                -Message (
                    "Sign-in query for CorrelationId [{0}] completed in {1} seconds." -f `
                    $CorrelationId,
                    $ElapsedSeconds
                )
                
        }

        $MatchingSignIns = @($Response.value)

		if ($MatchingSignIns.Count -eq 0) {
		
		    Write-Log `
		        -Level "WARN" `
		        -Message "No sign-in found for CorrelationId [$CorrelationId]."
		
		    $script:SignInCache[$CacheKey] = $EmptyResult
		
		    return $EmptyResult
		}

        $SignIn = $MatchingSignIns[0]
        
        Write-Log `
    		-Level "DEBUG" `
    		-Message (
	        "Returned SignIn: Id=[{0}] User=[{1}] IP=[{2}] App=[{3}]" -f
	        $SignIn.id,
	        $SignIn.userPrincipalName,
	        $SignIn.ipAddress,
	        $SignIn.appDisplayName
    		)

        $SignInStatus = "Unknown"
        $ErrorCode = $null
        $FailureReason = $null

        if ($null -ne $SignIn.status) {
            $ErrorCode = $SignIn.status.errorCode
            $FailureReason = $SignIn.status.failureReason

            if ($ErrorCode -eq 0) {
                $SignInStatus = "Success"
            }
            elseif ($null -ne $ErrorCode) {
                $SignInStatus = "Failure"
            }
        }

        $Browser = $null
        $OperatingSystem = $null
        $DeviceId = $null
        $DeviceDisplayName = $null
        $IsManaged = $null
        $IsCompliant = $null

        if ($null -ne $SignIn.deviceDetail) {
            $Browser = $SignIn.deviceDetail.browser
            $OperatingSystem = $SignIn.deviceDetail.operatingSystem
            $DeviceId = $SignIn.deviceDetail.deviceId
            $DeviceDisplayName = $SignIn.deviceDetail.displayName
            $IsManaged = $SignIn.deviceDetail.isManaged
            $IsCompliant = $SignIn.deviceDetail.isCompliant
        }

        $Result = [PSCustomObject]@{
            SignInFound               = $true
            SignInId                  = $SignIn.id
            SignInDateTime            = $SignIn.createdDateTime
            SignInStatus              = $SignInStatus
            SignInErrorCode           = $ErrorCode
            SignInFailureReason       = $FailureReason
            SignInIPAddress           = $SignIn.ipAddress
            AppDisplayName            = $SignIn.appDisplayName
            ResourceDisplayName       = $SignIn.resourceDisplayName
            ClientAppUsed             = $SignIn.clientAppUsed
            Browser                   = $Browser
            OperatingSystem           = $OperatingSystem
            DeviceId                  = $DeviceId
            DeviceDisplayName         = $DeviceDisplayName
            IsManaged                 = $IsManaged
            IsCompliant               = $IsCompliant
            ConditionalAccessStatus   = $SignIn.conditionalAccessStatus
        }
        
        $script:SignInCache[$CacheKey] = $Result
        
        return $Result
        
    }
	catch {
	
	    Write-Log `
	        -Level "WARN" `
	        -Message (
	            "Unable to query the sign-in for CorrelationId [{0}]: {1}" -f
	            $CorrelationId,
	            $_.Exception.Message
	        )
	
	    $script:SignInCache[$CacheKey] = $EmptyResult
	
	    return $EmptyResult
	}
}

function Expand-RiskDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Detection
    )

    $Info = Get-RiskAdditionalInfo `
        -AdditionalInfo $Detection.AdditionalInfo
        
    Write-Log `
    -Level "DEBUG" `
    -Message (
        "Processing risk detection: User=[{0}] CorrelationId=[{1}] RiskType=[{2}]" -f
        $Detection.UserPrincipalName,
        $Detection.CorrelationId,
        $Detection.RiskEventType
    )

    $SignIn = Get-SignInByCorrelationId `
        -CorrelationId $Detection.CorrelationId `
        -ActivityDateTime $Detection.ActivityDateTime

    $AdditionalDetails = (
        $Info.PSObject.Properties |
        Where-Object {
            $null -ne $_.Value -and
            $_.Value.ToString().Trim().Length -gt 0
        } |
        ForEach-Object {
            '{0}: {1}' -f $_.Name, $_.Value
        }
    ) -join '<br />'

    [PSCustomObject]@{
        Id                      = $Detection.Id
        UserDisplayName         = $Detection.UserDisplayName
        UserPrincipalName       = $Detection.UserPrincipalName

        RiskLevel               = $Detection.RiskLevel
        RiskState               = $Detection.RiskState
        RiskEventType           = $Detection.RiskEventType
        RiskDetail              = $Detection.RiskDetail
        DetectionType           = $Detection.DetectionType

        IPAddress               = $Detection.IPAddress
        City                    = $Detection.City
        State                   = $Detection.State
        CountryOrRegion         = $Detection.CountryOrRegion

        UserAgent               = $Info.userAgent
        MitreTechniques         = $Info.mitreTechniques
        AdditionalDetails       = $AdditionalDetails

        CorrelationId           = $Detection.CorrelationId
        ActivityDateTime        = $Detection.ActivityDateTime
        DetectedDateTime        = $Detection.DetectedDateTime

        SignInFound             = $SignIn.SignInFound
        SignInDateTime          = $SignIn.SignInDateTime
        SignInStatus            = $SignIn.SignInStatus
        SignInErrorCode         = $SignIn.SignInErrorCode
        SignInFailureReason     = $SignIn.SignInFailureReason
        SignInIPAddress         = $SignIn.SignInIPAddress

        AppDisplayName          = $SignIn.AppDisplayName
        ResourceDisplayName     = $SignIn.ResourceDisplayName
        ClientAppUsed           = $SignIn.ClientAppUsed

        Browser                 = $SignIn.Browser
        OperatingSystem         = $SignIn.OperatingSystem
        DeviceId                = $SignIn.DeviceId
        DeviceDisplayName       = $SignIn.DeviceDisplayName
        IsManaged               = $SignIn.IsManaged
        IsCompliant             = $SignIn.IsCompliant

        ConditionalAccessStatus = $SignIn.ConditionalAccessStatus
    }
}

function New-RiskDetectionHtmlBody {

    param(
        [array]$Detections
    )

    $HighCount = @(
        $Detections | Where-Object { $_.RiskLevel -eq 'high' }
    ).Count

    $MediumCount = @(
        $Detections | Where-Object { $_.RiskLevel -eq 'medium' }
    ).Count

    $RiskSummary = (
        $Detections |
        Group-Object RiskEventType |
        Sort-Object Count -Descending |
        Select-Object -First 5
    )

    $SummaryRows = foreach ($Item in $RiskSummary) {

        "<tr>
            <td>$($Item.Name)</td>
            <td>$($Item.Count)</td>
        </tr>"
    }

    $DetectionRows = foreach ($Detection in $Detections) {

        $RiskColor = switch ($Detection.RiskLevel) {

            'high'   { '#ffd6d6' }
            'medium' { '#fff3cd' }

            default  { '#ffffff' }
        }
    
@"
<tr style='background-color:$RiskColor'>
<td>$($Detection.UserDisplayName)</td>
<td>$($Detection.RiskLevel)</td>
<td>$($Detection.RiskEventType)</td>
<td>$($Detection.City), $($Detection.State)</td>
<td>$($Detection.IPAddress)</td>
<td>$($Detection.DetectedDateTime)</td>
</tr>
"@
}

$InvestigationRows = foreach ($Detection in $Detections) {
	Write-Log `
	    -Level "DEBUG" `
	    -Message (
	        "Building HTML row: User=[{0}] Risk=[{1}] SignInIP=[{2}] App=[{3}]" -f
	        $Detection.UserPrincipalName,
	        $Detection.RiskEventType,
	        $Detection.SignInIPAddress,
	        $Detection.AppDisplayName
	    )
    $SignInFoundText = if ($Detection.SignInFound) {
        "Yes"
    }
    else {
        "No"
    }

    $SignInStatusColor = switch ($Detection.SignInStatus) {
        "Success" { "#107c10" }
        "Failure" { "#d13438" }
        default   { "#605e5c" }
    }

    $ManagedText = if ($null -eq $Detection.IsManaged) {
        "Unknown"
    }
    elseif ($Detection.IsManaged) {
        "Yes"
    }
    else {
        "No"
    }

    $CompliantText = if ($null -eq $Detection.IsCompliant) {
        "Unknown"
    }
    elseif ($Detection.IsCompliant) {
        "Yes"
    }
    else {
        "No"
    }

@"
<tr>
    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $($Detection.UserDisplayName)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $($Detection.RiskDetail)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $SignInFoundText
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;
               color:$SignInStatusColor;font-weight:bold;'>
        $($Detection.SignInStatus)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $($Detection.AppDisplayName)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $($Detection.ClientAppUsed)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $($Detection.SignInIPAddress)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $($Detection.OperatingSystem)<br />
        $($Detection.Browser)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        Managed: $ManagedText<br />
        Compliant: $CompliantText
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $($Detection.ConditionalAccessStatus)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;
               max-width:350px;word-wrap:break-word;'>
        $($Detection.UserAgent)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;'>
        $($Detection.MitreTechniques)
    </td>

    <td style='padding:6px;border:1px solid #d1d1d1;vertical-align:top;
               font-family:Consolas,monospace;font-size:9pt;'>
        $($Detection.CorrelationId)
    </td>
</tr>
"@
}
    @"
<html>

<body style='font-family:Segoe UI,Arial;font-size:10pt'>

<div style='background:#8B0000;
            color:white;
            padding:15px;
            font-size:22px;
            font-weight:bold;'>

Microsoft Entra Risk Detection Alert

</div>

<br>

<table style='width:100%;border-collapse:collapse'>

<tr>

<td style='background:#d13438;
           color:white;
           padding:10px;
           text-align:center'>

<b>High Risks</b><br>
$HighCount

</td>

<td style='background:#ffb900;
           padding:10px;
           text-align:center'>

<b>Medium Risks</b><br>
$MediumCount

</td>

<td style='background:#0078d4;
           color:white;
           padding:10px;
           text-align:center'>

<b>Total</b><br>
$($Detections.Count)

</td>

</tr>

</table>

<br>

<h3>Top Risk Events</h3>

<table border='1'
       cellpadding='5'
       cellspacing='0'
       style='border-collapse:collapse'>

<tr>
<th>Risk Event</th>
<th>Count</th>
</tr>

$($SummaryRows -join "`n")

</table>

<br>

<h3>New Detections</h3>

<table border='1'
       cellpadding='5'
       cellspacing='0'
       style='border-collapse:collapse;width:100%'>

<tr style='background-color:#0078D4;color:white'>

<th>User</th>
<th>Risk Level</th>
<th>Risk Event</th>
<th>Location</th>
<th>IP Address</th>
<th>Detected</th>

</tr>

$($DetectionRows -join "`n")

</table>

<br>

<h3 style='font-family:Segoe UI,Arial;color:#323130;'>
Sign-In Investigation Details
</h3>

<table cellpadding='0'
cellspacing='0'
border='0'
style='border-collapse:collapse;
width:100%;
font-family:Segoe UI,Arial;
font-size:9pt;'>

<tr style='background-color:#323130;color:white;'>
<th style='padding:7px;border:1px solid #605e5c;'>User</th>
<th style='padding:7px;border:1px solid #605e5c;'>Risk Detail</th>
<th style='padding:7px;border:1px solid #605e5c;'>Sign-In Found</th>
<th style='padding:7px;border:1px solid #605e5c;'>Status</th>
<th style='padding:7px;border:1px solid #605e5c;'>Application</th>
<th style='padding:7px;border:1px solid #605e5c;'>Client</th>
<th style='padding:7px;border:1px solid #605e5c;'>Sign-In IP</th>
<th style='padding:7px;border:1px solid #605e5c;'>OS / Browser</th>
<th style='padding:7px;border:1px solid #605e5c;'>Device</th>
<th style='padding:7px;border:1px solid #605e5c;'>Conditional Access</th>
<th style='padding:7px;border:1px solid #605e5c;'>User Agent</th>
<th style='padding:7px;border:1px solid #605e5c;'>MITRE</th>
<th style='padding:7px;border:1px solid #605e5c;'>Correlation ID</th>
</tr>

$($InvestigationRows -join "`r`n")

</table>

<br>

<div style='font-size:8pt;color:#666;'>

Generated: $(Get-Date)

</div>



</body>
</html>
"@
}

#endregion

try {

    Write-Log `
    -Level "INFO" `
    -Message "========== Script Started =========="

    Write-Log "Importing Microsoft Graph module"

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    Write-Log "Connecting to Microsoft Graph"

    Connect-MgGraph `
        -TenantId $TenantId `
        -ClientId $ClientId `
        -CertificateThumbprint $Thumbprint `
        -NoWelcome `
        -ErrorAction Stop

    $Context = Get-MgContext

    Write-Log "Connected successfully"
    Write-Log "Tenant: $($Context.TenantId)"
    Write-Log "Client: $($Context.ClientId)"

    Write-Log "Testing Graph query"

    $Uri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$top=10"

    $Response = Invoke-MgGraphRequest `
        -Method GET `
        -Uri $Uri `
        -ErrorAction Stop

    Write-Log "Retrieved $($Response.value.Count) risk detections"

    $Response.value |
        Select-Object `
            riskEventType,
            riskLevel,
            riskState,
            detectedDateTime,
            ipAddress |
        Format-Table -AutoSize

$ProcessedIds = @(Get-ProcessedDetectionIds -Path $StateFilePath)

if (-not $ProcessedIds) {
    $ProcessedIds = @()
}

$CurrentDetections = @(Get-EntraRiskDetections)

if (-not (Test-Path $StateFilePath)) {

    Save-ProcessedDetectionIds `
        -Path $StateFilePath `
        -Ids $CurrentDetections.Id

    Write-Log "Initial baseline created. No alerts generated."

    return
}

$NewDetections = @(
    $CurrentDetections | Where-Object {
        $_.Id -notin $ProcessedIds
    }
)

$NewDetections | ForEach-Object {

    Write-Log `
        -Level "DEBUG" `
        -Message (
            "New Detection: Id=[{0}] User=[{1}] CorrelationId=[{2}]" -f
            $_.Id,
            $_.UserPrincipalName,
            $_.CorrelationId
        )
}

Write-Log `
    -Level "DEBUG" `
    -Message "===== New Detection List ====="

$NewDetections |
ForEach-Object {

    Write-Log `
        -Level "DEBUG" `
        -Message (
            "DetectionId=[{0}] User=[{1}] CorrelationId=[{2}] Detected=[{3}]" -f
            $_.Id,
            $_.UserPrincipalName,
            $_.CorrelationId,
            $_.DetectedDateTime
        )
}

Write-Log `
    -Level "INFO" `
    -Message "$($CurrentDetections.Count) total detections retrieved."

Write-Log `
    -Level "INFO" `
    -Message "$($NewDetections.Count) new detections identified."

$ExpandedDetections = @(
    foreach ($Detection in $NewDetections) {

        Expand-RiskDetection -Detection $Detection
    }
)

$ExpandedDetections = @(
    $ExpandedDetections |
        Sort-Object DetectedDateTime -Descending
)

if ($ExpandedDetections.Count -gt 0) {

	Write-Log `
	    -Level "INFO" `
	    -Message "$($ExpandedDetections.Count) detections prepared for alert email."

    $ExpandedDetections |
        Select-Object `
            UserDisplayName,
            UserPrincipalName,
            RiskLevel,
            RiskState,
            RiskEventType,
            RiskDetail,
            CorrelationId,
            IPAddress,
            City,
            State,
            CountryOrRegion,
            UserAgent,
            MitreTechniques,
            AdditionalDetails,
            ActivityDateTime,
            DetectedDateTime |
        Sort-Object DetectedDateTime -Descending |
        Format-Table -AutoSize
        
    $ExpandedDetections |
	ForEach-Object {
	
	    Write-Log `
	        -Level "DEBUG" `
	        -Message (
	            "Expanded Object: User=[{0}] App=[{1}] SignInIP=[{2}]" -f
	            $_.UserPrincipalName,
	            $_.AppDisplayName,
	            $_.SignInIPAddress
	        )
	}

    $EmailSent = Send-EntraRiskAlert `
        -Detections $ExpandedDetections `
        -From $EmailFrom `
        -To $EmailTo `
        -SmtpServer $SmtpServer

    if ($EmailSent) {

        $AllIds = @(
            $ProcessedIds
            $NewDetections.Id
        ) |
        Sort-Object -Unique

        Save-ProcessedDetectionIds `
            -Path $StateFilePath `
            -Ids $AllIds

        Write-Log "Processed detection IDs saved."
    }
    else {

        Write-Log `
            -Message "Alert email failed. State file not updated." `
            -Level "ERROR"
    }
}
else {

    Write-Host "No new detections found."
}

}   # <-- This closes TRY

catch {

	Write-Log `
	    -Level "ERROR" `
	    -Message (
	        "Line: {0}" -f
	        $_.InvocationInfo.ScriptLineNumber
	    )
	
	Write-Log `
	    -Level "ERROR" `
	    -Message (
	        "Command: {0}" -f
	        $_.InvocationInfo.Line.Trim()
	    )

    Write-Log `
        -Level "DEBUG" `
        -Message (
            "Stack: {0}" -f
            $_.ScriptStackTrace
        )
}
finally {
	try {
		Disconnect-MgGraph | Out-Null
		Write-Log `
			-Level "INFO" `
			-Message "Disconnected from Microsoft Graph."
	}
	catch {
		Write-Log `
			-Level "WARN" `
			-Message "Disconnect-MgGraph failed."
	}
    Write-Log `
	    -Level "INFO" `
	    -Message "========== Script Completed =========="
}