
#region initialize

# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Replace with your Log Analytics Workspace ID
$CustomerId = ""  

# Replace with your Primary Key
$SharedKey = ""

# Replace with your Custom Log name in Log Analytics
$DeviceLogName = ""

# Optional: keep blank; Azure Monitor will use ingestion time if not set
$TimeStampField = ""

#endregion initialize

# Function to create the authorization signature
Function New-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
    return $authorization
}

# Function to create and post the request
Function Send-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = New-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://${customerId}.ods.opinsights.azure.com${resource}?api-version=2016-04-01"
    # Validate that payload data does not exceed limits
    if ($body.Length -gt (31.9 *1024*1024)) {
        throw("Upload payload is too big and exceeds the 32Mb limit. Current payload size: " + ($body.Length/1024/1024).ToString("#.#") + "Mb")
    }
    $payloadsize = ("Upload payload size is " + ($body.Length/1024).ToString("#.#") + "Kb ")
    $headers = @{
        "Authorization"        = $signature
        "Log-Type"             = $logType
        "x-ms-date"            = $rfc1123date
        "time-generated-field" = $TimeStampField
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    $statusmessage = "$($response.StatusCode) : $($payloadsize)"
    return $statusmessage 
}

# Capture device details
$deviceName = $env:COMPUTERNAME
$loginName = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
if (-not $loginName) { $loginName = $env:USERNAME }

# Extract UPN using regex
$dsreg = dsregcmd /status
$upn = ($dsreg | Select-String "Executing Account Name").ToString().Split(",")[1].Trim()

# Get Serial Number and OS Version
$serialNumber = (Get-CimInstance Win32_BIOS).SerialNumber
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
$firmwareType = $env:firmware_type

# Get Country based on public IP
try {
    $publicIP = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json").ip
    $geoInfo  = Invoke-RestMethod -Uri "https://ipinfo.io/$publicIP/json"
    $country  = $geoInfo.country
} catch {
    $country = "Unable to retrieve country"
}

# Secure Boot checks
try {
    $secureBootStatus = Confirm-SecureBootUEFI
} catch {
    $secureBootStatus = "Secure Boot status could not be determined. System may not support UEFI."
}

try {
    $secureBootUpdateStatus = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
} catch {
    $secureBootUpdateStatus = "Secure Boot Update status could not be determined."
}

$secureBootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$servicingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$availableKey = "AvailableUpdates"
$statusKey = "UEFICA2023Status"
$secureBootUpdateState = "Unknown"

try {
    $availableUpdates = (Get-ItemProperty -Path $secureBootPath -Name $availableKey -ErrorAction Stop).$availableKey
    if ($availableUpdates -eq 0) {
        $secureBootUpdateEnabled = "False"
    } else {
        $secureBootUpdateEnabled = "True"
        try {
            $secureBootUpdateState = (Get-ItemProperty -Path $servicingPath -Name $statusKey -ErrorAction Stop).$statusKey
        } catch {
            $secureBootUpdateState = "UEFICA2023Status key not found."
        }
    }
} catch {
    $secureBootUpdateEnabled = "Registry key not found or inaccessible."
}

# Create inventory payload
$Inventory = [pscustomobject]@{
    DeviceName                = $deviceName
    Username                  = $loginName
    UserUPN                   = $upn
    SerialNumber              = $serialNumber
    OSVersion                 = $osVersion
    FirmwareType              = $firmwareType
    Country                   = $country
    SecureBootState           = $secureBootStatus
    SecureBootUpdateStatus    = $secureBootUpdateStatus
    SecureBootUpdateEnabled   = $secureBootUpdateEnabled
    SecureBootUpdateState     = $secureBootUpdateState
}

# Convert to JSON and send to Log Analytics
$DeviceJson = $Inventory | ConvertTo-Json -Depth 5 -Compress
$ResponseDeviceInventory = Send-LogAnalyticsData $CustomerId $SharedKey ([System.Text.Encoding]::UTF8.GetBytes($DeviceJson)) $DeviceLogName

# Output results
$date = Get-Date -Format "dd-MM HH:mm"
if ($ResponseDeviceInventory -match "200 :") {
    Write-Host "InventoryDate: $date - DeviceInventory: SUCCESS - $ResponseDeviceInventory"
} else {
    Write-Host "InventoryDate: $date - DeviceInventory: FAILED - $ResponseDeviceInventory"
}

Write-Host ("DeviceName: {0}`nUsername: {1}`nUserUPN: {2}`nSerialNumber: {3}`nOSVersion: {4}`nFirmwareType: {5}`nCountry: {6}`nSecureBootState: {7}`nSecureBootUpdateStatus: {8}`nSecureBootUpdateEnabled: {9}`nSecureBootUpdateState: {10}" -f `
    $deviceName, $loginName, $upn, $serialNumber, $osVersion, $firmwareType, $country, $secureBootStatus, $secureBootUpdateStatus, $secureBootUpdateEnabled, $secureBootUpdateState)
