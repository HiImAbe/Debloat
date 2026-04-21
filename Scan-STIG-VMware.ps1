# =============================================================================
# Scan-STIG-VMware.ps1
# VMware vSphere 8.0 Virtual Machine STIG Scanner (V2R1)
# Scans VMs against DISA STIG checks defined in JSON, updates CKL per VM,
# and exports a combined CSV summary.
#
# Supported CheckTypes:
#   - AdvancedSetting     (standard value, ABSENT, wildcard, MissingIsPass)
#   - VirtualDevice       (Floppy, CD/DVD, USB, Serial, Parallel, ConnectedOnly)
#   - VMConfig            (ExtensionData.Config properties, supports nested paths)
#   - VirtualDisk         (persistence mode)
#   - PassthroughDevice   (DirectPath I/O / PCI passthrough) -- new for 8.0
# =============================================================================

param(
    [Parameter(Mandatory)]
    [string]$vCenterServer,

    [Parameter(Mandatory)]
    [string]$TemplatePath,

    [Parameter(Mandatory)]
    [string[]]$VMName,

    [string]$ConfigPath   = '.\STIG_VMware80_VM.json',
    [string]$OutputFolder = '.\Output'
)

# =============================================================================
# FUNCTIONS
# =============================================================================

function Update-STIGCKL {
    param(
        [Parameter(Mandatory)]
        [xml]$Ckl,

        [Parameter(Mandatory)]
        [string]$VulnID,

        [Parameter(Mandatory)]
        [ValidateSet('Open', 'NotAFinding', 'Not_Applicable', 'Not_Reviewed')]
        [string]$Status,

        [string]$Details,
        [string]$Comments
    )

    $vulnNode = $Ckl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object {
        ($_.STIG_DATA | Where-Object {
            $_.VULN_ATTRIBUTE -eq 'Vuln_Num' -and $_.ATTRIBUTE_DATA -eq $VulnID
        })
    }

    if (-not $vulnNode) {
        Write-Warning "$VulnID not found in CKL template"
        return $false
    }

    $vulnNode.STATUS = $Status

    if ($Details) {
        $vulnNode.FINDING_DETAILS = $Details
    }

    if ($Comments) {
        $vulnNode.COMMENTS = $Comments
    }

    return $true
}

function Save-CKL {
    param(
        [Parameter(Mandatory)]
        [xml]$Ckl,

        [Parameter(Mandatory)]
        [string]$Path
    )

    # XmlWriter preserves tab indentation and UTF-8 no BOM (STIG Viewer schema)
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent       = $true
    $settings.IndentChars  = "`t"
    $settings.Encoding     = [System.Text.UTF8Encoding]::new($false)

    $writer = [System.Xml.XmlWriter]::Create($Path, $settings)
    $Ckl.Save($writer)
    $writer.Close()
}

function Get-NestedProperty {
    <#
    .SYNOPSIS
      Walks a dotted property path (e.g., Flags.EnableLogging) on an object.
    .DESCRIPTION
      Used by the VMConfig handler because some 8.0 checks (V-258720) live
      under nested structures like ExtensionData.Config.Flags.EnableLogging.
      Returns $null if any segment is missing.
    #>
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $current = $InputObject
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        $current = $current.$segment
    }
    return $current
}

# =============================================================================
# CHECK HANDLERS
# =============================================================================
# Each handler receives:
#   -VM     : The VM object from Get-VM
#   -Params : Hashtable of parameters from CheckParams in the JSON
#
# Each handler returns a hashtable:
#   @{ Status = 'NotAFinding' | 'Open' | 'Not_Applicable'; Details = 'explanation' }
# =============================================================================

$CheckHandlers = @{

    # -----------------------------------------------------------------
    # AdvancedSetting
    # Checks VM advanced settings via Get-AdvancedSetting.
    # Supports:
    #   - Standard value comparison
    #   - ABSENT (setting must NOT exist)
    #   - Wildcard pattern matching (e.g., ethernet*.filter*.name*)
    #   - MissingIsPass (for "does not exist = not a finding" checks)
    # -----------------------------------------------------------------
    'AdvancedSetting' = {
        param($VM, $Params)

        $settingName    = $Params.Name
        $expectedValue  = $Params.ExpectedValue
        $missingIsPass  = [bool]$Params.MissingIsPass

        # --- ABSENT: setting should not exist ---
        if ($expectedValue -eq 'ABSENT') {

            if ($settingName -match '\*') {
                # Wildcard - pass directly to -Name (DISA-documented approach)
                $matches = $VM | Get-AdvancedSetting -Name $settingName -ErrorAction SilentlyContinue
                if (($matches | Measure-Object).Count -gt 0) {
                    $names = ($matches | ForEach-Object { $_.Name }) -join ', '
                    return @{
                        Status  = 'Open'
                        Details = "Found settings matching '$settingName': $names. These should be removed."
                    }
                }
                else {
                    return @{
                        Status  = 'NotAFinding'
                        Details = "No settings matching '$settingName' found."
                    }
                }
            }
            else {
                $setting = $VM | Get-AdvancedSetting -Name $settingName -ErrorAction SilentlyContinue
                if ($setting) {
                    return @{
                        Status  = 'Open'
                        Details = "'$settingName' exists (value: $($setting.Value)) and should be removed."
                    }
                }
                else {
                    return @{
                        Status  = 'NotAFinding'
                        Details = "'$settingName' does not exist."
                    }
                }
            }
        }

        # --- Standard value check ---
        $setting = $VM | Get-AdvancedSetting -Name $settingName -ErrorAction SilentlyContinue

        if (-not $setting) {
            if ($missingIsPass) {
                return @{
                    Status  = 'NotAFinding'
                    Details = "Setting '$settingName' does not exist (default-safe, not a finding per STIG)."
                }
            }
            else {
                return @{
                    Status  = 'Open'
                    Details = "Setting '$settingName' is not configured."
                }
            }
        }
        elseif ([string]$setting.Value -eq [string]$expectedValue) {
            return @{
                Status  = 'NotAFinding'
                Details = "$settingName = $($setting.Value)"
            }
        }
        else {
            return @{
                Status  = 'Open'
                Details = "$settingName = $($setting.Value), expected $expectedValue"
            }
        }
    }

    # -----------------------------------------------------------------
    # VirtualDevice
    # Checks for presence/absence of virtual hardware.
    # Supports ConnectedOnly for CD/DVD (V-258723) where only *connected*
    # drives are a finding (disconnected drives are acceptable).
    # -----------------------------------------------------------------
    'VirtualDevice' = {
        param($VM, $Params)

        $devices = switch ($Params.DeviceType) {
            'Floppy' {
                $VM | Get-FloppyDrive
            }
            'CD/DVD' {
                if ([bool]$Params.ConnectedOnly) {
                    $VM | Get-CDDrive | Where-Object {
                        $_.ExtensionData.Connectable.Connected -eq $true
                    }
                }
                else {
                    $VM | Get-CDDrive
                }
            }
            'USB' {
                # USB controllers (both xHCI and older) AND any passed-through USB devices
                $controllers = $VM.ExtensionData.Config.Hardware.Device | Where-Object {
                    $_ -is [VMware.Vim.VirtualUSBController] -or
                    $_ -is [VMware.Vim.VirtualUSBXHCIController]
                }
                $usbDevices  = $VM | Get-UsbDevice -ErrorAction SilentlyContinue
                @($controllers) + @($usbDevices) | Where-Object { $_ }
            }
            'Serial' {
                # STIG V-258725 matches by label (catches VirtualSerialPort and variants)
                $VM.ExtensionData.Config.Hardware.Device |
                    Where-Object { $_.DeviceInfo.Label -match 'serial' }
            }
            'Parallel' {
                # STIG V-258724 matches by label
                $VM.ExtensionData.Config.Hardware.Device |
                    Where-Object { $_.DeviceInfo.Label -match 'parallel' }
            }
        }

        $hasDevice = ($devices | Measure-Object).Count -gt 0

        if ($Params.ShouldExist -eq $false) {
            if ($hasDevice) {
                $labels = ($devices | ForEach-Object {
                    if     ($_.Name)        { $_.Name }
                    elseif ($_.DeviceInfo)  { $_.DeviceInfo.Label }
                    else                    { $_.GetType().Name }
                }) -join ', '
                @{ Status = 'Open'; Details = "$($Params.DeviceType) device(s) present: $labels. Should be removed." }
            }
            else {
                @{ Status = 'NotAFinding'; Details = "No $($Params.DeviceType) devices found." }
            }
        }
        else {
            if ($hasDevice) {
                @{ Status = 'NotAFinding'; Details = "$($Params.DeviceType) device is present as required." }
            }
            else {
                @{ Status = 'Open'; Details = "$($Params.DeviceType) device not found but is required." }
            }
        }
    }

    # -----------------------------------------------------------------
    # VMConfig
    # Checks VM-level config properties via ExtensionData.Config.
    # Supports dotted property paths (e.g., Flags.EnableLogging).
    # ExpectedValues is an array; any match passes.
    # NA_When_Null: treat null as Not Applicable (e.g., FT not enabled).
    # -----------------------------------------------------------------
    'VMConfig' = {
        param($VM, $Params)

        $propPath = $Params.Property
        $value    = Get-NestedProperty -InputObject $VM.ExtensionData.Config -Path $propPath

        if ($null -eq $value) {
            if ([bool]$Params.NA_When_Null) {
                return @{
                    Status  = 'Not_Applicable'
                    Details = if ($Params.NA_Reason) { $Params.NA_Reason } else { "Property '$propPath' not present; check not applicable." }
                }
            }
            else {
                return @{
                    Status  = 'Open'
                    Details = "Property '$propPath' is not configured."
                }
            }
        }

        # Compare as string for flexibility (handles bool, enum, string uniformly)
        $strValue = [string]$value
        $expected = @($Params.ExpectedValues | ForEach-Object { [string]$_ })

        if ($expected -contains $strValue) {
            return @{
                Status  = 'NotAFinding'
                Details = "$propPath = $strValue"
            }
        }
        else {
            return @{
                Status  = 'Open'
                Details = "$propPath = $strValue, expected one of: $($expected -join ', ')"
            }
        }
    }

    # -----------------------------------------------------------------
    # VirtualDisk
    # Checks disk persistence modes via Get-HardDisk.
    # -----------------------------------------------------------------
    'VirtualDisk' = {
        param($VM, $Params)

        $disks         = $VM | Get-HardDisk
        $matchingDisks = $disks | Where-Object { $_.Persistence -eq $Params.Persistence }
        $hasMatching   = ($matchingDisks | Measure-Object).Count -gt 0

        if ($Params.ShouldExist -eq $false) {
            if ($hasMatching) {
                $diskNames = ($matchingDisks | ForEach-Object { $_.Name }) -join ', '
                @{ Status = 'Open'; Details = "Found $($Params.Persistence) disk(s): $diskNames" }
            }
            else {
                @{ Status = 'NotAFinding'; Details = "No $($Params.Persistence) disks found." }
            }
        }
        else {
            if ($hasMatching) {
                @{ Status = 'NotAFinding'; Details = "$($Params.Persistence) disk(s) present as required." }
            }
            else {
                @{ Status = 'Open'; Details = "No $($Params.Persistence) disks found but required." }
            }
        }
    }

    # -----------------------------------------------------------------
    # PassthroughDevice (new for 8.0)
    # Checks for DirectPath I/O / PCI passthrough devices (V-258727).
    # -----------------------------------------------------------------
    'PassthroughDevice' = {
        param($VM, $Params)

        $passthrough = $VM | Get-PassthroughDevice -ErrorAction SilentlyContinue
        $hasDevices  = ($passthrough | Measure-Object).Count -gt 0

        if ($Params.ShouldExist -eq $false) {
            if ($hasDevices) {
                $labels = ($passthrough | ForEach-Object { $_.Name }) -join ', '
                @{ Status = 'Open'; Details = "DirectPath I/O devices present: $labels. Review for documented approval." }
            }
            else {
                @{ Status = 'NotAFinding'; Details = "No DirectPath I/O devices attached." }
            }
        }
        else {
            if ($hasDevices) {
                @{ Status = 'NotAFinding'; Details = "Passthrough device is present as required." }
            }
            else {
                @{ Status = 'Open'; Details = "Passthrough device required but not found." }
            }
        }
    }
}

# =============================================================================
# MAIN
# =============================================================================

if (-not $global:DefaultVIServer) {
    Connect-VIServer -Server $vCenterServer
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$config     = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$allResults = [System.Collections.ArrayList]::new()
$vulnCount  = ($config.Vulnerabilities.PSObject.Properties | Measure-Object).Count

foreach ($name in $VMName) {
    Write-Host "`n$('=' * 50)" -ForegroundColor Cyan
    Write-Host "Scanning $name..." -ForegroundColor Cyan

    $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Warning "VM not found: $name"
        continue
    }

    # Create CKL from template
    $cklPath = Join-Path $OutputFolder "$name.ckl"
    [xml]$ckl = Get-Content -Path $TemplatePath -Raw

    $ckl.CHECKLIST.ASSET.HOST_NAME = $vm.Name
    $ckl.CHECKLIST.ASSET.HOST_FQDN = $vm.Name

    foreach ($vulnId in $config.Vulnerabilities.PSObject.Properties.Name) {
        $vuln = $config.Vulnerabilities.$vulnId

        $status       = $null
        $details      = $null
        $canRemediate = $false

        switch ($vuln.Action) {
            'Skip' {
                $status  = 'Not_Reviewed'
                $details = "Skipped: $($vuln.SkipReason)"
            }
            'NotApplicable' {
                $status  = 'Not_Applicable'
                $details = $vuln.NotApplicableReason
            }
            { $_ -in 'CheckOnly', 'CheckAndRemediate' } {
                $handler = $CheckHandlers[$vuln.CheckType]

                if (-not $handler) {
                    $status  = 'Not_Reviewed'
                    $details = "No handler registered for CheckType '$($vuln.CheckType)'."
                    break
                }

                $paramsHash = @{}
                $vuln.CheckParams.PSObject.Properties | ForEach-Object { $paramsHash[$_.Name] = $_.Value }

                try {
                    $result = & $handler -VM $vm -Params $paramsHash
                    $status  = $result.Status
                    $details = $result.Details
                }
                catch {
                    $status  = 'Not_Reviewed'
                    $details = "Handler error: $_"
                }

                if ($status -eq 'Open' -and $vuln.Action -eq 'CheckAndRemediate') {
                    $canRemediate = $true
                }

                if ($vuln.Action -eq 'CheckOnly' -and $status -eq 'Open' -and $vuln.ManualRemediationNote) {
                    $details += " | Manual: $($vuln.ManualRemediationNote)"
                }

                # On pass, prefer pre-written FindingDetails from JSON if present
                if ($status -eq 'NotAFinding' -and $vuln.FindingDetails) {
                    $details = $vuln.FindingDetails
                }
            }
        }

        Update-STIGCKL -Ckl $ckl `
                       -VulnID $vulnId `
                       -Status $status `
                       -Details $details `
                       -Comments "Scanned $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

        [void]$allResults.Add([PSCustomObject]@{
            VMName       = $vm.Name
            Host         = $vm.VMHost.Name
            PowerState   = $vm.PowerState
            VulnID       = $vulnId
            RuleVersion  = $vuln.RuleVersion
            Title        = $vuln.Title
            Severity     = $vuln.Severity
            Status       = $status
            Details      = $details
            CanRemediate = $canRemediate
        })

        $color = switch ($status) {
            'Open'           { 'Red' }
            'NotAFinding'    { 'Green' }
            'Not_Applicable' { 'DarkGray' }
            default          { 'Yellow' }
        }
        Write-Host "  $vulnId : $status" -ForegroundColor $color
    }

    Save-CKL -Ckl $ckl -Path $cklPath
    Write-Host "CKL saved: $cklPath" -ForegroundColor Green
}

# =============================================================================
# CSV EXPORT
# =============================================================================

$csvPath = Join-Path $OutputFolder "ScanResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$allResults | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nCSV saved: $csvPath" -ForegroundColor Green

# =============================================================================
# SUMMARY
# =============================================================================

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "  VMs scanned:  $($VMName.Count)"
Write-Host "  Vulns per VM: $vulnCount"
Write-Host ""

$allResults | Group-Object Status | Sort-Object Name | ForEach-Object {
    $color = switch ($_.Name) {
        'Open'           { 'Red' }
        'NotAFinding'    { 'Green' }
        'Not_Applicable' { 'DarkGray' }
        default          { 'Yellow' }
    }
    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor $color
}

$openFindings = $allResults | Where-Object { $_.Status -eq 'Open' }
if ($openFindings) {
    Write-Host "`n  Open Findings:" -ForegroundColor Red
    $openFindings | ForEach-Object {
        Write-Host "    $($_.VMName) | $($_.VulnID) [$($_.Severity)] | $($_.Title)" -ForegroundColor Red
    }
}

Write-Host ""
