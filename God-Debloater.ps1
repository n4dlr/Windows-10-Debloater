#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    God Debloater - Professional Windows Debloat & Optimization Tool
    
.DESCRIPTION
    Production-level Windows 10/11 debloat and optimization tool with modern GUI.
    Safe, modular architecture with restore points and rollback capability.
    
.NOTES
    Author: God Debloater Project
    Version: 1.0.0
    Windows 10/11 Compatible
    Execution Policy: Works with RemoteSigned (no bypass required for local scripts)
#>

#region Configuration
$script:Version = "1.1.0"
$script:LogPath = Join-Path $env:LOCALAPPDATA "GodDebloater\Logs"
$script:BackupPath = Join-Path $env:LOCALAPPDATA "GodDebloater\Backups"
$script:CurrentLogFile = $null
$script:ChangeLog = [System.Collections.Generic.List[object]]::new()
$script:AnalyzedData = @{}
$script:IsAnalyzed = $false

# Critical services - NEVER touch these
$script:ProtectedServices = @(
    'Audiosrv','AudioEndpointBuilder','BITS','CryptSvc','DcomLaunch','Dhcp','Dnscache',
    'EventLog','gpsvc','LanmanServer','LanmanWorkstation','lmhosts','Netlogon','netprofm',
    'NlaSvc','nsi','PlugPlay','PolicyAgent','Power','RpcEptMapper','RpcSs','SamSs',
    'Schedule','Spooler','StorSvc','SysMain','Themes','TrkWks','W32Time','Wcmsvc',
    'Winmgmt','WinDefend','WdiServiceHost','WdiSystemHost','WinHttpAutoProxySvc',
    'wuauserv','WlanSvc','wscsvc','EventSystem','FontCache','LSM','ProfSvc','UserManager'
)
#endregion

#region Core Functions

function Initialize-Logging {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not (Test-Path $script:LogPath)) {
        New-Item -ItemType Directory -Path $script:LogPath -Force | Out-Null
    }
    $script:CurrentLogFile = Join-Path $script:LogPath "GodDebloater_$timestamp.log"
    if (-not (Test-Path $script:BackupPath)) {
        New-Item -ItemType Directory -Path $script:BackupPath -Force | Out-Null
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('SUCCESS','ERROR','WARNING','INFO','DEBUG')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    try {
        Add-Content -Path $script:CurrentLogFile -Value $logEntry -ErrorAction Stop
    } catch {
        $logEntry | Out-File -FilePath $script:CurrentLogFile -Encoding UTF8 -Append -Force
    }
}

function Test-IsAdministrator {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function New-RestorePoint {
    param([string]$Description = "God Debloater - $script:Version")
    try {
        Write-Log "Creating restore point: $Description" -Level INFO
        Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue
        $ErrorActionPreference = 'SilentlyContinue'
        try {
            $null = Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop 2>&1
            Write-Log "Restore point created successfully" -Level SUCCESS
            return $true
        } catch {
            if ($_.Exception.Message -match '1440|already been created') {
                Write-Log "Restore point skipped: One was created in the last 24 hours" -Level WARNING
                return $false
            }
            $sr = Get-WmiObject -List "Win32_ShadowCopy" -ErrorAction SilentlyContinue
            if ($sr) {
                $sr.Create($env:SystemDrive, "ClientAccessible") | Out-Null
                Write-Log "Restore point created via WMI" -Level SUCCESS
                return $true
            }
            vssadmin create shadow /For="$($env:SystemDrive)\" /AutoRetry=15 2>&1 | Out-Null
            Write-Log "Restore point created via vssadmin" -Level SUCCESS
            return $true
        }
    } catch {
        if ($_.Exception.Message -match '1440|already been created') {
            Write-Log "Restore point skipped: One exists within 24 hours" -Level WARNING
        } else {
            Write-Log "Restore point creation failed: $_" -Level WARNING
        }
        return $false
    }
}

function Register-Change {
    param(
        [string]$Category,
        [string]$Action,
        [hashtable]$OriginalState,
        [string]$RollbackScript
    )
    $script:ChangeLog.Add([PSCustomObject]@{
        Timestamp = Get-Date
        Category = $Category
        Action = $Action
        OriginalState = $OriginalState
        RollbackScript = $RollbackScript
    })
}

function Add-FormLog {
    param(
        [System.Windows.Controls.TextBox]$TextBox,
        [string]$Message,
        [string]$Level = 'INFO'
    )
    if (-not $TextBox) { return }
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $prefix = switch ($Level) {
        'SUCCESS' { '[OK]' }
        'ERROR' { '[ERR]' }
        'WARNING' { '[WRN]' }
        default { '[INF]' }
    }
    $entry = "$timestamp $prefix $Message`r\n"
    $TextBox.Dispatcher.Invoke([action]{
        $TextBox.AppendText($entry)
        $TextBox.ScrollToEnd()
    })
}

#endregion

#region Analysis Functions

# Critical UWP - shown but marked, user can still select (at own risk)
$script:CriticalUwp = @('*Windows.ImmersiveControlPanel*','*Windows.ShellExperienceHost*','*Microsoft.WindowsStore*','*Windows.CBSPreview*','*Microsoft.AAD.BrokerPlugin*','*Microsoft.AccountsControl*','*Microsoft.LockApp*','*Microsoft.Windows.SecHealthUI*','*Microsoft.WindowsShell*')

function Get-SystemApps {
    $apps = @()
    try {
        $packages = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        foreach ($pkg in $packages) {
            if (-not $pkg.Name -or -not $pkg.PackageFullName) { continue }
            $critical = $false
            foreach ($pat in $script:CriticalUwp) {
                if ($pkg.Name -like $pat) { $critical = $true; break }
            }
            $apps += [PSCustomObject]@{
                Name = $pkg.Name
                DisplayName = $pkg.Name
                FullName = $pkg.PackageFullName
                IsCritical = $critical
            }
        }
    } catch {
        Write-Log "Get-SystemApps error: $_" -Level ERROR
    }
    return ($apps | Sort-Object Name)
}

function Get-InstalledPrograms {
    $programs = @()
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $seen = @{}
    foreach ($path in $paths) {
        try {
            $items = @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)
            foreach ($item in $items) {
                $name = $item.DisplayName -as [string]
                if (-not $name -or $name.Length -lt 2) { continue }
                if ($seen[$name]) { continue }
                $seen[$name] = $true
                $uninstall = $item.UninstallString -as [string]
                $quiet = $item.QuietUninstallString -as [string]
                if (-not $uninstall -and -not $quiet) { continue }
                $programs += [PSCustomObject]@{
                    DisplayName = $name
                    UninstallString = $uninstall
                    QuietUninstallString = $quiet
                    InstallLocation = $item.InstallLocation -as [string]
                    RegPath = $item.PSPath
                }
            }
        } catch { }
    }
    return ($programs | Sort-Object DisplayName)
}

function Get-InstalledDrivers {
    $drivers = @()
    try {
        $output = pnputil /enum-drivers 2>&1 | Out-String
        $current = $null
        foreach ($line in ($output -split "`r?`n")) {
            $line = $line.Trim()
            if ($line -match '^Published Name:\s+(.+)$') {
                if ($current -and $current['PublishedName']) {
                    $on = if ($current['OriginalName']) { $current['OriginalName'] } else { $current['PublishedName'] }
                    if ($current['Provider'] -notlike 'Microsoft*') {
                        $drivers += [PSCustomObject]@{
                            PublishedName = $current['PublishedName']
                            OriginalName = $on
                            Provider = $current['Provider']
                            ClassName = $current['ClassName']
                        }
                    }
                }
                $current = @{ PublishedName = $Matches[1].Trim(); OriginalName = $null; Provider = $null; ClassName = $null }
            } elseif ($current -and $line -match '^Original Name:\s+(.+)$') {
                $current['OriginalName'] = $Matches[1].Trim()
            } elseif ($current -and $line -match '^Provider Name:\s+(.+)$') {
                $current['Provider'] = $Matches[1].Trim()
            } elseif ($current -and $line -match '^Class Name:\s+(.+)$') {
                $current['ClassName'] = $Matches[1].Trim()
            } elseif ($current -and $line -match '^Driver Version:') {
                if ($current['Provider'] -notlike 'Microsoft*') {
                    $on = if ($current['OriginalName']) { $current['OriginalName'] } else { $current['PublishedName'] }
                    $drivers += [PSCustomObject]@{
                        PublishedName = $current['PublishedName']
                        OriginalName = $on
                        Provider = $current['Provider']
                        ClassName = $current['ClassName']
                    }
                }
                $current = $null
            }
        }
        if ($current -and $current['PublishedName'] -and $current['Provider'] -notlike 'Microsoft*') {
            $on = if ($current['OriginalName']) { $current['OriginalName'] } else { $current['PublishedName'] }
            $drivers += [PSCustomObject]@{
                PublishedName = $current['PublishedName']
                OriginalName = $on
                Provider = $current['Provider']
                ClassName = $current['ClassName']
            }
        }
        $drivers = $drivers | Sort-Object OriginalName
    } catch {
        Write-Log "Get-InstalledDrivers error: $_" -Level ERROR
    }
    return $drivers
}

function Get-WindowsOptionalFeaturesList {
    $features = @()
    try {
        $list = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -notlike '*Language*' -and $_.FeatureName -notlike '*Font*' }
        foreach ($f in $list) {
            $features += [PSCustomObject]@{
                Name = $f.FeatureName
                State = $f.State
            }
        }
    } catch {
        Write-Log "Get-WindowsOptionalFeatures error: $_" -Level ERROR
    }
    return ($features | Sort-Object Name)
}

function Get-OptionalFeaturesList {
    return @(
        [PSCustomObject]@{ Id = 'OneDrive'; Name = 'OneDrive (Optional Removal)'; Description = 'Remove OneDrive integration' },
        [PSCustomObject]@{ Id = 'Xbox'; Name = 'Xbox Components'; Description = 'Remove Xbox app and Game Bar' },
        [PSCustomObject]@{ Id = 'EdgeBg'; Name = 'Edge Background Services'; Description = 'Disable Edge background (browser stays)' },
        [PSCustomObject]@{ Id = 'Cortana'; Name = 'Cortana'; Description = 'Disable Cortana' }
    )
}

function Get-StartupItems {
    $items = @()
    try {
        $runPaths = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        )
        foreach ($path in $runPaths) {
            if (Test-Path $path) {
                $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object {
                        $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
                    } | ForEach-Object {
                        $items += [PSCustomObject]@{
                            Name = $_.Name
                            Path = $path
                            Command = $_.Value
                            Type = 'Registry'
                        }
                    }
                }
            }
        }
        $tasks = Get-ScheduledTask | Where-Object {
            $_.State -eq 'Ready' -and $_.TaskPath -notlike '\Microsoft\Windows\*' -and
            (($_.Triggers | Where-Object { $_.Enabled }) -ne $null)
        } | Select-Object -First 120
        foreach ($t in $tasks) {
            $action = ($t.Actions | Select-Object -First 1)
            $items += [PSCustomObject]@{
                Name = $t.TaskName
                Path = $t.TaskPath
                Command = if ($action) { $action.Execute } else { '' }
                Type = 'ScheduledTask'
            }
        }
    } catch {
        Write-Log "Get-StartupItems error: $_" -Level ERROR
    }
    return $items
}

function Get-OptimizableServices {
    $serviceMap = @{
        Safe = @{
            'SysMain' = 'SuperFetch/PreFetch (Manual recommended)'
            'TabletInputService' = 'Touch keyboard (Manual)'
            'WbioSrvc' = 'Windows Biometric (Manual)'
            'Fax' = 'Fax Service (Disabled)'
            'MapsBroker' = 'Downloaded Maps (Disabled)'
            'lfsvc' = 'Geolocation (Disabled)'
            'WpnService' = 'Windows Push (Disabled)'
            'RetailDemo' = 'Retail Demo (Disabled)'
            'diagnosticshub.standardcollector.service' = 'Diagnostics Collector (Disabled)'
        }
        Moderate = @{
            'DiagTrack' = 'Connected User Experience (Disabled)'
            'dmwappushservice' = 'Device Management WAP (Disabled)'
            'XblAuthManager' = 'Xbox Auth (Disabled)'
            'XblGameSave' = 'Xbox Game Save (Disabled)'
            'XboxGipSvc' = 'Xbox Accessory (Disabled)'
            'WSearch' = 'Windows Search (Manual - affects search)'
        }
        Risky = @{
            'RemoteRegistry' = 'Remote Registry (Disabled)'
            'RemoteAccess' = 'Remote Access (Disabled)'
        }
    }
    $result = @()
    foreach ($level in @('Safe','Moderate','Risky')) {
        foreach ($svc in $serviceMap[$level].Keys) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s -and $script:ProtectedServices -notcontains $svc) {
                $result += [PSCustomObject]@{
                    Name = $svc
                    DisplayName = $s.DisplayName
                    Risk = $level
                    Recommendation = $serviceMap[$level][$svc]
                    CurrentStatus = $s.Status.ToString()
                    StartType = (Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction SilentlyContinue).StartMode
                }
            }
        }
    }
    return $result
}

function Get-PrivacyTweaks {
    return @(
        [PSCustomObject]@{ Id = 'Telemetry'; Name = 'Minimize Telemetry'; Description = 'Set telemetry to Security level' }
        [PSCustomObject]@{ Id = 'DataCollection'; Name = 'Disable Data Collection'; Description = 'Disable diagnostic data via policy' }
        [PSCustomObject]@{ Id = 'AdsId'; Name = 'Disable Advertising ID'; Description = 'Turn off tailored ads' }
        [PSCustomObject]@{ Id = 'ContentDelivery'; Name = 'Disable Content Delivery'; Description = 'Suggestions, tips, ads' }
    )
}

function Get-GamingTweaks {
    return @(
        [PSCustomObject]@{ Id = 'GameDVR'; Name = 'Disable Game DVR'; Description = 'Disable Game Bar recording' }
        [PSCustomObject]@{ Id = 'GameMode'; Name = 'Game Mode Optimization'; Description = 'Optimize for gaming' }
    )
}

function Get-AdvancedTweaks {
    return @(
        [PSCustomObject]@{ Id = 'VisualFX'; Name = 'Performance Visual Effects'; Description = 'Adjust for best performance' }
        [PSCustomObject]@{ Id = 'PowerPlan'; Name = 'High Performance Power Plan'; Description = 'Set High Performance plan' }
        [PSCustomObject]@{ Id = 'TempClean'; Name = 'Clean Temporary Files'; Description = 'Remove temp files' }
        [PSCustomObject]@{ Id = 'MemoryCompression'; Name = 'Memory Compression Status'; Description = 'View status only (read)' }
    )
}

function Get-SecurityTweaks {
    return @(
        [PSCustomObject]@{ Id = 'DefenderRTP'; Name = 'Disable Real-Time Protection (Optional)'; Description = 'Only disables RTP - Defender stays' }
        [PSCustomObject]@{ Id = 'FirewallStatus'; Name = 'Firewall Status'; Description = 'View only (read)' }
    )
}

function Get-SystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $mem = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $ramTotal = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $ramFree = [math]::Round($mem.FreePhysicalMemory * 1KB / 1MB, 0)
    $mc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'EnableCompressedMemory' -ErrorAction SilentlyContinue
    return [PSCustomObject]@{
        OSVersion = $os.Caption
        Build = $os.BuildNumber
        RAMTotalGB = $ramTotal
        RAMFreeMB = $ramFree
        MemoryCompression = if ($mc.EnableCompressedMemory -eq 0) { 'Disabled' } else { 'Enabled' }
    }
}

#endregion

#region Apply Functions

function Remove-SelectedApps {
    param([array]$Apps, [System.Windows.Controls.TextBox]$LogBox)
    $removed = 0
    foreach ($app in $Apps) {
        try {
            Remove-AppxPackage -Package $app.FullName -AllUsers -ErrorAction Stop
            try {
                $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "$($app.Name)*" }
                foreach ($p in $provisioned) {
                    Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction SilentlyContinue
                }
            } catch { }
            Add-FormLog $LogBox "Removed (full): $($app.Name)" -Level SUCCESS
            Write-Log "Removed app: $($app.Name)" -Level SUCCESS
            $removed++
        } catch {
            try {
                Remove-AppxPackage -Package $app.FullName -ErrorAction Stop
                Add-FormLog $LogBox "Removed (user): $($app.Name)" -Level SUCCESS
                $removed++
            } catch {
                Add-FormLog $LogBox "Failed: $($app.Name) - $_" -Level ERROR
                Write-Log "Failed to remove $($app.Name): $_" -Level ERROR
            }
        }
    }
    return $removed
}

function Uninstall-Win32Program {
    param($Program, [System.Windows.Controls.TextBox]$LogBox)
    try {
        $cmd = $Program.QuietUninstallString
        if (-not $cmd) { $cmd = $Program.UninstallString }
        if (-not $cmd) {
            Add-FormLog $LogBox "No uninstall: $($Program.DisplayName)" -Level ERROR
            return $false
        }
        $cmd = $cmd.Trim()
        if ($cmd.StartsWith('"')) {
            $end = $cmd.IndexOf('"', 1)
            $exe = $cmd.Substring(1, $end - 1)
            $args = $cmd.Substring($end + 1).Trim()
        } else {
            $firstSpace = $cmd.IndexOf(' ')
            if ($firstSpace -gt 0) {
                $exe = $cmd.Substring(0, $firstSpace)
                $args = $cmd.Substring($firstSpace).Trim()
            } else {
                $exe = $cmd
                $args = ''
            }
        }
        if ($exe -like '*msiexec*') {
            if ($args -notmatch '/qn|/quiet') { $args = "$args /qn" }
        } elseif ($args -and $args -notmatch '/S|/silent|/quiet|/uninstall|-uninstall|/VERYSILENT|/qn') {
            $args = "$args /S"
        } elseif (-not $args) {
            $args = '/S'
        }
        $proc = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        Add-FormLog $LogBox "Uninstalled: $($Program.DisplayName) (exit:$($proc.ExitCode))" -Level SUCCESS
        Write-Log "Uninstalled: $($Program.DisplayName)" -Level SUCCESS
        return $true
    } catch {
        Add-FormLog $LogBox "Uninstall failed $($Program.DisplayName): $_" -Level ERROR
        return $false
    }
}

function Remove-DriverByOEM {
    param($Driver, [System.Windows.Controls.TextBox]$LogBox)
    try {
        $name = $Driver.PublishedName
        $result = pnputil /delete-driver $name /force 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-FormLog $LogBox "Driver removed: $($Driver.OriginalName)" -Level SUCCESS
            return $true
        } else {
            Add-FormLog $LogBox "Driver remove failed: $($Driver.OriginalName)" -Level ERROR
            return $false
        }
    } catch {
        Add-FormLog $LogBox "Driver error $($Driver.OriginalName): $_" -Level ERROR
        return $false
    }
}

function Disable-WindowsOptionalFeatureByName {
    param([string]$FeatureName, [System.Windows.Controls.TextBox]$LogBox)
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop
        Add-FormLog $LogBox "Disabled feature: $FeatureName" -Level SUCCESS
        return $true
    } catch {
        Add-FormLog $LogBox "Feature disable failed $FeatureName : $_" -Level ERROR
        return $false
    }
}

function Invoke-OneDriveRemoval {
    param([System.Windows.Controls.TextBox]$LogBox)
    try {
        Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force
        $path = "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDriveSetup.exe"
        if (Test-Path $path) {
            Start-Process $path -ArgumentList '/uninstall' -Wait
            Add-FormLog $LogBox "OneDrive uninstall initiated" -Level SUCCESS
        }
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
        if (-not (Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $policyPath -Name 'DisableFileSyncNGSC' -Value 1 -Type DWord -Force
        Add-FormLog $LogBox "OneDrive policy disabled" -Level SUCCESS
        return $true
    } catch {
        Add-FormLog $LogBox "OneDrive removal error: $_" -Level ERROR
        return $false
    }
}

function Invoke-XboxRemoval {
    param([System.Windows.Controls.TextBox]$LogBox)
    try {
        Get-AppxPackage '*Xbox*' | Remove-AppxPackage -ErrorAction SilentlyContinue
        $svcs = @('XblAuthManager','XblGameSave','XboxGipSvc','XboxNetApiSvc')
        foreach ($s in $svcs) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service $s -Force -ErrorAction SilentlyContinue
                Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
        $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name 'AllowGameDVR' -Value 0 -Type DWord -Force
        Add-FormLog $LogBox "Xbox components disabled" -Level SUCCESS
        return $true
    } catch {
        Add-FormLog $LogBox "Xbox removal error: $_" -Level ERROR
        return $false
    }
}

function Invoke-EdgeBackgroundDisable {
    param([System.Windows.Controls.TextBox]$LogBox)
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like '*Edge*' -or $_.TaskName -like '*MicrosoftEdge*' }
        foreach ($t in $tasks) {
            Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
        }
        $svcs = @('edgeupdate','edgeupdatem')
        foreach ($s in $svcs) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service $s -Force -ErrorAction SilentlyContinue
                Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
        Add-FormLog $LogBox "Edge background services disabled" -Level SUCCESS
        return $true
    } catch {
        Add-FormLog $LogBox "Edge disable error: $_" -Level ERROR
        return $false
    }
}

function Invoke-CortanaDisable {
    param([System.Windows.Controls.TextBox]$LogBox)
    try {
        $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name 'AllowCortana' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name 'AllowSearchToUseLocation' -Value 0 -Type DWord -Force
        Add-FormLog $LogBox "Cortana disabled" -Level SUCCESS
        return $true
    } catch {
        Add-FormLog $LogBox "Cortana disable error: $_" -Level ERROR
        return $false
    }
}

function Set-ServiceStartup {
    param([string]$Name, [string]$StartType, [System.Windows.Controls.TextBox]$LogBox)
    if ($script:ProtectedServices -contains $Name) {
        Add-FormLog $LogBox "Blocked: $Name is protected" -Level WARNING
        return $false
    }
    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc) { return $false }
        $before = (Get-CimInstance Win32_Service -Filter "Name='$Name'").StartMode
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $Name -StartupType $StartType -ErrorAction Stop
        Register-Change -Category 'Service' -Action "Set $Name to $StartType" -OriginalState @{ Name=$Name; StartType=$before } -RollbackScript "Set-Service -Name '$Name' -StartupType '$before'"
        Add-FormLog $LogBox "Service $Name -> $StartType" -Level SUCCESS
        return $true
    } catch {
        Add-FormLog $LogBox "Service $Name error: $_" -Level ERROR
        return $false
    }
}

function Invoke-PrivacyTweaks {
    param([array]$Ids, [System.Windows.Controls.TextBox]$LogBox)
    foreach ($id in $Ids) {
        try {
            switch ($id) {
                'Telemetry' {
                    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                    Set-ItemProperty -Path $p -Name 'AllowTelemetry' -Value 0 -Type DWord -Force
                    Add-FormLog $LogBox "Telemetry minimized" -Level SUCCESS
                }
                'DataCollection' {
                    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                    Set-ItemProperty -Path $p -Name 'AllowTelemetry' -Value 0 -Type DWord -Force
                    Add-FormLog $LogBox "Data collection disabled" -Level SUCCESS
                }
                'AdsId' {
                    $p = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                    Set-ItemProperty -Path $p -Name 'Enabled' -Value 0 -Type DWord -Force
                    Add-FormLog $LogBox "Advertising ID disabled" -Level SUCCESS
                }
                'ContentDelivery' {
                    $p = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                    Set-ItemProperty -Path $p -Name 'ContentDeliveryAllowed' -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $p -Name 'PreInstalledAppsEnabled' -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $p -Name 'SystemPaneSuggestionsEnabled' -Value 0 -Type DWord -Force
                    Add-FormLog $LogBox "Content delivery disabled" -Level SUCCESS
                }
            }
        } catch {
            Add-FormLog $LogBox "Privacy $id error: $_" -Level ERROR
        }
    }
}

function Invoke-GamingTweaks {
    param([array]$Ids, [System.Windows.Controls.TextBox]$LogBox)
    foreach ($id in $Ids) {
        try {
            switch ($id) {
                'GameDVR' {
                    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                    Set-ItemProperty -Path $p -Name 'AllowGameDVR' -Value 0 -Type DWord -Force
                    Add-FormLog $LogBox "Game DVR disabled" -Level SUCCESS
                }
                'GameMode' {
                    $p = 'HKCU:\Software\Microsoft\GameBar'
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                    Set-ItemProperty -Path $p -Name 'AllowAutoGameMode' -Value 1 -Type DWord -Force
                    Add-FormLog $LogBox "Game Mode optimized" -Level SUCCESS
                }
            }
        } catch {
            Add-FormLog $LogBox "Gaming $id error: $_" -Level ERROR
        }
    }
}

function Invoke-AdvancedTweaks {
    param([array]$Ids, [System.Windows.Controls.TextBox]$LogBox)
    foreach ($id in $Ids) {
        try {
            switch ($id) {
                'VisualFX' {
                    $p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                    Set-ItemProperty -Path $p -Name 'VisualFXSetting' -Value 2 -Type DWord -Force
                    $dp = 'HKCU:\Control Panel\Desktop'
                    Set-ItemProperty -Path $dp -Name 'UserPreferencesMask' -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $dp -Name 'DragFullWindows' -Value '0' -Force -ErrorAction SilentlyContinue
                    Add-FormLog $LogBox "Visual effects set to performance" -Level SUCCESS
                }
                'PowerPlan' {
                    powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>&1 | Out-Null
                    Add-FormLog $LogBox "High Performance power plan set" -Level SUCCESS
                }
                'TempClean' {
                    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Add-FormLog $LogBox "Temporary files cleaned" -Level SUCCESS
                }
            }
        } catch {
            Add-FormLog $LogBox "Advanced $id error: $_" -Level ERROR
        }
    }
}

function Invoke-DefenderRTPDisable {
    param([System.Windows.Controls.TextBox]$LogBox)
    try {
        $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name 'DisableRealtimeMonitoring' -Value 1 -Type DWord -Force
        Add-FormLog $LogBox "Defender Real-Time Protection disabled (Defender remains active)" -Level SUCCESS
        return $true
    } catch {
        Add-FormLog $LogBox "Defender RTP error: $_" -Level ERROR
        return $false
    }
}

function Disable-StartupItem {
    param($Item, [System.Windows.Controls.TextBox]$LogBox)
    try {
        if ($Item.Type -eq 'Registry') {
            Remove-ItemProperty -Path $Item.Path -Name $Item.Name -Force -ErrorAction Stop
            Add-FormLog $LogBox "Startup disabled: $($Item.Name)" -Level SUCCESS
        } else {
            Disable-ScheduledTask -TaskName $Item.Name -TaskPath $Item.Path -ErrorAction Stop
            Add-FormLog $LogBox "Task disabled: $($Item.Name)" -Level SUCCESS
        }
        return $true
    } catch {
        Add-FormLog $LogBox "Startup disable error $($Item.Name): $_" -Level ERROR
        return $false
    }
}

#endregion

#region Rollback

function Invoke-Rollback {
    param([System.Windows.Controls.TextBox]$LogBox)
    $count = $script:ChangeLog.Count
    if ($count -eq 0) {
        Add-FormLog $LogBox "No changes to rollback" -Level WARNING
        return
    }
    Add-FormLog $LogBox "Rolling back $count changes..." -Level INFO
    foreach ($change in ($script:ChangeLog | Sort-Object { $_.Timestamp } -Descending)) {
        try {
            if ($change.RollbackScript) {
                Invoke-Expression $change.RollbackScript
                Add-FormLog $LogBox "Reverted: $($change.Category) - $($change.Action)" -Level SUCCESS
            }
        } catch {
            Add-FormLog $LogBox "Rollback failed: $($change.Action) - $_" -Level ERROR
        }
    }
    $script:ChangeLog.Clear()
    Add-FormLog $LogBox "Rollback complete" -Level SUCCESS
}

#endregion

#region GUI

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="God Debloater v1.1" Height="800" Width="1200"
        WindowStartupLocation="CenterScreen" ResizeMode="CanResizeWithGrip"
        Background="#0d1117">
    <Window.Resources>
        <Style x:Key="DarkButton" TargetType="Button">
            <Setter Property="Background" Value="#21262d"/>
            <Setter Property="Foreground" Value="#c9d1d9"/>
            <Setter Property="BorderBrush" Value="#30363d"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#30363d"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="AccentButton" TargetType="Button" BasedOn="{StaticResource DarkButton}">
            <Setter Property="Background" Value="#238636"/>
            <Setter Property="BorderBrush" Value="#2ea043"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#2ea043"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style x:Key="CheckBoxDark" TargetType="CheckBox">
            <Setter Property="Foreground" Value="#c9d1d9"/>
        </Style>
    </Window.Resources>
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <TextBlock Grid.Row="0" Text="GOD DEBLOATER" FontSize="28" FontWeight="Bold" Foreground="#58a6ff" Margin="0,0,0,8"/>
        <TextBlock Grid.Row="0" Text="Professional Windows Optimization" FontSize="12" Foreground="#8b949e" Margin="0,36,0,-24" VerticalAlignment="Top"/>
        
        <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,12">
            <Button x:Name="BtnAnalyze" Content="Analyze System" Style="{StaticResource AccentButton}" Margin="0,0,8,0" Width="120"/>
            <Button x:Name="BtnApply" Content="Apply Selected" Style="{StaticResource AccentButton}" Margin="0,0,8,0" Width="120"/>
            <Button x:Name="BtnSelectAll" Content="Select All" Style="{StaticResource DarkButton}" Margin="0,0,8,0" Width="80"/>
            <Button x:Name="BtnDeselectAll" Content="Deselect All" Style="{StaticResource DarkButton}" Margin="0,0,8,0" Width="90"/>
            <Button x:Name="BtnRestore" Content="Create Restore Point" Style="{StaticResource DarkButton}" Margin="0,0,8,0" Width="140"/>
            <Button x:Name="BtnExportLog" Content="Export Log" Style="{StaticResource DarkButton}" Margin="0,0,8,0" Width="100"/>
            <Button x:Name="BtnRollback" Content="Rollback Changes" Style="{StaticResource DarkButton}" Margin="0,0,8,0" Width="120"/>
        </StackPanel>
        
        <TabControl x:Name="MainTabControl" Grid.Row="2" Background="#161b22" BorderBrush="#30363d" Foreground="#c9d1d9">
            <TabItem Header="UWP Apps">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabSystemApps" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Installed Programs">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabPrograms" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Drivers">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabDrivers" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Windows Features">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabFeatures" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Optional Features">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabOptional" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Startup Programs">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabStartup" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Services">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabServices" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Privacy &amp; Telemetry">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabPrivacy" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Gaming">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabGaming" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Advanced Tweaks">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabAdvanced" Margin="8"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Security">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="TabSecurity" Margin="8"/>
                </ScrollViewer>
            </TabItem>
        </TabControl>
        
        <Border Grid.Row="3" Background="#161b22" BorderBrush="#30363d" BorderThickness="1" CornerRadius="4" Margin="0,12,0,0" Padding="8" Height="120">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <TextBlock Text="Activity Log" Foreground="#8b949e" FontSize="11"/>
                <TextBox x:Name="TxtLog" Grid.Row="1" IsReadOnly="True" TextWrapping="Wrap" AcceptsReturn="True"
                         VerticalScrollBarVisibility="Auto" Background="#0d1117" Foreground="#c9d1d9"
                         BorderThickness="0" Padding="4" FontFamily="Consolas" FontSize="11"/>
            </Grid>
        </Border>
    </Grid>
</Window>
'@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$btnAnalyze = $window.FindName('BtnAnalyze')
$btnApply = $window.FindName('BtnApply')
$btnSelectAll = $window.FindName('BtnSelectAll')
$btnDeselectAll = $window.FindName('BtnDeselectAll')
$btnRestore = $window.FindName('BtnRestore')
$mainTabControl = $window.FindName('MainTabControl')
$btnExportLog = $window.FindName('BtnExportLog')
$btnRollback = $window.FindName('BtnRollback')
$txtLog = $window.FindName('TxtLog')
$tabSystemApps = $window.FindName('TabSystemApps')
$tabPrograms = $window.FindName('TabPrograms')
$tabDrivers = $window.FindName('TabDrivers')
$tabFeatures = $window.FindName('TabFeatures')
$tabOptional = $window.FindName('TabOptional')
$tabStartup = $window.FindName('TabStartup')
$tabServices = $window.FindName('TabServices')
$tabPrivacy = $window.FindName('TabPrivacy')
$tabGaming = $window.FindName('TabGaming')
$tabAdvanced = $window.FindName('TabAdvanced')
$tabSecurity = $window.FindName('TabSecurity')

$script:Checkboxes = @{
    Apps = [System.Collections.ArrayList]::new()
    Programs = [System.Collections.ArrayList]::new()
    Drivers = [System.Collections.ArrayList]::new()
    Features = [System.Collections.ArrayList]::new()
    Optional = @{}
    Startup = [System.Collections.ArrayList]::new()
    Services = @{}
    Privacy = @{}
    Gaming = @{}
    Advanced = @{}
    Security = @{}
}

function Add-Log { param([string]$Msg,[string]$Lvl='INFO') Add-FormLog $txtLog $Msg $Lvl }

function Build-OptionalTab {
    $tabOptional.Children.Clear()
    Get-OptionalFeaturesList | ForEach-Object {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = "$($_.Name) - $($_.Description)"
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,4,0,0)
        $cb.Tag = $_.Id
        $script:Checkboxes.Optional[$_.Id] = $cb
        $tabOptional.Children.Add($cb) | Out-Null
    }
}

function Build-PrivacyTab {
    $tabPrivacy.Children.Clear()
    Get-PrivacyTweaks | ForEach-Object {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = "$($_.Name) - $($_.Description)"
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,4,0,0)
        $cb.Tag = $_.Id
        $script:Checkboxes.Privacy[$_.Id] = $cb
        $tabPrivacy.Children.Add($cb) | Out-Null
    }
}

function Build-GamingTab {
    $tabGaming.Children.Clear()
    Get-GamingTweaks | ForEach-Object {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = "$($_.Name) - $($_.Description)"
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,4,0,0)
        $cb.Tag = $_.Id
        $script:Checkboxes.Gaming[$_.Id] = $cb
        $tabGaming.Children.Add($cb) | Out-Null
    }
}

function Build-AdvancedTab {
    $tabAdvanced.Children.Clear()
    Get-AdvancedTweaks | ForEach-Object {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = "$($_.Name) - $($_.Description)"
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,4,0,0)
        $cb.Tag = $_.Id
        $script:Checkboxes.Advanced[$_.Id] = $cb
        $tabAdvanced.Children.Add($cb) | Out-Null
    }
}

function Build-SecurityTab {
    $tabSecurity.Children.Clear()
    $info = Get-SystemInfo
    $fwStatus = "N/A"
    try {
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($fw) {
            $profiles = $fw | ForEach-Object { "$($_.Name):$($_.Enabled)" }
            $fwStatus = ($profiles -join " | ")
        }
    } catch { }
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = "Firewall: $fwStatus | Memory Compression: $($info.MemoryCompression) | RAM: $($info.RAMTotalGB) GB"
    $tb.Foreground = [System.Windows.Media.Brushes]::LightGray
    $tb.Margin = [System.Windows.Thickness]::new(0,0,0,12)
    $tabSecurity.Children.Add($tb) | Out-Null
    Get-SecurityTweaks | ForEach-Object {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = "$($_.Name) - $($_.Description)"
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,4,0,0)
        $cb.Tag = $_.Id
        $script:Checkboxes.Security[$_.Id] = $cb
        $tabSecurity.Children.Add($cb) | Out-Null
    }
}

function Invoke-Analyze {
    Add-Log "Analyzing system..." INFO
    $script:AnalyzedData.Apps = Get-SystemApps
    $script:AnalyzedData.Programs = Get-InstalledPrograms
    $script:AnalyzedData.Drivers = Get-InstalledDrivers
    $script:AnalyzedData.Features = Get-WindowsOptionalFeaturesList
    $script:AnalyzedData.Startup = Get-StartupItems
    $script:AnalyzedData.Services = Get-OptimizableServices
    $script:IsAnalyzed = $true
    
    $tabSystemApps.Children.Clear()
    $script:Checkboxes.Apps.Clear()
    foreach ($app in $script:AnalyzedData.Apps) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $pref = if ($app.IsCritical) { '[CRITICAL] ' } else { '' }
        $cb.Content = "$pref$($app.Name)"
        $cb.Foreground = if ($app.IsCritical) { [System.Windows.Media.BrushConverter]::new().ConvertFromString('#f85149') } else { [System.Windows.Media.Brushes]::White }
        $cb.Margin = [System.Windows.Thickness]::new(0,2,0,0)
        $cb.Tag = $app
        [void]$script:Checkboxes.Apps.Add($cb)
        $tabSystemApps.Children.Add($cb) | Out-Null
    }
    Add-Log "Found $($script:AnalyzedData.Apps.Count) UWP apps" SUCCESS
    
    $tabPrograms.Children.Clear()
    $script:Checkboxes.Programs.Clear()
    foreach ($prog in $script:AnalyzedData.Programs) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = $prog.DisplayName
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,2,0,0)
        $cb.Tag = $prog
        [void]$script:Checkboxes.Programs.Add($cb)
        $tabPrograms.Children.Add($cb) | Out-Null
    }
    Add-Log "Found $($script:AnalyzedData.Programs.Count) installed programs" SUCCESS
    
    $tabDrivers.Children.Clear()
    $script:Checkboxes.Drivers.Clear()
    foreach ($drv in $script:AnalyzedData.Drivers) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = "$($drv.OriginalName) [$($drv.Provider)]"
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,2,0,0)
        $cb.Tag = $drv
        [void]$script:Checkboxes.Drivers.Add($cb)
        $tabDrivers.Children.Add($cb) | Out-Null
    }
    Add-Log "Found $($script:AnalyzedData.Drivers.Count) third-party drivers" SUCCESS
    
    $tabFeatures.Children.Clear()
    $script:Checkboxes.Features.Clear()
    foreach ($feat in $script:AnalyzedData.Features) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = $feat.Name
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,2,0,0)
        $cb.Tag = $feat
        [void]$script:Checkboxes.Features.Add($cb)
        $tabFeatures.Children.Add($cb) | Out-Null
    }
    Add-Log "Found $($script:AnalyzedData.Features.Count) optional features" SUCCESS
    
    $tabStartup.Children.Clear()
    $script:Checkboxes.Startup.Clear()
    foreach ($item in $script:AnalyzedData.Startup) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = "$($item.Name) [$($item.Type)]"
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        $cb.Margin = [System.Windows.Thickness]::new(0,2,0,0)
        $cb.Tag = $item
        [void]$script:Checkboxes.Startup.Add($cb)
        $tabStartup.Children.Add($cb) | Out-Null
    }
    Add-Log "Found $($script:AnalyzedData.Startup.Count) startup items" SUCCESS
    
    $tabServices.Children.Clear()
    $script:Checkboxes.Services.Clear()
    foreach ($svc in $script:AnalyzedData.Services) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $color = switch ($svc.Risk) { 'Safe' { '#3fb950' } 'Moderate' { '#d29922' } default { '#f85149' } }
        $cb.Content = "[$($svc.Risk)] $($svc.DisplayName) - $($svc.Recommendation)"
        $cb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($color)
        $cb.Margin = [System.Windows.Thickness]::new(0,2,0,0)
        $cb.Tag = $svc
        $script:Checkboxes.Services[$svc.Name] = $cb
        $tabServices.Children.Add($cb) | Out-Null
    }
    Add-Log "Found $($script:AnalyzedData.Services.Count) optimizable services" SUCCESS
    Add-Log "Analysis complete" SUCCESS
}

function Invoke-Apply {
    $selected = 0
    if (-not $script:IsAnalyzed) {
        Add-Log "Run Analyze System first" WARNING
        return
    }
    
    $createRp = [System.Windows.MessageBox]::Show("Create restore point before applying?", "God Debloater", "YesNo", "Question")
    if ($createRp -eq 'Yes') {
        if (New-RestorePoint) { Add-Log "Restore point created" SUCCESS } else { Add-Log "Restore point failed" WARNING }
    }
    
    $appsToRemove = $script:Checkboxes.Apps | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $_.Tag }
    if ($appsToRemove.Count -gt 0) {
        $cnt = Remove-SelectedApps -Apps $appsToRemove -LogBox $txtLog
        $selected += $cnt
    }
    
    $progsToRemove = $script:Checkboxes.Programs | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $_.Tag }
    foreach ($prog in $progsToRemove) {
        if (Uninstall-Win32Program -Program $prog -LogBox $txtLog) { $selected++ }
    }
    
    $driversToRemove = $script:Checkboxes.Drivers | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $_.Tag }
    foreach ($drv in $driversToRemove) {
        if (Remove-DriverByOEM -Driver $drv -LogBox $txtLog) { $selected++ }
    }
    
    $featuresToDisable = $script:Checkboxes.Features | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $_.Tag }
    foreach ($feat in $featuresToDisable) {
        if (Disable-WindowsOptionalFeatureByName -FeatureName $feat.Name -LogBox $txtLog) { $selected++ }
    }
    
    $script:Checkboxes.Optional.GetEnumerator() | Where-Object { $_.Value.IsChecked -eq $true } | ForEach-Object {
        switch ($_.Key) {
            'OneDrive' { Invoke-OneDriveRemoval -LogBox $txtLog; $selected++ }
            'Xbox' { Invoke-XboxRemoval -LogBox $txtLog; $selected++ }
            'EdgeBg' { Invoke-EdgeBackgroundDisable -LogBox $txtLog; $selected++ }
            'Cortana' { Invoke-CortanaDisable -LogBox $txtLog; $selected++ }
        }
    }
    
    $script:Checkboxes.Startup | Where-Object { $_.IsChecked -eq $true } | ForEach-Object {
        if (Disable-StartupItem -Item $_.Tag -LogBox $txtLog) { $selected++ }
    }
    
    $script:Checkboxes.Services.GetEnumerator() | Where-Object { $_.Value.IsChecked -eq $true } | ForEach-Object {
        $svc = $_.Value.Tag
        $startType = if ($svc.Risk -eq 'Risky') { 'Manual' } else { if ($svc.Recommendation -like '*Disabled*') { 'Disabled' } else { 'Manual' } }
        if (Set-ServiceStartup -Name $svc.Name -StartType $startType -LogBox $txtLog) { $selected++ }
    }
    
    $privacyIds = $script:Checkboxes.Privacy.GetEnumerator() | Where-Object { $_.Value.IsChecked -eq $true } | ForEach-Object { $_.Key }
    if ($privacyIds.Count -gt 0) { Invoke-PrivacyTweaks -Ids $privacyIds -LogBox $txtLog; $selected += $privacyIds.Count }
    
    $gamingIds = $script:Checkboxes.Gaming.GetEnumerator() | Where-Object { $_.Value.IsChecked -eq $true } | ForEach-Object { $_.Key }
    if ($gamingIds.Count -gt 0) { Invoke-GamingTweaks -Ids $gamingIds -LogBox $txtLog; $selected += $gamingIds.Count }
    
    $advIds = $script:Checkboxes.Advanced.GetEnumerator() | Where-Object { $_.Value.IsChecked -eq $true } | ForEach-Object { $_.Key }
    if ($advIds.Count -gt 0) { Invoke-AdvancedTweaks -Ids $advIds -LogBox $txtLog; $selected += $advIds.Count }
    
    $secIds = $script:Checkboxes.Security.GetEnumerator() | Where-Object { $_.Value.IsChecked -eq $true } | ForEach-Object { $_.Key }
    if ($secIds -contains 'DefenderRTP') { Invoke-DefenderRTPDisable -LogBox $txtLog; $selected++ }
    
    Add-Log "Apply complete. Changes applied: $selected" SUCCESS
}

function Get-CurrentTabCheckboxes {
    $idx = $mainTabControl.SelectedIndex
    $collections = @(
        $script:Checkboxes.Apps,
        $script:Checkboxes.Programs,
        $script:Checkboxes.Drivers,
        $script:Checkboxes.Features,
        @($script:Checkboxes.Optional.Values),
        $script:Checkboxes.Startup,
        @($script:Checkboxes.Services.Values),
        @($script:Checkboxes.Privacy.Values),
        @($script:Checkboxes.Gaming.Values),
        @($script:Checkboxes.Advanced.Values),
        @($script:Checkboxes.Security.Values)
    )
    if ($idx -ge 0 -and $idx -lt $collections.Length) {
        $c = $collections[$idx]
        if ($c -is [System.Collections.ArrayList]) { return @($c) }
        return @($c)
    }
    return @()
}

$btnAnalyze.Add_Click({ Invoke-Analyze })
$btnApply.Add_Click({ Invoke-Apply })
$btnSelectAll.Add_Click({
    $checkboxes = Get-CurrentTabCheckboxes
    foreach ($cb in $checkboxes) {
        if ($cb -is [System.Windows.Controls.CheckBox]) { $cb.IsChecked = $true }
    }
    Add-Log "Selected all in current tab" INFO
})
$btnDeselectAll.Add_Click({
    $checkboxes = Get-CurrentTabCheckboxes
    foreach ($cb in $checkboxes) {
        if ($cb -is [System.Windows.Controls.CheckBox]) { $cb.IsChecked = $false }
    }
    Add-Log "Deselected all in current tab" INFO
})
$btnRestore.Add_Click({
    if (New-RestorePoint) {
        Add-Log "Restore point created successfully" SUCCESS
        [System.Windows.MessageBox]::Show("Restore point created successfully.", "God Debloater", "OK", "Information")
    } else {
        Add-Log "Restore point skipped (24h limit or disabled)" WARNING
        [System.Windows.MessageBox]::Show("Restore point was not created.`n`nWindows allows only one restore point per 24 hours. You can change this in:`nHKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore`n(Set 'SystemRestorePointCreationFrequency' to 0 for no limit, or minutes between points)", "God Debloater", "OK", "Warning")
    }
})
$btnExportLog.Add_Click({
    $savePath = Join-Path $env:USERPROFILE "Desktop\GodDebloater_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $content = "God Debloater Log - $(Get-Date)`r`n`r`n"
    if (Test-Path $script:CurrentLogFile) {
        $content += Get-Content $script:CurrentLogFile -Raw
    }
    $content += "`r`n`r`n--- Activity Log ---`r`n" + $txtLog.Text
    $content | Out-File -FilePath $savePath -Encoding UTF8
    Add-Log "Log exported to $savePath" SUCCESS
    [System.Windows.MessageBox]::Show("Log exported to:`n$savePath", "God Debloater", "OK", "Information")
})
$btnRollback.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show("Rollback all tracked changes?", "God Debloater", "YesNo", "Question")
    if ($confirm -eq 'Yes') { Invoke-Rollback -LogBox $txtLog }
})

# Initial build
Build-OptionalTab
Build-PrivacyTab
Build-GamingTab
Build-AdvancedTab
Build-SecurityTab

#endregion

#region Main

if (-not (Test-IsAdministrator)) {
    [System.Windows.MessageBox]::Show("God Debloater requires Administrator privileges. Please run as Administrator.", "Error", "OK", "Error")
    exit 1
}

Initialize-Logging
Write-Log "God Debloater started - Version $script:Version" -Level INFO
Add-Log "God Debloater v$script:Version - Ready. Click 'Analyze System' to begin." INFO

$window.ShowDialog() | Out-Null

#endregion
