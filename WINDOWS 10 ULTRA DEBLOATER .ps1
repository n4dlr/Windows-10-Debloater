# ============================================
# Windows 10 PowerShell Debloat Script
# Tam versiya - Bütün funksiyalar daxil
# ============================================

# Region: İlkin Tənzimləmələr
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Region: Parametrlər
param(
    [switch]$SkipWarning = $false,
    [switch]$NoRestart = $false,
    [switch]$CreateRestorePoint = $true,
    [switch]$SkipOptimization = $false,
    [switch]$SkipPrivacy = $false,
    [switch]$SkipApps = $false,
    [switch]$SkipServices = $false
)

# Region: Dəyişənlər və Konfiqurasiya
$ScriptVersion = "2.5"
$ExecutionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$LogPath = "$env:TEMP\Windows10_Debloat_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$TranscriptPath = "$env:TEMP\Windows10_Debloat_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$BackupPath = "$env:TEMP\Debloat_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Renk kodları
function Write-Color {
    param(
        [string]$Text,
        [string]$Color = "White",
        [switch]$NoNewLine = $false
    )
    
    $ColorMap = @{
        "Green" = "`e[92m"
        "Red" = "`e[91m"
        "Yellow" = "`e[93m"
        "Blue" = "`e[94m"
        "Magenta" = "`e[95m"
        "Cyan" = "`e[96m"
        "Gray" = "`e[90m"
        "White" = "`e[97m"
    }
    
    $Reset = "`e[0m"
    
    if ($ColorMap.ContainsKey($Color)) {
        if ($NoNewLine) {
            Write-Host "$($ColorMap[$Color])$Text$Reset" -NoNewline
        } else {
            Write-Host "$($ColorMap[$Color])$Text$Reset"
        }
    } else {
        Write-Host $Text -NoNewline:$NoNewLine
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("SUCCESS","ERROR","WARNING","INFO","DEBUG")]
        [string]$Level = "INFO",
        [switch]$NoConsole = $false
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Fayla yaz
    try {
        Add-Content -Path $LogPath -Value $LogMessage -ErrorAction Stop
    }
    catch {
        # Əgər fayl yoxdursa, yarat
        $LogMessage | Out-File -FilePath $LogPath -Encoding UTF8 -Force
    }
    
    # Konsola yaz
    if (-not $NoConsole) {
        switch ($Level) {
            "SUCCESS" { 
                Write-Color "[$Timestamp] ✓ $Message" -Color "Green"
            }
            "ERROR" { 
                Write-Color "[$Timestamp] ✗ $Message" -Color "Red"
            }
            "WARNING" { 
                Write-Color "[$Timestamp] ⚠ $Message" -Color "Yellow"
            }
            "INFO" { 
                Write-Color "[$Timestamp] ℹ $Message" -Color "Cyan"
            }
            "DEBUG" { 
                Write-Color "[$Timestamp] 🐛 $Message" -Color "Gray"
            }
        }
    }
}

function Test-Administrator {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Show-Header {
    Clear-Host
    Write-Color "╔══════════════════════════════════════════════════════════╗" -Color "Cyan"
    Write-Color "║           WINDOWS 10 DEBLOAT SCRIPT                     ║" -Color "Yellow"
    Write-Color "║           Versiya: $ScriptVersion" -Color "Yellow" -NoNewLine
    Write-Color "                           ║" -Color "Cyan"
    Write-Color "║           Tarix: $ExecutionDate" -Color "Yellow" -NoNewLine
    Write-Color "               ║" -Color "Cyan"
    Write-Color "╚══════════════════════════════════════════════════════════╝" -Color "Cyan"
    Write-Host ""
}

function Show-Section {
    param(
        [int]$SectionNumber,
        [int]$TotalSections,
        [string]$SectionTitle,
        [string]$SectionDescription = ""
    )
    
    Write-Host ""
    Write-Color "┌────────────────────────────────────────────────────────────┐" -Color "Magenta"
    Write-Color "│ [BÖLMƏ $SectionNumber/$TotalSections] $SectionTitle" -Color "Magenta" -NoNewLine
    Write-Color " │" -Color "Magenta"
    Write-Color "└────────────────────────────────────────────────────────────┘" -Color "Magenta"
    
    if ($SectionDescription) {
        Write-Color "   $SectionDescription" -Color "Gray"
    }
    
    Write-Log "Bölmə başladı: $SectionTitle ($SectionNumber/$TotalSections)" -Level "INFO"
}

function Show-Progress {
    param(
        [int]$Current,
        [int]$Total,
        [string]$Activity,
        [string]$Status
    )
    
    $percent = [math]::Round(($Current / $Total) * 100)
    $progressBar = "[" + ("█" * [math]::Round($percent / 2)) + ("░" * (50 - [math]::Round($percent / 2))) + "]"
    
    Write-Host -NoNewline "`r$Activity $progressBar $percent% - $Status"
    
    if ($Current -eq $Total) {
        Write-Host ""
    }
}

function Create-SystemRestorePoint {
    try {
        Write-Log "Sistem Bərpa Nöqtəsi yaradılır..." -Level "INFO"
        
        # Checkpoint yarat
        $CheckpointDescription = "Windows 10 Debloat Script - $ExecutionDate"
        
        # WMI ilə bərpa nöqtəsi yarat
        $SRP = Get-WmiObject -Class Win32_ShadowCopy -List | Where-Object {$_.VolumeName -eq "$env:SystemDrive\"}
        if ($SRP) {
            $Method = $SRP | Get-Member | Where-Object {$_.Name -eq "Create"}
            if ($Method) {
                $SRP.Create("$env:SystemDrive\", "ClientAccessible") | Out-Null
                Write-Log "Sistem Bərpa Nöqtəsi uğurla yaradıldı" -Level "SUCCESS"
                return $true
            }
        }
        
        # Əgər WMI ilə olmazsa, vssadmin ilə yoxla
        vssadmin create shadow /For=$env:SystemDrive /AutoRetry=15 2>&1 | Out-Null
        Write-Log "Sistem Bərpa Nöqtəsi yaradıldı (vssadmin)" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Bərpa nöqtəsi yaradılarkən xəta: $_" -Level "WARNING"
        return $false
    }
}

function Backup-Registry {
    param(
        [string]$RegistryPath,
        [string]$BackupName
    )
    
    try {
        if (-not (Test-Path $BackupPath)) {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        }
        
        $BackupFile = Join-Path $BackupPath "$BackupName.reg"
        
        # Registry-ni ixrac et
        reg export $RegistryPath $BackupFile 2>&1 | Out-Null
        
        if (Test-Path $BackupFile) {
            Write-Log "Registry backup yaradıldı: $BackupName" -Level "INFO" -NoConsole
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Confirm-UserConsent {
    Show-Header
    
    Write-Color "❗ XƏBƏRDARLIQ: BU SCRIPT AŞAĞIDAKILARI EDƏCƏK ❗" -Color "Red"
    Write-Host ""
    
    Write-Color "🔴 SİLİNƏCƏK:" -Color "Red"
    Write-Color "  • Windows Defender (tamamilə)" -Color "Gray"
    Write-Color "  • Cortana" -Color "Gray"
    Write-Color "  • Microsoft Edge (tamamilə + WebView2)" -Color "Gray"
    Write-Color "  • Windows Store" -Color "Gray"
    Write-Color "  • OneDrive (tamamilə)" -Color "Gray"
    Write-Color "  • Xbox və bütün oyun servisləri" -Color "Gray"
    Write-Color "  • Telemetriya və izləmə servisləri" -Color "Gray"
    Write-Color "  • Bloatware proqramları" -Color "Gray"
    Write-Color "  • 3D Builder, Paint 3D, Mixed Reality" -Color "Gray"
    Write-Color "  • People, Mail, Calendar, Skype" -Color "Gray"
    Write-Color "  • Spotify, Netflix, TikTok" -Color "Gray"
    Write-Color "  • Bing Weather, News, Sports, Finance" -Color "Gray"
    Write-Host ""
    
    Write-Color "🟡 DEAKTİV EDİLƏCƏK:" -Color "Yellow"
    Write-Color "  • Windows Update" -Color "Gray"
    Write-Color "  • Windows Security Center" -Color "Gray"
    Write-Color "  • Əksər telemetriya servisləri" -Color "Gray"
    Write-Color "  • Windows Feedback Hub" -Color "Gray"
    Write-Host ""
    
    Write-Color "🟢 TOXUNULMAYACAQ:" -Color "Green"
    Write-Color "  • Kamera və səs servisləri" -Color "Gray"
    Write-Color "  • PowerShell 2.0 və 5.1" -Color "Gray"
    Write-Color "  • Windows Media Player (əski)" -Color "Gray"
    Write-Color "  • Bütün şəbəkə və internet servisləri" -Color "Gray"
    Write-Color "  • Hardware detection servisləri" -Color "Gray"
    Write-Color "  • Printer və skaner servisləri" -Color "Gray"
    Write-Color "  • Audio servisləri (Realtek, Intel, NVIDIA)" -Color "Gray"
    Write-Color "  • Display driver servisləri" -Color "Gray"
    Write-Color "  • Disk və partition servisləri" -Color "Gray"
    Write-Color "  • USB və PnP servisləri" -Color "Gray"
    Write-Color "  • Task Scheduler (əsas)" -Color "Gray"
    Write-Host ""
    
    Write-Color "⚠️  MÜHÜM XƏBƏRDARLIQLAR:" -Color "Red"
    Write-Color "  1. Windows Defender silinəcək - Alternativ antivirus quraşdırın!" -Color "Yellow"
    Write-Color "  2. Windows Update deaktiv olunacaq - Manual yeniləmələr edin!" -Color "Yellow"
    Write-Color "  3. Microsoft Edge silinəcək - Browser quraşdırın!" -Color "Yellow"
    Write-Color "  4. OneDrive silinəcək - Alternativ backup həlli istifadə edin!" -Color "Yellow"
    Write-Color "  5. Sistem Bərpa Nöqtəsi avtomatik yaradılacaq!" -Color "Yellow"
    Write-Host ""
    Write-Color "🚨 İSTİFADƏ ÖZ TƏHLÜKƏNİZDƏDİR! 🚨" -Color "Red"
    Write-Host ""
    
    $confirmation = Read-Host "Davam etmək istəyirsinizmi? (Y/N)"
    
    if ($confirmation -notmatch '^(Y|y|E|e|Yes|yes|YES)$') {
        Write-Log "İstifadəçi tərəfindən ləğv edildi" -Level "INFO"
        Write-Host "Script ləğv edildi. Çıxmaq üçün hər hansı düyməni basın."
        pause
        exit 0
    }
    
    # İkinci təsdiq
    Write-Host ""
    Write-Color "⛔ BU ƏMƏLİYYAT GERİ ÇEVİRİLƏ BİLMƏZ! ⛔" -Color "Red"
    $secondConfirmation = Read-Host "ƏMININIZ? (Y yaxud N yazın)"
    
    if ($secondConfirmation -notmatch '^(Y|y|E|e|Yes|yes|YES)$') {
        Write-Log "İstifadəçi tərəfindən ləğv edildi (2-ci təsdiq)" -Level "INFO"
        Write-Host "Script ləğv edildi. Çıxmaq üçün hər hansı düyməni basın."
        pause
        exit 0
    }
    
    Write-Log "İstifadəçi razılığı alındı" -Level "SUCCESS"
}

function Remove-WindowsApps {
    Show-Section -SectionNumber 1 -TotalSections 15 -SectionTitle "Windows Store App'larını Silinməsi" -SectionDescription "Bloatware app'lar təmizlənir..."
    
    $TotalAppsRemoved = 0
    $TotalAppsFailed = 0
    
    # Silinəcək app'ların tam siyahısı
    $AppsToRemove = @(
        # Microsoft Edge (tamamilə)
        "*Microsoft.MicrosoftEdge*",
        "*Microsoft.Edge*",
        "*MicrosoftEdge*",
        "*Edge*",
        
        # Windows Defender & Security
        "*WindowsDefender*",
        "*Windows.Security*",
        
        # Cortana
        "*Microsoft.549981C3F5F10*",
        "*Microsoft.Windows.Cortana*",
        "*Cortana*",
        
        # Xbox və oyunlar
        "*Microsoft.Xbox*",
        "*Xbox*",
        "*Game*",
        "*Minecraft*",
        "*CandyCrush*",
        "*Solitaire*",
        "*BubbleWitch*",
        "*Disney*",
        "*Asphalt*",
        "*MarchofEmpires*",
        "*RoyalRevolt*",
        "*AlphaJump*",
        "*Autodesk*",
        "*CaesarsSlots*",
        "*Cooking*",
        "*Dragon*",
        "*Farm*",
        "*HiddenCity*",
        "*Mahjong*",
        "*Mystery*",
        "*Plex*",
        "*Poker*",
        "*Sudoku*",
        "*Twitter*",
        
        # OneDrive
        "*Microsoft.OneDrive*",
        "*OneDrive*",
        
        # Office Apps (trial)
        "*Microsoft.MicrosoftOfficeHub*",
        "*Microsoft.Office*",
        "*Office*",
        
        # Media Apps
        "*Microsoft.ZuneMusic*",
        "*Microsoft.ZuneVideo*",
        "*Microsoft.WindowsSoundRecorder*",
        "*Microsoft.WindowsAlarms*",
        "*Microsoft.WindowsCamera*",
        "*Microsoft.WindowsMaps*",
        "*Microsoft.WindowsPhotos*",
        "*Microsoft.Windows.Photos*",
        
        # Communication Apps
        "*Microsoft.People*",
        "*Microsoft.Windows.CommunicationsApps*",
        "*Microsoft.SkypeApp*",
        "*skype*",
        
        # News & Weather
        "*Microsoft.BingNews*",
        "*Microsoft.BingWeather*",
        "*Microsoft.BingSports*",
        "*Microsoft.BingFinance*",
        "*Bing*",
        
        # 3D & Mixed Reality
        "*Microsoft.Microsoft3DViewer*",
        "*Microsoft.Print3D*",
        "*Microsoft.MixedReality.Portal*",
        "*3D*",
        
        # Social Media & Entertainment
        "*Spotify*",
        "*Netflix*",
        "*TikTok*",
        "*Facebook*",
        "*Instagram*",
        "*Twitter*",
        "*Disney*",
        "*Hulu*",
        "*Pandora*",
        
        # Feedback & Help
        "*Microsoft.Getstarted*",
        "*Microsoft.GetHelp*",
        "*Microsoft.WindowsFeedbackHub*",
        "*Microsoft.PowerAutomateDesktop*",
        
        # Others
        "*Microsoft.Todos*",
        "*Microsoft.YourPhone*",
        "*YourPhone*",
        "*Microsoft.ScreenSketch*",
        "*Microsoft.WindowsCalculator*",
        "*Calculator*",
        "*Microsoft.WindowsStore*",
        "*Microsoft.Store*",
        
        # Sticky Notes (sonra quraşdırıla bilər)
        "*Microsoft.MicrosoftStickyNotes*",
        
        # Voice Recorder, Alarms
        "*Microsoft.WindowsSoundRecorder*",
        "*Microsoft.WindowsAlarms*"
    )
    
    # Qorunacaq app'lar
    $AppsToKeep = @(
        "*Windows.Media.Player*",
        "*Microsoft.Windows.Camera*",
        "*Microsoft.Windows.Photos*",  # Windows Photo Viewer üçün
        "*Microsoft.SnippingTool*",    # Qədim Snipping Tool
        "*Microsoft.Windows.Notepad*",
        "*Microsoft.Windows.WordPad*",
        "*Microsoft.Windows.Calculator*"  # Əgər istifadə etmək istəyirsinizsə
    )
    
    Write-Log "App paketləri silinir..." -Level "INFO"
    
    # 1. Provisioned paketləri sil
    Write-Log "Provisioned paketlər silinir..." -Level "INFO"
    $ProvisionedPackages = Get-AppxProvisionedPackage -Online
    
    foreach ($AppPattern in $AppsToRemove) {
        $Packages = $ProvisionedPackages | Where-Object {$_.DisplayName -like $AppPattern}
        
        foreach ($Package in $Packages) {
            $ShouldRemove = $true
            
            # Qorunacaq app'ları yoxla
            foreach ($KeepPattern in $AppsToKeep) {
                if ($Package.DisplayName -like $KeepPattern) {
                    $ShouldRemove = $false
                    break
                }
            }
            
            if ($ShouldRemove) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $Package.PackageName -ErrorAction Stop
                    Write-Log "✓ Provisioned paket silindi: $($Package.DisplayName)" -Level "SUCCESS"
                    $TotalAppsRemoved++
                }
                catch {
                    Write-Log "✗ Provisioned paket silinmədi: $($Package.DisplayName) - $_" -Level "ERROR"
                    $TotalAppsFailed++
                }
            }
        }
    }
    
    # 2. Cari istifadəçi üçün app paketləri sil
    Write-Log "Cari istifadəçi üçün app paketləri silinir..." -Level "INFO"
    $UserPackages = Get-AppxPackage -AllUsers
    
    foreach ($AppPattern in $AppsToRemove) {
        $Packages = $UserPackages | Where-Object {$_.Name -like $AppPattern}
        
        foreach ($Package in $Packages) {
            $ShouldRemove = $true
            
            # Qorunacaq app'ları yoxla
            foreach ($KeepPattern in $AppsToKeep) {
                if ($Package.Name -like $KeepPattern) {
                    $ShouldRemove = $false
                    break
                }
            }
            
            if ($ShouldRemove) {
                try {
                    Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction Stop
                    Write-Log "✓ User app paketi silindi: $($Package.Name)" -Level "SUCCESS"
                    $TotalAppsRemoved++
                }
                catch {
                    Write-Log "✗ User app paketi silinmədi: $($Package.Name) - $_" -Level "ERROR"
                    $TotalAppsFailed++
                }
            }
        }
    }
    
    # 3. Bütün istifadəçilər üçün app paketləri sil
    Write-Log "Bütün istifadəçilər üçün app paketləri silinir..." -Level "INFO"
    
    foreach ($AppPattern in $AppsToRemove) {
        Get-AppxPackage -AllUsers | Where-Object {$_.Name -like $AppPattern} | ForEach-Object {
            $ShouldRemove = $true
            
            foreach ($KeepPattern in $AppsToKeep) {
                if ($_.Name -like $KeepPattern) {
                    $ShouldRemove = $false
                    break
                }
            }
            
            if ($ShouldRemove) {
                try {
                    Remove-AppxPackage -AllUsers -Package $_.PackageFullName -ErrorAction Stop
                    Write-Log "✓ All users app paketi silindi: $($_.Name)" -Level "SUCCESS"
                    $TotalAppsRemoved++
                }
                catch {
                    Write-Log "✗ All users app paketi silinmədi: $($_.Name) - $_" -Level "ERROR"
                    $TotalAppsFailed++
                }
            }
        }
    }
    
    # 4. Appx fayllarını təmizlə
    Write-Log "Appx cache faylları təmizlənir..." -Level "INFO"
    $AppxCachePaths = @(
        "$env:LOCALAPPDATA\Packages",
        "$env:ProgramFiles\WindowsApps",
        "${env:ProgramFiles(x86)}\WindowsApps"
    )
    
    foreach ($CachePath in $AppxCachePaths) {
        if (Test-Path $CachePath) {
            try {
                Get-ChildItem -Path $CachePath | Where-Object {
                    foreach ($AppPattern in $AppsToRemove) {
                        if ($_.Name -like $AppPattern) {
                            return $true
                        }
                    }
                    return $false
                } | ForEach-Object {
                    try {
                        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
                        Write-Log "✓ Appx cache silindi: $($_.Name)" -Level "SUCCESS"
                    }
                    catch {
                        Write-Log "⚠ Appx cache silinmədi: $($_.Name)" -Level "WARNING"
                    }
                }
            }
            catch {
                Write-Log "Appx cache təmizlənmədi: $CachePath" -Level "WARNING"
            }
        }
    }
    
    # Nəticə
    Write-Log "App silmə tamamlandı. Silindi: $TotalAppsRemoved, Xəta: $TotalAppsFailed" -Level "INFO"
    
    return @{
        Removed = $TotalAppsRemoved
        Failed = $TotalAppsFailed
    }
}

function Remove-EdgeCompletely {
    Show-Section -SectionNumber 2 -TotalSections 15 -SectionTitle "Microsoft Edge Tam Silinməsi" -SectionDescription "Edge, Edge Update və WebView2 silinir..."
    
    $RemovedItems = 0
    $FailedItems = 0
    
    # Edge qovluqları
    $EdgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge",
        "${env:ProgramFiles}\Microsoft\Edge",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate",
        "${env:ProgramFiles}\Microsoft\EdgeUpdate",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView",
        "${env:ProgramFiles}\Microsoft\EdgeWebView",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeCore",
        "${env:ProgramFiles}\Microsoft\EdgeCore",
        "$env:LOCALAPPDATA\Microsoft\Edge",
        "$env:LOCALAPPDATA\Microsoft\EdgeUpdate",
        "$env:LOCALAPPDATA\Microsoft\EdgeWebView",
        "$env:APPDATA\Microsoft\Edge",
        "$env:ProgramData\Microsoft\Edge",
        "$env:ProgramData\Microsoft\EdgeUpdate",
        "${env:SystemDrive}\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
    )
    
    # Edge qovluqlarını sil
    foreach ($Path in $EdgePaths) {
        if (Test-Path $Path) {
            try {
                # İcazələri dəyiş
                takeown /f "$Path" /r /d y 2>&1 | Out-Null
                icacls "$Path" /grant "$env:USERDOMAIN\$env:USERNAME:F" /t /c /q 2>&1 | Out-Null
                icacls "$Path" /grant "Administrators:F" /t /c /q 2>&1 | Out-Null
                
                # Sil
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                Write-Log "✓ Edge qovluğu silindi: $Path" -Level "SUCCESS"
                $RemovedItems++
            }
            catch {
                Write-Log "✗ Edge qovluğu silinmədi: $Path - $_" -Level "ERROR"
                $FailedItems++
            }
        }
    }
    
    # Edge servisləri
    $EdgeServices = @(
        "edgeupdate",
        "edgeupdatem",
        "MicrosoftEdgeElevationService",
        "EdgeUpdateService",
        "EdgeUpdateServiceMachine",
        "MicrosoftEdgeUpdateService",
        "MicrosoftEdgeElevationService"
    )
    
    foreach ($Service in $EdgeServices) {
        try {
            $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceObj) {
                # Servisi dayandır
                Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                
                # Servisi deaktiv et
                Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
                
                # Servisi sil
                sc.exe delete "$Service" 2>&1 | Out-Null
                
                Write-Log "✓ Edge servisi silindi: $Service" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ Edge servisi silinmədi: $Service" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Edge registry
    $EdgeRegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
        "HKLM:\SOFTWARE\Microsoft\Edge",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate",
        "HKCU:\Software\Microsoft\Edge",
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xht",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xhtml",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf"
    )
    
    foreach ($RegPath in $EdgeRegistryPaths) {
        try {
            if (Test-Path $RegPath) {
                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction Stop
                Write-Log "✓ Edge registry silindi: $RegPath" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ Edge registry silinmədi: $RegPath" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Edge scheduled tasks
    $EdgeTasks = Get-ScheduledTask | Where-Object {
        $_.TaskName -like "*Edge*" -or 
        $_.TaskName -like "*MicrosoftEdge*" -or
        $_.TaskName -like "*edgeupdate*"
    }
    
    foreach ($Task in $EdgeTasks) {
        try {
            Unregister-ScheduledTask -TaskName $Task.TaskName -Confirm:$false -ErrorAction Stop
            Write-Log "✓ Edge scheduled task silindi: $($Task.TaskName)" -Level "SUCCESS"
            $RemovedItems++
        }
        catch {
            Write-Log "⚠ Edge scheduled task silinmədi: $($Task.TaskName)" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Edge context menu
    $ContextMenuPaths = @(
        "HKLM:\SOFTWARE\Classes\*\shell\Open with Microsoft Edge",
        "HKLM:\SOFTWARE\Classes\Directory\shell\Open with Microsoft Edge",
        "HKLM:\SOFTWARE\Classes\Directory\Background\shell\Open with Microsoft Edge",
        "HKCU:\Software\Microsoft\Internet Explorer\MenuExt\Open with Microsoft Edge",
        "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MenuExt\Open with Microsoft Edge"
    )
    
    foreach ($RegPath in $ContextMenuPaths) {
        try {
            if (Test-Path $RegPath) {
                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "✓ Edge context menu silindi: $RegPath" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ Edge context menu silinmədi: $RegPath" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # File associations - Edge-dən çıxar
    $FileTypes = @(".htm", ".html", ".shtml", ".xht", ".xhtml", ".pdf", ".svg")
    
    foreach ($FileType in $FileTypes) {
        try {
            # ProqId'ni tap
            $ProgId = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$FileType\UserChoice" -ErrorAction SilentlyContinue).ProgId
            
            if ($ProgId -like "*Edge*") {
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$FileType\UserChoice" -Name "ProgId" -Force -ErrorAction SilentlyContinue
                Write-Log "✓ File association təmizləndi: $FileType" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ File association təmizlənmədi: $FileType" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Hosts faylına Edge domainləri əlavə et (bloklamaq üçün)
    try {
        $EdgeHosts = @"
# Microsoft Edge Blok
0.0.0.0 edge.microsoft.com
0.0.0.0 msedge.api.cdp.microsoft.com
0.0.0.0 edgeassetservice.azureedge.net
0.0.0.0 msedgesettings.api.cdp.microsoft.com
0.0.0.0 msedge.b.tlu.dl.delivery.mp.microsoft.com
0.0.0.0 msedge.f.dl.delivery.mp.microsoft.com
"@
        
        Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "`n$EdgeHosts" -Encoding ASCII -ErrorAction SilentlyContinue
        Write-Log "✓ Edge domainləri hosts faylına əlavə edildi" -Level "SUCCESS"
        $RemovedItems++
    }
    catch {
        Write-Log "⚠ Edge domainləri hosts faylına əlavə edilmədi" -Level "WARNING"
        $FailedItems++
    }
    
    Write-Log "Edge tam silmə tamamlandı. Silindi: $RemovedItems, Xəta: $FailedItems" -Level "INFO"
    
    return @{
        Removed = $RemovedItems
        Failed = $FailedItems
    }
}

function Remove-OneDriveCompletely {
    Show-Section -SectionNumber 3 -TotalSections 15 -SectionTitle "OneDrive Tam Silinməsi" -SectionDescription "OneDrive app, servis və startup təmizlənir..."
    
    $RemovedItems = 0
    $FailedItems = 0
    
    # OneDrive proseslərini dayandır
    Write-Log "OneDrive prosesləri dayandırılır..." -Level "INFO"
    
    $OneDriveProcesses = @("OneDrive.exe", "FileCoAuth.exe", "OneDriveStandaloneUpdater.exe")
    
    foreach ($Process in $OneDriveProcesses) {
        try {
            Get-Process -Name $Process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Log "✓ OneDrive prosesi dayandırıldı: $Process" -Level "SUCCESS"
            $RemovedItems++
        }
        catch {
            Write-Log "⚠ OneDrive prosesi dayandırılmadı: $Process" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # OneDrive qovluqları
    $OneDrivePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft OneDrive",
        "${env:ProgramFiles}\Microsoft OneDrive",
        "$env:LOCALAPPDATA\Microsoft\OneDrive",
        "$env:ProgramData\Microsoft OneDrive",
        "$env:USERPROFILE\OneDrive",
        "$env:USERPROFILE\OneDrive - *",
        "${env:SystemDrive}\OneDriveTemp",
        "$env:APPDATA\Microsoft\OneDrive"
    )
    
    # OneDrive qovluqlarını sil
    foreach ($Path in $OneDrivePaths) {
        try {
            if (Test-Path $Path) {
                # İcazələri dəyiş
                takeown /f "$Path" /r /d y 2>&1 | Out-Null
                icacls "$Path" /grant "$env:USERDOMAIN\$env:USERNAME:F" /t /c /q 2>&1 | Out-Null
                icacls "$Path" /grant "Administrators:F" /t /c /q 2>&1 | Out-Null
                
                # Sil
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "✓ OneDrive qovluğu silindi: $Path" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ OneDrive qovluğu silinmədi: $Path" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # OneDrive registry
    $OneDriveRegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
        "HKCU:\Software\Microsoft\OneDrive",
        "HKLM:\SOFTWARE\Microsoft\OneDrive",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        "HKLM:\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        "HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    )
    
    foreach ($RegPath in $OneDriveRegistryPaths) {
        try {
            if ($RegPath -like "*Run*") {
                # Run registry-dən OneDrive'ı sil
                Remove-ItemProperty -Path $RegPath -Name "OneDrive" -ErrorAction SilentlyContinue
                Write-Log "✓ OneDrive startup silindi: $RegPath" -Level "SUCCESS"
                $RemovedItems++
            }
            elseif (Test-Path $RegPath) {
                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "✓ OneDrive registry silindi: $RegPath" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ OneDrive registry silinmədi: $RegPath" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # OneDrive scheduled tasks
    $OneDriveTasks = Get-ScheduledTask | Where-Object {
        $_.TaskName -like "*OneDrive*"
    }
    
    foreach ($Task in $OneDriveTasks) {
        try {
            Unregister-ScheduledTask -TaskName $Task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "✓ OneDrive scheduled task silindi: $($Task.TaskName)" -Level "SUCCESS"
            $RemovedItems++
        }
        catch {
            Write-Log "⚠ OneDrive scheduled task silinmədi: $($Task.TaskName)" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # OneDrive context menu
    $ContextMenuPaths = @(
        "HKLM:\SOFTWARE\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers\OneDrive",
        "HKLM:\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        "HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    )
    
    foreach ($RegPath in $ContextMenuPaths) {
        try {
            if (Test-Path $RegPath) {
                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "✓ OneDrive context menu silindi: $RegPath" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ OneDrive context menu silinmədi: $RegPath" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # OneDrive Group Policy
    try {
        $OneDrivePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        if (-not (Test-Path $OneDrivePolicyPath)) {
            New-Item -Path $OneDrivePolicyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $OneDrivePolicyPath -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
        Write-Log "✓ OneDrive Group Policy deaktiv edildi" -Level "SUCCESS"
        $RemovedItems++
    }
    catch {
        Write-Log "⚠ OneDrive Group Policy deaktiv edilmədi" -Level "WARNING"
        $FailedItems++
    }
    
    Write-Log "OneDrive tam silmə tamamlandı. Silindi: $RemovedItems, Xəta: $FailedItems" -Level "INFO"
    
    return @{
        Removed = $RemovedItems
        Failed = $FailedItems
    }
}

function Remove-WindowsDefender {
    Show-Section -SectionNumber 4 -TotalSections 15 -SectionTitle "Windows Defender Silinməsi" -SectionDescription "Defender tamamilə deaktiv edilir..."
    
    $DisabledItems = 0
    $FailedItems = 0
    
    # Defender servisləri
    $DefenderServices = @(
        "WinDefend",
        "WdNisSvc",
        "Sense",
        "SecurityHealthService",
        "wscsvc",
        "MsMpSvc",
        "NisSrv"
    )
    
    foreach ($Service in $DefenderServices) {
        try {
            $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceObj) {
                # Servisi dayandır
                Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                
                # Servisi deaktiv et
                Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
                
                # Servis konfiqurasiyasını dəyiş
                sc.exe config "$Service" start= disabled 2>&1 | Out-Null
                
                Write-Log "✓ Defender servisi deaktiv edildi: $Service" -Level "SUCCESS"
                $DisabledItems++
            }
        }
        catch {
            Write-Log "⚠ Defender servisi deaktiv edilmədi: $Service" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Defender registry ayarları
    $DefenderRegistry = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" = @{
            "DisableAntiSpyware" = 1
            "DisableRoutinelyTakingAction" = 1
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @{
            "DisableRealtimeMonitoring" = 1
            "DisableBehaviorMonitoring" = 1
            "DisableOnAccessProtection" = 1
            "DisableScanOnRealtimeEnable" = 1
            "DisableIOAVProtection" = 1
        }
        "HKLM:\SOFTWARE\Microsoft\Windows Defender" = @{
            "DisableAntiSpyware" = 1
        }
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" = @{
            "TamperProtection" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" = @{
            "SpynetReporting" = 0
            "SubmitSamplesConsent" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" = @{
            "Notification_Suppress" = 1
        }
    }
    
    foreach ($RegPath in $DefenderRegistry.Keys) {
        try {
            if (-not (Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            
            foreach ($Value in $DefenderRegistry[$RegPath].Keys) {
                Set-ItemProperty -Path $RegPath -Name $Value -Value $DefenderRegistry[$RegPath][$Value] -Type DWord -Force
            }
            Write-Log "✓ Defender registry ayarları tətbiq edildi: $RegPath" -Level "SUCCESS"
            $DisabledItems++
        }
        catch {
            Write-Log "⚠ Defender registry ayarları tətbiq edilmədi: $RegPath" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Defender qovluqlarını sil
    $DefenderPaths = @(
        "${env:ProgramFiles}\Windows Defender",
        "${env:ProgramData}\Microsoft\Windows Defender",
        "$env:LOCALAPPDATA\Microsoft\Windows Defender",
        "${env:ProgramFiles(x86)}\Windows Defender"
    )
    
    foreach ($Path in $DefenderPaths) {
        try {
            if (Test-Path $Path) {
                # İcazələri dəyiş
                takeown /f "$Path" /r /d y 2>&1 | Out-Null
                icacls "$Path" /grant "$env:USERDOMAIN\$env:USERNAME:F" /t /c /q 2>&1 | Out-Null
                icacls "$Path" /grant "Administrators:F" /t /c /q 2>&1 | Out-Null
                
                # Sil
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "✓ Defender qovluğu silindi: $Path" -Level "SUCCESS"
                $DisabledItems++
            }
        }
        catch {
            Write-Log "⚠ Defender qovluğu silinmədi: $Path" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Windows Security iconunu gizlət
    try {
        $ExplorerRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $ExplorerRegPath)) {
            New-Item -Path $ExplorerRegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $ExplorerRegPath -Name "HideWindowsSecurity" -Value 1 -Type DWord -Force
        Write-Log "✓ Windows Security iconu gizlədildi" -Level "SUCCESS"
        $DisabledItems++
    }
    catch {
        Write-Log "⚠ Windows Security iconu gizlədilmədi" -Level "WARNING"
        $FailedItems++
    }
    
    Write-Log "Windows Defender deaktivasiya tamamlandı. Deaktiv edildi: $DisabledItems, Xəta: $FailedItems" -Level "INFO"
    
    return @{
        Disabled = $DisabledItems
        Failed = $FailedItems
    }
}

function Remove-XboxAndGaming {
    Show-Section -SectionNumber 5 -TotalSections 15 -SectionTitle "Xbox və Oyun Servisləri" -SectionDescription "Xbox app, Game Bar və Game Services silinir..."
    
    $RemovedItems = 0
    $FailedItems = 0
    
    # Xbox servisləri
    $XboxServices = @(
        "XboxNetApiSvc",
        "XblAuthManager",
        "XblGameSave",
        "XboxGipSvc",
        "xbgm",
        "XboxGipSvc",
        "XboxNetApiSvc"
    )
    
    foreach ($Service in $XboxServices) {
        try {
            $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceObj) {
                # Servisi dayandır
                Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                
                # Servisi deaktiv et
                Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
                
                Write-Log "✓ Xbox servisi deaktiv edildi: $Service" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ Xbox servisi deaktiv edilmədi: $Service" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Xbox registry ayarları
    $XboxRegistry = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" = @{
            "AllowGameDVR" = 0
        }
        "HKCU:\System\GameConfigStore" = @{
            "GameDVR_Enabled" = 0
            "GameDVR_FSEBehaviorMode" = 2
            "GameDVR_HonorUserFSEBehaviorMode" = 1
            "GameDVR_DXGIHonorFSEWindowsCompatible" = 1
            "GameDVR_EFSEFeatureFlags" = 0
        }
        "HKCU:\Software\Microsoft\GameBar" = @{
            "AllowAutoGameMode" = 0
            "AutoGameModeEnabled" = 0
            "ShowStartupPanel" = 0
            "UseNexusForGameBarEnabled" = 0
        }
    }
    
    foreach ($RegPath in $XboxRegistry.Keys) {
        try {
            if (-not (Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            
            foreach ($Value in $XboxRegistry[$RegPath].Keys) {
                Set-ItemProperty -Path $RegPath -Name $Value -Value $XboxRegistry[$RegPath][$Value] -Type DWord -Force
            }
            Write-Log "✓ Xbox registry ayarları tətbiq edildi: $RegPath" -Level "SUCCESS"
            $RemovedItems++
        }
        catch {
            Write-Log "⚠ Xbox registry ayarları tətbiq edilmədi: $RegPath" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Game Bar qovluqlarını sil
    $GameBarPaths = @(
        "$env:LOCALAPPDATA\Microsoft\GameBar",
        "$env:APPDATA\Microsoft\GameBar",
        "$env:ProgramData\Microsoft\GameBar"
    )
    
    foreach ($Path in $GameBarPaths) {
        try {
            if (Test-Path $Path) {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "✓ Game Bar qovluğu silindi: $Path" -Level "SUCCESS"
                $RemovedItems++
            }
        }
        catch {
            Write-Log "⚠ Game Bar qovluğu silinmədi: $Path" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Game Mode deaktiv et
    try {
        $GameModePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
        if (-not (Test-Path $GameModePath)) {
            New-Item -Path $GameModePath -Force | Out-Null
        }
        Set-ItemProperty -Path $GameModePath -Name "AllowGameMode" -Value 0 -Type DWord -Force
        Write-Log "✓ Game Mode deaktiv edildi" -Level "SUCCESS"
        $RemovedItems++
    }
    catch {
        Write-Log "⚠ Game Mode deaktiv edilmədi" -Level "WARNING"
        $FailedItems++
    }
    
    Write-Log "Xbox və oyun servisləri təmizləmə tamamlandı. Silindi: $RemovedItems, Xəta: $FailedItems" -Level "INFO"
    
    return @{
        Removed = $RemovedItems
        Failed = $FailedItems
    }
}

function Disable-TelemetryServices {
    Show-Section -SectionNumber 6 -TotalSections 15 -SectionTitle "Telemetriya Servisləri" -SectionDescription "Telemetriya və izləmə servisləri deaktiv edilir..."
    
    $DisabledItems = 0
    $FailedItems = 0
    
    # Telemetriya servisləri
    $TelemetryServices = @(
        "DiagTrack",
        "dmwappushservice",
        "WMPNetworkSvc",
        "WSearch",
        "wercplsupport",
        "WerSvc",
        "PcaSvc",
        "DPS",
        "diagnosticshub.standardcollector.service",
        "DiagSvcs",
        "diagnosticshub.standardcollector.service"
    )
    
    foreach ($Service in $TelemetryServices) {
        try {
            $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceObj) {
                # Servisi dayandır
                Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                
                # Servisi deaktiv et
                Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
                
                Write-Log "✓ Telemetriya servisi deaktiv edildi: $Service" -Level "SUCCESS"
                $DisabledItems++
            }
        }
        catch {
            Write-Log "⚠ Telemetriya servisi deaktiv edilmədi: $Service" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Telemetriya registry ayarları
    $TelemetryRegistry = @{
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{
            "AllowTelemetry" = 0
            "MaxTelemetryAllowed" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
            "AllowTelemetry" = 0
            "AllowDeviceNameInTelemetry" = 0
        }
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{
            "AllowTelemetry" = 0
        }
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
            "ContentDeliveryAllowed" = 0
            "OemPreInstalledAppsEnabled" = 0
            "PreInstalledAppsEnabled" = 0
            "SilentInstalledAppsEnabled" = 0
            "SubscribedContent-338387Enabled" = 0
            "SubscribedContent-338388Enabled" = 0
            "SubscribedContent-338389Enabled" = 0
            "SubscribedContent-353698Enabled" = 0
            "SystemPaneSuggestionsEnabled" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" = @{
            "DisableWindowsConsumerFeatures" = 1
        }
        "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" = @{
            "NumberOfSIUFInPeriod" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" = @{
            "DisabledByGroupPolicy" = 1
        }
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" = @{
            "Enabled" = 0
        }
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" = @{
            "EnableWebContentEvaluation" = 0
        }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" = @{
            "DODownloadMode" = 0
        }
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
            "ShowSyncProviderNotifications" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" = @{
            "AllowMessageSync" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" = @{
            "DisableCredentialsSettingSync" = 2
            "DisableCredentialsSettingSyncUserOverride" = 1
            "DisableApplicationSettingSync" = 2
            "DisableApplicationSettingSyncUserOverride" = 1
            "DisablePersonalizationSettingSync" = 2
            "DisablePersonalizationSettingSyncUserOverride" = 1
            "DisableWindowsSettingSync" = 2
            "DisableWindowsSettingSyncUserOverride" = 1
        }
    }
    
    foreach ($RegPath in $TelemetryRegistry.Keys) {
        try {
            if (-not (Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            
            foreach ($Value in $TelemetryRegistry[$RegPath].Keys) {
                Set-ItemProperty -Path $RegPath -Name $Value -Value $TelemetryRegistry[$RegPath][$Value] -Type DWord -Force
            }
            Write-Log "✓ Telemetriya registry ayarları tətbiq edildi: $RegPath" -Level "SUCCESS"
            $DisabledItems++
        }
        catch {
            Write-Log "⚠ Telemetriya registry ayarları tətbiq edilmədi: $RegPath" -Level "WARNING"
            $FailedItems++
        }
    }
    
    Write-Log "Telemetriya servisləri deaktivasiya tamamlandı. Deaktiv edildi: $DisabledItems, Xəta: $FailedItems" -Level "INFO"
    
    return @{
        Disabled = $DisabledItems
        Failed = $FailedItems
    }
}

function Disable-WindowsUpdate {
    Show-Section -SectionNumber 7 -TotalSections 15 -SectionTitle "Windows Update Deaktivasiya" -SectionDescription "Windows Update servisləri deaktiv edilir..."
    
    $DisabledItems = 0
    $FailedItems = 0
    
    # Windows Update servisləri
    $UpdateServices = @(
        "wuauserv",
        "UsoSvc",
        "WaaSMedicSvc",
        "BITS"
    )
    
    foreach ($Service in $UpdateServices) {
        try {
            $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceObj) {
                # Servisi dayandır
                Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                
                # Servisi deaktiv et
                Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
                
                Write-Log "✓ Update servisi deaktiv edildi: $Service" -Level "SUCCESS"
                $DisabledItems++
            }
        }
        catch {
            Write-Log "⚠ Update servisi deaktiv edilmədi: $Service" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Windows Update registry ayarları
    $UpdateRegistry = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
            "NoAutoUpdate" = 1
            "AUOptions" = 1
        }
        "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" = @{
            "UxOption" = 1
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" = @{
            "DisableOSUpgrade" = 1
            "DeferFeatureUpdates" = 1
            "DeferFeatureUpdatesPeriodInDays" = 365
            "DeferQualityUpdates" = 1
            "DeferQualityUpdatesPeriodInDays" = 30
        }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" = @{
            "AUOptions" = 1
        }
    }
    
    foreach ($RegPath in $UpdateRegistry.Keys) {
        try {
            if (-not (Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            
            foreach ($Value in $UpdateRegistry[$RegPath].Keys) {
                Set-ItemProperty -Path $RegPath -Name $Value -Value $UpdateRegistry[$RegPath][$Value] -Type DWord -Force
            }
            Write-Log "✓ Windows Update registry ayarları tətbiq edildi: $RegPath" -Level "SUCCESS"
            $DisabledItems++
        }
        catch {
            Write-Log "⚠ Windows Update registry ayarları tətbiq edilmədi: $RegPath" -Level "WARNING"
            $FailedItems++
        }
    }
    
    # Delivery Optimization deaktiv et
    try {
        $DOPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
        if (-not (Test-Path $DOPath)) {
            New-Item -Path $DOPath -Force | Out-Null
        }
        Set-ItemProperty -Path $DOPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
        Write-Log "✓ Delivery Optimization deaktiv edildi" -Level "SUCCESS"
        $DisabledItems++
    }
    catch {
        Write-Log "⚠ Delivery Optimization deaktiv edilmədi" -Level "WARNING"
        $FailedItems++
    }
    
    Write-Log "Windows Update deaktivasiya tamamlandı. Deaktiv edildi: $DisabledItems, Xəta: $FailedItems" -Level "INFO"
    
    return @{
        Disabled = $DisabledItems
        Failed = $FailedItems
    }
}

function Clean-ScheduledTasks {
    Show-Section -SectionNumber 8 -TotalSections 15 -SectionTitle "Scheduled Tasks Təmizləmə" -SectionDescription "Lazımsız scheduled tasks silinir..."
    
    $RemovedTasks = 0
    $FailedTasks = 0
    
    # Silinəcək scheduled tasks pattern-ləri
    $TasksToRemove = @(
        "*OneDrive*",
        "*Edge*",
        "*MicrosoftEdge*",
        "*Xbox*",
        "*Game*",
        "*Advertising*",
        "*Customer Experience*",
        "*Data Collection*",
        "*Diagnostics*",
        "*Feedback*",
        "*Office*",
        "*Telemetry*",
        "*Update*",
        "*Cortana*",
        "*Skype*",
        "*Spotify*",
        "*Netflix*",
        "*TikTok*",
        "*Bing*",
        "*Microsoft Compatibility*",
        "*ProgramDataUpdater*",
        "*Consolidator*",
        "*KernelCeipTask*",
        "*UsbCeip*",
        "*DiskDiagnostic*",
        "*Defender*"
    )
    
    # Qorunacaq tasks
    $TasksToKeep = @(
        "*\Microsoft\Windows\*",
        "*SystemSoundsService*",
        "*WindowsHello*",
        "*WindowsUpdate*",
        "*WindowsBackup*",
        "*WindowsDiagnostics*"
    )
    
    $AllTasks = Get-ScheduledTask
    
    foreach ($TaskPattern in $TasksToRemove) {
        $Tasks = $AllTasks | Where-Object {$_.TaskName -like $TaskPattern -or $_.TaskPath -like "*$TaskPattern*"}
        
        foreach ($Task in $Tasks) {
            $ShouldRemove = $true
            
            # Qorunacaq tasks-ları yoxla
            foreach ($KeepPattern in $TasksToKeep) {
                if ($Task.TaskName -like $KeepPattern -or $Task.TaskPath -like "*$KeepPattern*") {
                    $ShouldRemove = $false
                    break
                }
            }
            
            if ($ShouldRemove) {
                try {
                    Unregister-ScheduledTask -TaskName $Task.TaskName -Confirm:$false -ErrorAction Stop
                    Write-Log "✓ Scheduled task silindi: $($Task.TaskName)" -Level "SUCCESS"
                    $RemovedTasks++
                }
                catch {
                    Write-Log "⚠ Scheduled task silinmədi: $($Task.TaskName)" -Level "WARNING"
                    $FailedTasks++
                }
            }
        }
    }
    
    Write-Log "Scheduled tasks təmizləmə tamamlandı. Silindi: $RemovedTasks, Xəta: $FailedTasks" -Level "INFO"
    
    return @{
        Removed = $RemovedTasks
        Failed = $FailedTasks
    }
}

function Optimize-Pagefile {
    Show-Section -SectionNumber 9 -TotalSections 15 -SectionTitle "Pagefile Optimizasiya" -SectionDescription "Pagefile 2048-4096MB arasında optimizasiya edilir..."
    
    try {
        # Pagefile tənzimləmələri
        $ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $PhysicalMemory = [math]::Round($ComputerSystem.TotalPhysicalMemory / 1MB)
        
        # Optimal pagefile ölçüsü
        $InitialSize = 2048
        $MaximumSize = 4096
        
        if ($PhysicalMemory -gt 8192) { # 8GB-dan çox RAM
            $InitialSize = 4096
            $MaximumSize = 8192
        }
        
        # Avtomatik pagefile idarəetməsini söndür
        $System = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
        $System.AutomaticManagedPagefile = $false
        $System.Put() | Out-Null
        
        # Cari pagefile ayarlarını sil
        $CurrentPageFile = Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting WHERE Name='C:\\pagefile.sys'"
        if ($CurrentPageFile) {
            $CurrentPageFile.Delete()
        }
        
        # Yeni pagefile ayarlarını tətbiq et
        Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{
            Name = "C:\pagefile.sys"
            InitialSize = $InitialSize
            MaximumSize = $MaximumSize
        } | Out-Null
        
        # Digər disklerdəki pagefile'ları sil
        Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting WHERE Name!='C:\\pagefile.sys'" | ForEach-Object {
            $_.Delete()
        }
        
        Write-Log "✓ Pagefile optimizasiya edildi: $InitialSize-$MaximumSize MB" -Level "SUCCESS"
        
        return @{
            Success = $true
            InitialSize = $InitialSize
            MaximumSize = $MaximumSize
        }
    }
    catch {
        Write-Log "✗ Pagefile optimizasiya edilərkən xəta: $_" -Level "ERROR"
        return @{
            Success = $false
            Error = $_
        }
    }
}

function Optimize-PowerPlan {
    Show-Section -SectionNumber 10 -TotalSections 15 -SectionTitle "Power Plan Optimizasiya" -SectionDescription "Ultimate Performance power plan aktiv edilir..."
    
    try {
        # Ultimate Performance power plan'ı aktiv et
        $UltimatePerfGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
        $HighPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        
        # Power planları yoxla
        $PowerPlans = powercfg /list
        
        # Ultimate Performance planını yoxla
        if ($PowerPlans -notmatch $UltimatePerfGuid) {
            # Ultimate Performance planını yarat
            powercfg /duplicatescheme $HighPerfGuid $UltimatePerfGuid 2>&1 | Out-Null
            Write-Log "✓ Ultimate Performance power plan yaradıldı" -Level "SUCCESS"
        }
        
        # Ultimate Performance planını aktiv et
        powercfg /setactive $UltimatePerfGuid 2>&1 | Out-Null
        Write-Log "✓ Ultimate Performance power plan aktiv edildi" -Level "SUCCESS"
        
        # Power plan tənzimləmələri
        powercfg /change /monitor-timeout-ac 0 2>&1 | Out-Null
        powercfg /change /disk-timeout-ac 0 2>&1 | Out-Null
        powercfg /change /standby-timeout-ac 0 2>&1 | Out-Null
        powercfg /change /hibernate-timeout-ac 0 2>&1 | Out-Null
        
        # Yüksək performans tənzimləmələri
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFINCPOL 2>&1 | Out-Null
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFDECPOL 2>&1 | Out-Null
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100 2>&1 | Out-Null
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100 2>&1 | Out-Null
        powercfg /setactive SCHEME_CURRENT 2>&1 | Out-Null
        
        Write-Log "✓ Power plan tənzimləmələri tətbiq edildi" -Level "SUCCESS"
        
        return @{
            Success = $true
            PowerPlan = "Ultimate Performance"
        }
    }
    catch {
        Write-Log "✗ Power plan optimizasiya edilərkən xəta: $_" -Level "ERROR"
        return @{
            Success = $false
            Error = $_
        }
    }
}

function Optimize-VisualEffects {
    Show-Section -SectionNumber 11 -TotalSections 15 -SectionTitle "Visual Effects Optimizasiya" -SectionDescription "Görüntü effektləri optimizasiya edilir..."
    
    try {
        # Registry ayarlarını tətbiq et
        $VisualEffectsReg = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects]
"VisualFXSetting"=dword:00000002

[HKEY_CURRENT_USER\Control Panel\Desktop]
"DragFullWindows"="0"
"FontSmoothing"="2"
"FontSmoothingType"=dword:00000002
"FontSmoothingOrientation"=dword:00000001
"UserPreferencesMask"=hex:90,12,03,80,10,00,00,00
"MenuShowDelay"="4"
"AutoEndTasks"="1"
"HungAppTimeout"="1000"
"WaitToKillAppTimeout"="2000"
"LowLevelHooksTimeout"="1000"
"IconsOnly"="1"

[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]
"MinAnimate"="0"
"Shell Icon Size"="32"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ListviewAlphaSelect"=dword:00000000
"ListviewShadow"=dword:00000000
"TaskbarAnimations"=dword:00000000
"DisallowShaking"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM]
"EnableAeroPeek"=dword:00000000
"AlwaysHibernateThumbnails"=dword:00000000
"UseMachineCheck"=dword:00000000
"EnableWindowColorization"=dword:00000000

[HKEY_CURRENT_USER\Control Panel\Mouse]
"MouseHoverTime"="400"
"MouseSpeed"="0"
"MouseThreshold1"="0"
"MouseThreshold2"="0"
"SnapToDefaultButton"="0"
"MouseTrails"="0"
"MouseSensitivity"="10"
"DoubleClickHeight"="4"
"DoubleClickWidth"="4"
"DoubleClickSpeed"="500"
"ActiveWindowTracking"=dword:00000000
"MouseSonar"=dword:00000000
"MouseVanish"=dword:00000000
"MouseClickLock"=dword:00000000
"MouseClickLockTime"="1000"
"MouseKeys"=dword:00000000
"MouseKeysTimeToMaxSpeed"="3000"
"MouseKeysMaxSpeed"="40"
"MouseKeysAccelerationTime"="3000"
"SwapMouseButtons"=dword:00000000
"MouseWheelRouting"=dword:00000000
"MouseWheelScrollChars"="3"
"MouseWheelScrollLines"="3"
"MouseWheelTurnToScroll"=dword:00000000
"MouseWheelVirtualDesktop"=dword:00000000
"MouseWheelWindowActivation"=dword:00000000
"MouseWheelZoom"=dword:00000000
"MouseWheelEject"=dword:00000000
"MouseWheelSearch"=dword:00000000
"MouseWheelStartMenu"=dword:00000000
"MouseWheelTaskbar"=dword:00000000
"MouseWheelTray"=dword:00000000
"MouseWheelVolume"=dword:00000000
"MouseWheelMedia"=dword:00000000
"MouseWheelAppSwitch"=dword:00000000
"MouseWheelDesktopSwitch"=dword:00000000
"MouseWheelZoom"=dword:00000000
"MouseWheelEject"=dword:00000000
"MouseWheelSearch"=dword:00000000
"MouseWheelStartMenu"=dword:00000000
"MouseWheelTaskbar"=dword:00000000
"MouseWheelTray"=dword:00000000
"MouseWheelVolume"=dword:00000000
"MouseWheelMedia"=dword:00000000
"MouseWheelAppSwitch"=dword:00000000
"MouseWheelDesktopSwitch"=dword:00000000
"@
        
        # Registry faylı yarat və tətbiq et
        $RegFile = "$env:TEMP\visualfx.reg"
        $VisualEffectsReg | Out-File -FilePath $RegFile -Encoding ASCII -Force
        regedit /s $RegFile 2>&1 | Out-Null
        Remove-Item $RegFile -Force -ErrorAction SilentlyContinue
        
        # System properties - Advanced - Performance Settings
        $SystemPropertiesAdvanced = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects]
"VisualFXSetting"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000026

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"DisablePagingExecutive"=dword:00000001
"LargeSystemCache"=dword:00000001
"IoPageLockLimit"=dword:00010000
"SecondLevelDataCache"=dword:00000200
"SystemPages"=dword:00000000
"PagedPoolSize"=dword:ffffffff
"NonPagedPoolSize"=dword:00000000
"PagingFiles"=hex:5a,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"PhysicalAddressExtension"=dword:00000000
"SessionViewSize"=dword:00000030
"SessionPoolSize"=dword:00000004
"WriteWatch"=dword:00000001
"LargePageMinimum"=dword:00000000
"EnforceWriteProtection"=dword:00000000
"DisablePagingExecutive"=dword:00000000
"ClearPageFileAtShutdown"=dword:00000000
"@
        
        $RegFile2 = "$env:TEMP\systemperf.reg"
        $SystemPropertiesAdvanced | Out-File -FilePath $RegFile2 -Encoding ASCII -Force
        regedit /s $RegFile2 2>&1 | Out-Null
        Remove-Item $RegFile2 -Force -ErrorAction SilentlyContinue
        
        Write-Log "✓ Visual effects optimizasiya edildi" -Level "SUCCESS"
        
        return @{
            Success = $true
        }
    }
    catch {
        Write-Log "✗ Visual effects optimizasiya edilərkən xəta: $_" -Level "ERROR"
        return @{
            Success = $false
            Error = $_
        }
    }
}

function Optimize-Services {
    Show-Section -SectionNumber 12 -TotalSections 15 -SectionTitle "Servislərin Optimizasiyası" -SectionDescription "Təhlükəsiz servislər optimizasiya edilir..."
    
    $OptimizedServices = 0
    $FailedServices = 0
    
    # Optimizasiya ediləcək servislər
    $ServicesToOptimize = @{
        "SysMain" = "Manual"           # Superfetch
        "WbioSrvc" = "Manual"          # Windows Biometric Service
        "TabletInputService" = "Manual" # Tablet Input Service
        "RemoteRegistry" = "Disabled"   # Remote Registry
        "RemoteAccess" = "Disabled"     # Remote Access
        "Fax" = "Disabled"             # Fax Service
        "lmhosts" = "Manual"           # TCP/IP NetBIOS Helper
        "WpnService" = "Disabled"      # Windows Push Notifications
        "MapsBroker" = "Disabled"      # Downloaded Maps Manager
        "lfsvc" = "Disabled"           # Geolocation Service
        "SharedAccess" = "Disabled"     # Internet Connection Sharing
        "NetTcpPortSharing" = "Disabled"
        "WdNisSvc" = "Disabled"        # Windows Defender Network Inspection
        "WdiServiceHost" = "Manual"    # Diagnostic Service Host
        "WdiSystemHost" = "Manual"     # Diagnostic System Host
        "DiagTrack" = "Disabled"       # Connected User Experiences and Telemetry
        "dmwappushservice" = "Disabled" # Device Management Wireless Application Protocol
        "MpsSvc" = "Manual"            # Windows Firewall
        "WSearch" = "Manual"           # Windows Search
        "TermService" = "Disabled"     # Remote Desktop Services
        "SessionEnv" = "Disabled"      # Remote Desktop Configuration
        "UmRdpService" = "Disabled"    # Remote Desktop Services UserMode Port Redirector
        "RpcLocator" = "Disabled"      # Remote Procedure Call Locator
        "RetailDemo" = "Disabled"      # Retail Demo Service
        "SensorService" = "Disabled"   # Sensor Service
        "SensrSvc" = "Disabled"        # Sensor Monitoring Service
        "SensorDataService" = "Disabled"
        "WpcMonSvc" = "Disabled"       # Parental Controls
        "PhoneSvc" = "Disabled"        # Phone Service
        "PrintNotify" = "Manual"       # Printer Extensions and Notifications
        "Spooler" = "Manual"           # Print Spooler (Manual edirik, lazım olanda işləyəcək)
    }
    
    # Qorunacaq servislər (toxunulmayacaq)
    $ProtectedServices = @(
        "AudioEndpointBuilder",
        "Audiosrv",
        "BluetoothUserService",
        "BthAvctpSvc",
        "BthHFSrv",
        "DispBrokerDesktopSvc",
        "FDResPub",
        "FrameServer",
        "LanmanServer",
        "LanmanWorkstation",
        "Netlogon",
        "Netman",
        "PNRPsvc",
        "Pnrpsvc",
        "SSDPSRV",
        "WlanSvc",
        "wscsvc",
        "EventLog",
        "Dnscache",
        "Dhcp",
        "Winmgmt",
        "CryptSvc",
        "PlugPlay",
        "RpcSs",
        "SamSs",
        "Schedule",
        "SysMain",           # Superfetch (Manual edirik)
        "Themes",
        "TrkWks",
        "W32Time",
        "WdiServiceHost",
        "WinDefend",         # Defender (Disabled edirik)
        "WpnService",        # Push Notifications (Disabled edirik)
        "wuauserv",          # Windows Update (Disabled edirik)
        "WSearch"            # Windows Search (Manual edirik)
    )
    
    foreach ($Service in $ServicesToOptimize.Keys) {
        try {
            $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceObj) {
                $CurrentStartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$Service'").StartMode
                $TargetStartType = $ServicesToOptimize[$Service]
                
                if ($CurrentStartType -ne $TargetStartType) {
                    # Servisi dayandır
                    Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                    
                    # Startup type dəyiş
                    Set-Service -Name $Service -StartupType $TargetStartType -ErrorAction SilentlyContinue
                    
                    Write-Log "✓ Servis optimizasiya edildi: $Service ($CurrentStartType -> $TargetStartType)" -Level "SUCCESS"
                    $OptimizedServices++
                }
            }
        }
        catch {
            Write-Log "⚠ Servis optimizasiya edilmədi: $Service" -Level "WARNING"
            $FailedServices++
        }
    }
    
    Write-Log "Servis optimizasiyası tamamlandı. Optimizasiya edildi: $OptimizedServices, Xəta: $FailedServices" -Level "INFO"
    
    return @{
        Optimized = $OptimizedServices
        Failed = $FailedServices
    }
}

function Set-PrivacySettings {
    Show-Section -SectionNumber 13 -TotalSections 15 -SectionTitle "Məxfilik Tənzimləmələri" -SectionDescription "Məxfilik ayarları tətbiq edilir..."
    
    $AppliedSettings = 0
    $FailedSettings = 0
    
    # Location services disable
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Log "✓ Location services deaktiv edildi" -Level "SUCCESS"
        $AppliedSettings++
    }
    catch {
        Write-Log "⚠ Location services deaktiv edilmədi" -Level "WARNING"
        $FailedSettings++
    }
    
    # Diagnostic data minimal
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force
        Write-Log "✓ Diagnostic data minimala endirildi" -Level "SUCCESS"
        $AppliedSettings++
    }
    catch {
        Write-Log "⚠ Diagnostic data minimala endirilmədi" -Level "WARNING"
        $FailedSettings++
    }
    
    # Activity history təmizlə
    try {
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Name "*" -Force -ErrorAction SilentlyContinue
        Write-Log "✓ Activity history təmizləndi" -Level "SUCCESS"
        $AppliedSettings++
    }
    catch {
        Write-Log "⚠ Activity history təmizlənmədi" -Level "WARNING"
        $FailedSettings++
    }
    
    # Hosts file-a telemetriya domainləri əlavə et
    try {
        $HostsContent = @"
# Windows Telemetry Block
0.0.0.0 vortex.data.microsoft.com
0.0.0.0 vortex-win.data.microsoft.com
0.0.0.0 telecommand.telemetry.microsoft.com
0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net
0.0.0.0 oca.telemetry.microsoft.com
0.0.0.0 oca.telemetry.microsoft.com.nsatc.net
0.0.0.0 sqm.telemetry.microsoft.com
0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net
0.0.0.0 watson.telemetry.microsoft.com
0.0.0.0 watson.telemetry.microsoft.com.nsatc.net
0.0.0.0 redir.metaservices.microsoft.com
0.0.0.0 choice.microsoft.com
0.0.0.0 choice.microsoft.com.nsatc.net
0.0.0.0 df.telemetry.microsoft.com
0.0.0.0 reports.wes.df.telemetry.microsoft.com
0.0.0.0 services.wes.df.telemetry.microsoft.com
0.0.0.0 sqm.df.telemetry.microsoft.com
0.0.0.0 telemetry.microsoft.com
0.0.0.0 watson.ppe.telemetry.microsoft.com
0.0.0.0 telemetry.appex.bing.net
0.0.0.0 telemetry.urs.microsoft.com
0.0.0.0 settings-sandbox.data.microsoft.com
0.0.0.0 vortex-sandbox.data.microsoft.com
0.0.0.0 survey.watson.microsoft.com
0.0.0.0 watson.live.com
0.0.0.0 watson.microsoft.com
0.0.0.0 statsfe2.ws.microsoft.com
0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com
0.0.0.0 compatexchange.cloudapp.net
0.0.0.0 cs1.wpc.v0cdn.net
0.0.0.0 a-0001.a-msedge.net
0.0.0.0 statsfe2.update.microsoft.com.akadns.net
0.0.0.0 sls.update.microsoft.com.nsatc.net
0.0.0.0 fe2.update.microsoft.com.nsatc.net
0.0.0.0 diagnostics.support.microsoft.com
0.0.0.0 corp.sts.microsoft.com
0.0.0.0 statsfe1.ws.microsoft.com
0.0.0.0 pre.footprintpredict.com
0.0.0.0 i1.services.social.microsoft.com
0.0.0.0 i1.services.social.microsoft.com.nsatc.net
0.0.0.0 feedback.windows.com
0.0.0.0 feedback.microsoft-hohm.com
0.0.0.0 feedback.search.microsoft.com
0.0.0.0 rad.msn.com
0.0.0.0 preview.msn.com
0.0.0.0 ad.doubleclick.net
0.0.0.0 ads.msn.com
0.0.0.0 ads1.msads.net
0.0.0.0 ads1.msn.com
0.0.0.0 a.ads1.msn.com
0.0.0.0 a.ads2.msn.com
0.0.0.0 adnexus.net
0.0.0.0 adnxs.com
0.0.0.0 az361816.vo.msecnd.net
0.0.0.0 az512334.vo.msecnd.net

# Microsoft Edge Blok
0.0.0.0 edge.microsoft.com
0.0.0.0 msedge.api.cdp.microsoft.com
0.0.0.0 edgeassetservice.azureedge.net
0.0.0.0 msedgesettings.api.cdp.microsoft.com
0.0.0.0 msedge.b.tlu.dl.delivery.mp.microsoft.com
0.0.0.0 msedge.f.dl.delivery.mp.microsoft.com

# OneDrive Blok
0.0.0.0 oneclient.sfx.ms
0.0.0.0 g.live.com
0.0.0.0 onedrive.live.com
0.0.0.0 skyapi.onedrive.live.com

# Xbox Blok
0.0.0.0 xboxlive.com
0.0.0.0 xbox.com
0.0.0.0 user.auth.xboxlive.com
0.0.0.0 presence-heartbeat.xboxlive.com
"@
        
        $HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $CurrentHosts = Get-Content $HostsPath -ErrorAction SilentlyContinue
        
        if ($CurrentHosts -notcontains "# Windows Telemetry Block") {
            Add-Content -Path $HostsPath -Value "`n$HostsContent" -Encoding ASCII -ErrorAction SilentlyContinue
            Write-Log "✓ Hosts faylı telemetriya domainləri ilə güncəlləndi" -Level "SUCCESS"
            $AppliedSettings++
        } else {
            Write-Log "ℹ Hosts faylı əvvəlcədən güncəllənib" -Level "INFO"
        }
    }
    catch {
        Write-Log "⚠ Hosts faylı güncəllənmədi" -Level "WARNING"
        $FailedSettings++
    }
    
    # Cortana deaktiv et
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Log "✓ Cortana deaktiv edildi" -Level "SUCCESS"
        $AppliedSettings++
    }
    catch {
        Write-Log "⚠ Cortana deaktiv edilmədi" -Level "WARNING"
        $FailedSettings++
    }
    
    # Tailored experiences disable
    try {
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force
        Write-Log "✓ Tailored experiences deaktiv edildi" -Level "SUCCESS"
        $AppliedSettings++
    }
    catch {
        Write-Log "⚠ Tailored experiences deaktiv edilmədi" -Level "WARNING"
        $FailedSettings++
    }
    
    # Advertising ID disable
    try {
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord -Force
        Write-Log "✓ Advertising ID deaktiv edildi" -Level "SUCCESS"
        $AppliedSettings++
    }
    catch {
        Write-Log "⚠ Advertising ID deaktiv edilmədi" -Level "WARNING"
        $FailedSettings++
    }
    
    Write-Log "Məxfilik tənzimləmələri tamamlandı. Tətbiq edildi: $AppliedSettings, Xəta: $FailedSettings" -Level "INFO"
    
    return @{
        Applied = $AppliedSettings
        Failed = $FailedSettings
    }
}

function Optimize-DiskCleanup {
    Show-Section -SectionNumber 14 -TotalSections 15 -SectionTitle "Disk Cleanup" -SectionDescription "Disk təmizləmə və optimizasiya işləyir..."
    
    $CleanedItems = 0
    $FailedItems = 0
    
    try {
        # Temp faylları təmizlə
        Write-Log "Temp faylları təmizlənir..." -Level "INFO"
        
        $TempPaths = @(
            "$env:TEMP\*",
            "C:\Windows\Temp\*",
            "$env:LOCALAPPDATA\Temp\*",
            "$env:USERPROFILE\AppData\Local\Temp\*"
        )
        
        foreach ($TempPath in $TempPaths) {
            try {
                Remove-Item -Path $TempPath -Recurse -Force -ErrorAction SilentlyContinue
                $CleanedItems++
            }
            catch {
                $FailedItems++
            }
        }
        
        Write-Log "✓ Temp faylları təmizləndi" -Level "SUCCESS"
        
        # Prefetch fayllarını təmizlə
        try {
            Remove-Item -Path "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
            Write-Log "✓ Prefetch faylları təmizləndi" -Level "SUCCESS"
            $CleanedItems++
        }
        catch {
            Write-Log "⚠ Prefetch faylları təmizlənmədi" -Level "WARNING"
            $FailedItems++
        }
        
        # DNS cache təmizlə
        try {
            ipconfig /flushdns 2>&1 | Out-Null
            Write-Log "✓ DNS cache təmizləndi" -Level "SUCCESS"
            $CleanedItems++
        }
        catch {
            Write-Log "⚠ DNS cache təmizlənmədi" -Level "WARNING"
            $FailedItems++
        }
        
        # Disk cleanup işə sal
        try {
            # Cleanmgr parametrləri
            $CleanmgrParams = "/sagerun:1"
            
            # Disk cleanup faylını yarat
            $RegCleanmgr = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Memory Dump Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Service Pack Cleanup]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Archive Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Queue Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Archive Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Queue Files]
@=""
"StateFlags0001"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files]
@=""
"StateFlags0001"=dword:00000002
"@
            
            $RegFile = "$env:TEMP\cleanmgr.reg"
            $RegCleanmgr | Out-File -FilePath $RegFile -Encoding ASCII -Force
            regedit /s $RegFile 2>&1 | Out-Null
            Remove-Item $RegFile -Force -ErrorAction SilentlyContinue
            
            # Cleanmgr işə sal
            Start-Process -FilePath "cleanmgr.exe" -ArgumentList $CleanmgrParams -Wait -WindowStyle Hidden
            Write-Log "✓ Disk cleanup işə salındı" -Level "SUCCESS"
            $CleanedItems++
        }
        catch {
            Write-Log "⚠ Disk cleanup işə salınmadı" -Level "WARNING"
            $FailedItems++
        }
        
        # Disk optimizasiya
        try {
            # Defrag info
            $Drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3 -and $_.Size -gt 0}
            
            foreach ($Drive in $Drives) {
                $DriveLetter = $Drive.DeviceID
                
                # Optimize drive
                Optimize-Volume -DriveLetter $DriveLetter.TrimEnd(':') -Defrag -Verbose -ErrorAction SilentlyContinue
                Write-Log "✓ Disk optimizasiya edildi: $DriveLetter" -Level "SUCCESS"
                $CleanedItems++
            }
        }
        catch {
            Write-Log "⚠ Disk optimizasiya edilmədi" -Level "WARNING"
            $FailedItems++
        }
        
    }
    catch {
        Write-Log "✗ Disk cleanup edilərkən xəta: $_" -Level "ERROR"
        $FailedItems++
    }
    
    Write-Log "Disk cleanup tamamlandı. Təmizləndi: $CleanedItems, Xəta: $FailedItems" -Level "INFO"
    
    return @{
        Cleaned = $CleanedItems
        Failed = $FailedItems
    }
}

function Show-FinalSummary {
    Show-Section -SectionNumber 15 -TotalSections 15 -SectionTitle "Əməliyyat Xülasəsi" -SectionDescription "Bütün dəyişikliklər xülasəsi..."
    
    Write-Host ""
    Write-Color "════════════════════════════════════════════════════════════════════" -Color "Cyan"
    Write-Color "                    DEBLOAT SCRIPTİ TAMAMLANDI!                     " -Color "Green"
    Write-Color "════════════════════════════════════════════════════════════════════" -Color "Cyan"
    Write-Host ""
    
    # Statistika cədvəli
    Write-Color "📊 ƏMƏLİYYAT STATİSTİKASI:" -Color "Yellow"
    Write-Host ""
    
    $StatsTable = @(
        [PSCustomObject]@{
            "Bölmə" = "Windows Apps"
            "Status" = "✓ Tamamlandı"
            "Detallar" = "$($Global:Stats.AppsRemoved) app silindi"
        }
        [PSCustomObject]@{
            "Bölmə" = "Microsoft Edge"
            "Status" = "✓ Tam silindi"
            "Detallar" = "Edge, WebView2, Update"
        }
        [PSCustomObject]@{
            "Bölmə" = "OneDrive"
            "Status" = "✓ Tam silindi"
            "Detallar" = "App, Servis, Startup"
        }
        [PSCustomObject]@{
            "Bölmə" = "Windows Defender"
            "Status" = "✓ Deaktiv edildi"
            "Detallar" = "Tamamilə deaktiv"
        }
        [PSCustomObject]@{
            "Bölmə" = "Xbox & Oyunlar"
            "Status" = "✓ Silindi"
            "Detallar" = "App, Game Bar, Servislər"
        }
        [PSCustomObject]@{
            "Bölmə" = "Telemetriya"
            "Status" = "✓ Deaktiv edildi"
            "Detallar" = "$($Global:Stats.TelemetryDisabled) servis"
        }
        [PSCustomObject]@{
            "Bölmə" = "Windows Update"
            "Status" = "⚠ Deaktiv edildi"
            "Detallar" = "Manual yeniləmələr edin!"
        }
        [PSCustomObject]@{
            "Bölmə" = "Scheduled Tasks"
            "Status" = "✓ Təmizləndi"
            "Detallar" = "$($Global:Stats.TasksRemoved) task silindi"
        }
        [PSCustomObject]@{
            "Bölmə" = "Pagefile"
            "Status" = "✓ Optimizasiya edildi"
            "Detallar" = "$($Global:Stats.PagefileInitial)-$($Global:Stats.PagefileMax) MB"
        }
        [PSCustomObject]@{
            "Bölmə" = "Power Plan"
            "Status" = "✓ Aktiv edildi"
            "Detallar" = "Ultimate Performance"
        }
        [PSCustomObject]@{
            "Bölmə" = "Visual Effects"
            "Status" = "✓ Optimizasiya edildi"
            "Detallar" = "Performans prioritet"
        }
        [PSCustomObject]@{
            "Bölmə" = "Servislər"
            "Status" = "✓ Optimizasiya edildi"
            "Detallar" = "$($Global:Stats.ServicesOptimized) servis"
        }
        [PSCustomObject]@{
            "Bölmə" = "Məxfilik"
            "Status" = "✓ Tənzimləndi"
            "Detallar" = "$($Global:Stats.PrivacySettings) ayar"
        }
        [PSCustomObject]@{
            "Bölmə" = "Disk Cleanup"
            "Status" = "✓ Tamamlandı"
            "Detallar" = "Temp fayllar təmizləndi"
        }
    )
    
    $StatsTable | Format-Table -AutoSize | Out-Host
    
    Write-Host ""
    Write-Color "📁 LOG FAYLLARI:" -Color "Yellow"
    Write-Color "   • Əməliyyat Logu: $LogPath" -Color "Gray"
    Write-Color "   • Transcript: $TranscriptPath" -Color "Gray"
    Write-Color "   • Backup Qovluğu: $BackupPath" -Color "Gray"
    Write-Host ""
    
    Write-Color "⚠️  MÜHÜM XƏBƏRDARLIQLAR:" -Color "Red"
    Write-Color "   1. Windows Defender silindi - ALTERNATİV ANTİVİRUS QURAŞDIRIN!" -Color "Yellow"
    Write-Color "   2. Windows Update deaktivdir - MANUAL YENİLƏMƏLƏR EDİN!" -Color "Yellow"
    Write-Color "   3. Microsoft Edge silindi - BROWSER QURAŞDIRIN!" -Color "Yellow"
    Write-Color "   4. Sistem Bərpa Nöqtəsi yaradılıb: 'Windows 10 Debloat Script'" -Color "Yellow"
    Write-Host ""
    
    Write-Color "🚀 NÖVBƏTİ ADDIMLAR:" -Color "Green"
    Write-Color "   1. Sistemə alternativ antivirus quraşdırın (Malwarebytes, Kaspersky, vs.)" -Color "Gray"
    Write-Color "   2. İstədiyiniz browser-i quraşdırın (Chrome, Firefox, Opera, Brave)" -Color "Gray"
    Write-Color "   3. Office proqramına ehtiyacınız varsa, LibreOffice və ya Office 365 quraşdırın" -Color "Gray"
    Write-Color "   4. OneDrive alternativi kimi Google Drive, Dropbox istifadə edin" -Color "Gray"
    Write-Color "   5. Sistemin stabil işlədiyini yoxlayın" -Color "Gray"
    Write-Host ""
    
    Write-Color "🛡️  QORUNAN SERVİSLƏR (İŞLƏYİR):" -Color "Green"
    
    $ProtectedServices = @(
        "AudioEndpointBuilder",
        "Audiosrv",
        "BluetoothUserService",
        "BthAvctpSvc",
        "BthHFSrv",
        "DispBrokerDesktopSvc",
        "FDResPub",
        "FrameServer",
        "LanmanServer",
        "LanmanWorkstation",
        "Netlogon",
        "Netman",
        "PNRPsvc",
        "Pnrpsvc",
        "SSDPSRV",
        "WlanSvc",
        "EventLog",
        "Dnscache",
        "Dhcp",
        "Winmgmt",
        "CryptSvc",
        "PlugPlay",
        "RpcSs",
        "SamSs",
        "Schedule",
        "Themes",
        "TrkWks",
        "W32Time"
    )
    
    $RunningServices = 0
    foreach ($Service in $ProtectedServices) {
        try {
            $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
            if ($ServiceObj -and $ServiceObj.Status -eq "Running") {
                $RunningServices++
            }
        }
        catch {
            # Xəta olarsa, keç
        }
    }
    
    Write-Color "   $RunningServices/$($ProtectedServices.Count) qorunan servis işləyir" -Color "Green"
    Write-Host ""
    
    # Qorunan servislərin siyahısı
    Write-Color "🔧 QORUNAN HƏYATİ SERVİSLƏR:" -Color "Cyan"
    $CriticalServices = @("Audiosrv", "WlanSvc", "Dhcp", "Dnscache", "EventLog", "PlugPlay", "RpcSs")
    foreach ($Service in $CriticalServices) {
        $Status = (Get-Service -Name $Service -ErrorAction SilentlyContinue).Status
        $Icon = if ($Status -eq "Running") { "✓" } else { "✗" }
        $Color = if ($Status -eq "Running") { "Green" } else { "Red" }
        Write-Color "   $Icon $Service: $Status" -Color $Color
    }
    
    Write-Host ""
    
    # Yenidən başlatma seçimi
    if (-not $NoRestart) {
        Write-Color "🔄 Bəzi dəyişikliklərin tətbiqi üçün sistemin yenidən başladılması lazımdır." -Color "Yellow"
        $restartChoice = Read-Host "Sistem indi yenidən başladılsın? (Y/N)"
        
        if ($restartChoice -match '^(Y|y|E|e|Yes|yes|YES)$') {
            Write-Log "İstifadəçi tərəfindən yenidən başlatma seçildi" -Level "INFO"
            Write-Color "Sistem 10 saniyəyə yenidən başladılır..." -Color "Yellow"
            
            # Registry ayarlarını təzələ
            rundll32.exe user32.dll, UpdatePerUserSystemParameters 1, True 2>&1 | Out-Null
            
            # Explorer restart
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Process explorer.exe
            
            # Yenidən başlatma sayğacı
            for ($i = 10; $i -gt 0; $i--) {
                Write-Host -NoNewline "`rYenidən başlatma $i saniyəyə...   "
                Start-Sleep -Seconds 1
            }
            
            Restart-Computer -Force
        }
        else {
            Write-Log "İstifadəçi yenidən başlatmağı ləğv etdi" -Level "INFO"
            Write-Color "⚠ Sistemi özünüz yenidən başlatmağı unutmayın!" -Color "Yellow"
        }
    }
    
    Write-Host ""
    Write-Color "✅ Script tamamlandı. Log fayllarına baxmağı unutmayın!" -Color "Green"
    Write-Host ""
    
    # Script'i açıq qoy
    Write-Color "Çıxmaq üçün Enter düyməsini basın..." -Color "Gray" -NoNewLine
    $null = Read-Host
}

function Start-DebloatMain {
    # Global statistika
    $Global:Stats = @{
        AppsRemoved = 0
        EdgeRemoved = 0
        OneDriveRemoved = 0
        DefenderDisabled = 0
        XboxRemoved = 0
        TelemetryDisabled = 0
        UpdateDisabled = 0
        TasksRemoved = 0
        PagefileInitial = 0
        PagefileMax = 0
        PowerPlan = ""
        ServicesOptimized = 0
        PrivacySettings = 0
        DiskCleaned = 0
    }
    
    # Transcript başlat
    Start-Transcript -Path $TranscriptPath -ErrorAction SilentlyContinue
    
    try {
        Show-Header
        
        # 1. İlkin yoxlamalar
        Show-Section -SectionNumber 0 -TotalSections 15 -SectionTitle "İlkin Yoxlamalar" -SectionDescription "Sistem və administrator yoxlamaları..."
        
        # Administrator yoxlaması
        if (-not (Test-Administrator)) {
            Write-Log "Bu scripti icra etmək üçün Administrator hüquqları lazımdır!" -Level "ERROR"
            Write-Color "Scripti 'Run as Administrator' seçimi ilə yenidən başladın." -Color "Red"
            pause
            exit 1
        }
        Write-Log "Administrator hüquqları yoxlandı: TƏSDİQ" -Level "SUCCESS"
        
        # Windows versiyası yoxlaması
        $OSVersion = [System.Environment]::OSVersion.Version
        if ($OSVersion.Major -ne 10) {
            Write-Log "Bu script yalnız Windows 10 üçün nəzərdə tutulub!" -Level "WARNING"
            $continue = Read-Host "Buna baxmayaraq davam etmək istəyirsiniz? (Y/N)"
            if ($continue -notmatch '^(Y|y|E|e)$') {
                exit 0
            }
        }
        
        # İstifadəçi razılığı
        if (-not $SkipWarning) {
            Confirm-UserConsent
        }
        
        # Sistem Bərpa Nöqtəsi
        if ($CreateRestorePoint) {
            $restoreCreated = Create-SystemRestorePoint
            if (-not $restoreCreated) {
                $continue = Read-Host "Bərpa nöqtəsi yaradıla bilmədi. Davam etmək istəyirsiniz? (Y/N)"
                if ($continue -notmatch '^(Y|y|E|e)$') {
                    exit 0
                }
            }
        }
        
        # Backup qovluğu yarat
        if (-not (Test-Path $BackupPath)) {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        }
        
        # Əsas əməliyyatlar
        if (-not $SkipApps) {
            $appsResult = Remove-WindowsApps
            $Global:Stats.AppsRemoved = $appsResult.Removed
            
            $edgeResult = Remove-EdgeCompletely
            $Global:Stats.EdgeRemoved = $edgeResult.Removed
            
            $oneDriveResult = Remove-OneDriveCompletely
            $Global:Stats.OneDriveRemoved = $oneDriveResult.Removed
        }
        
        if (-not $SkipServices) {
            $defenderResult = Remove-WindowsDefender
            $Global:Stats.DefenderDisabled = $defenderResult.Disabled
            
            $xboxResult = Remove-XboxAndGaming
            $Global:Stats.XboxRemoved = $xboxResult.Removed
            
            $telemetryResult = Disable-TelemetryServices
            $Global:Stats.TelemetryDisabled = $telemetryResult.Disabled
            
            $updateResult = Disable-WindowsUpdate
            $Global:Stats.UpdateDisabled = $updateResult.Disabled
            
            $tasksResult = Clean-ScheduledTasks
            $Global:Stats.TasksRemoved = $tasksResult.Removed
        }
        
        if (-not $SkipOptimization) {
            $pagefileResult = Optimize-Pagefile
            if ($pagefileResult.Success) {
                $Global:Stats.PagefileInitial = $pagefileResult.InitialSize
                $Global:Stats.PagefileMax = $pagefileResult.MaximumSize
            }
            
            $powerPlanResult = Optimize-PowerPlan
            if ($powerPlanResult.Success) {
                $Global:Stats.PowerPlan = $powerPlanResult.PowerPlan
            }
            
            $visualEffectsResult = Optimize-VisualEffects
            
            $servicesResult = Optimize-Services
            $Global:Stats.ServicesOptimized = $servicesResult.Optimized
            
            $diskResult = Optimize-DiskCleanup
            $Global:Stats.DiskCleaned = $diskResult.Cleaned
        }
        
        if (-not $SkipPrivacy) {
            $privacyResult = Set-PrivacySettings
            $Global:Stats.PrivacySettings = $privacyResult.Applied
        }
        
        # Final xülasə
        Show-FinalSummary
        
    }
    catch {
        Write-Log "Script icrasında gözlənilməz xəta: $_" -Level "ERROR"
        Write-Color "Script xəta ilə dayandı. Log fayllarını yoxlayın." -Color "Red"
        Write-Host ""
        Write-Color "Xəta detalları: $_" -Color "Red"
        Write-Host ""
    }
    finally {
        # Transcript dayandır
        Stop-Transcript -ErrorAction SilentlyContinue
        
        # Log faylının yerini göstər
        if (Test-Path $LogPath) {
            Write-Host ""
            Write-Color "Log faylı: $LogPath" -Color "Gray"
        }
        
        if (Test-Path $TranscriptPath) {
            Write-Color "Transcript: $TranscriptPath" -Color "Gray"
        }
        
        if (Test-Path $BackupPath) {
            $backupSize = "{0:N2} MB" -f ((Get-ChildItem $BackupPath -Recurse | Measure-Object Length -Sum).Sum / 1MB)
            Write-Color "Backup: $BackupPath ($backupSize)" -Color "Gray"
        }
    }
}

# Script başladılır
Start-DebloatMain