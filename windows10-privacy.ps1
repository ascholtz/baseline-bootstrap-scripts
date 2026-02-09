# 1. Disable the "Choose privacy settings" experience screen
$OOBEPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"
if (-not (Test-Path $OOBEPath)) { New-Item -Path $OOBEPath -Force }
Set-ItemProperty -Path $OOBEPath -Name "DisablePrivacyExperience" -Value 1 -Type DWord

# 2. Mark privacy consent as already provided (to bypass prompts)
$CurrentOOBE = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
Set-ItemProperty -Path $CurrentOOBE -Name "PrivacyConsentStatus" -Value 1 -Type DWord
Set-ItemProperty -Path $CurrentOOBE -Name "ProtectYourPC" -Value 3 -Type DWord

# 3. Disable specific privacy data collection features
# Turn off Location Services
$LocPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
if (Test-Path $LocPath) { Set-ItemProperty -Path $LocPath -Name "Value" -Value "Deny" }

# Turn off Advertising ID
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord

# Turn off Tailored Experiences (Diagnostic Data)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord

Write-Host "Privacy settings updated. Restart your computer to apply all changes." -ForegroundColor Green

# ----------------------------------------------------------------------------------------------------------------------

# --- 1. Disable Location Services ---
$LocPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
if (-not (Test-Path $LocPath)) { New-Item -Path $LocPath -Force }
Set-ItemProperty -Path $LocPath -Name "Value" -Value "Deny" #

# --- 2. Set Diagnostic Data to Required Only (Minimum level) ---
$DiagPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if (-not (Test-Path $DiagPath)) { New-Item -Path $DiagPath -Force }
Set-ItemProperty -Path $DiagPath -Name "AllowTelemetry" -Value 0 -Type DWord #

# --- 3. Disable Tailored Experiences ---
$TailorPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"
Set-ItemProperty -Path $TailorPath -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord #

# --- 4. Disable Find My Device ---
$FMDPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FindMyDevice"
if (-not (Test-Path $FMDPath)) { New-Item -Path $FMDPath -Force }
Set-ItemProperty -Path $FMDPath -Name "AllowFindMyDevice" -Value 0 -Type DWord #

# --- 5. Disable Inking & Typing Personalization ---
$InkPath = "HKCU:\Software\Microsoft\InputPersonalization"
if (-not (Test-Path $InkPath)) { New-Item -Path $InkPath -Force }
Set-ItemProperty -Path $InkPath -Name "RestrictImplicitInkCollection" -Value 1 -Type DWord
Set-ItemProperty -Path $InkPath -Name "RestrictImplicitTextCollection" -Value 1 -Type DWord #

# --- 6. Disable Advertising ID ---
$AdPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
Set-ItemProperty -Path $AdPath -Name "Enabled" -Value 0 -Type DWord #

# --- 7. Disable the Privacy OOBE Screen (Initial Prompt) ---
$OOBEPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"
if (-not (Test-Path $OOBEPath)) { New-Item -Path $OOBEPath -Force }
Set-ItemProperty -Path $OOBEPath -Name "DisablePrivacyExperience" -Value 1 -Type DWord #

Write-Host "All privacy settings have been set to OFF/NO. Restart your PC to complete." -ForegroundColor Cyan

# ----------------------------------------------------------------------------------------------------------------------

# 1. Map the HKU drive
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
}

# Define the registry settings
$RegistrySettings = @(
    @{ Path = "Software\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0; Type = "DWord" },
    @{ Path = "Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Value = 0; Type = "DWord" }
)

# 2. Function to apply settings with full path and setting output
function Apply-RegistrySettings($rootPath, $profileDisplayName) {
    Write-Host "`n[+] Processing Profile: $profileDisplayName" -ForegroundColor Cyan
    
    foreach ($setting in $RegistrySettings) {
        $fullPath = "$rootPath\$($setting.Path)"
        
        if (-not (Test-Path $fullPath)) { 
            New-Item -Path $fullPath -Force | Out-Null 
        }
        
        Write-Host "    Path:    $fullPath" -ForegroundColor DarkGray
        Write-Host "    Setting: $($setting.Name) = $($setting.Value) ($($setting.Type))" -ForegroundColor Gray
        
        New-ItemProperty -Path $fullPath -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
    }
}

# 3. Update the "Default" profile (Future Users)
Write-Host "--- Modifying Default User Hive ---" -ForegroundColor Yellow
$defaultHivePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"

Write-Host "[*] Action: Loading Default User hive..." -ForegroundColor Magenta
reg load HKU\DefaultUser $defaultHivePath | Out-Null

Apply-RegistrySettings "HKU:\DefaultUser" "Default User Template"

[gc]::Collect()
Write-Host "[*] Action: Unloading Default User hive..." -ForegroundColor Magenta
reg unload HKU\DefaultUser | Out-Null

# 4. Update Existing Profiles (Active & Offline)
Write-Host "`n--- Modifying Existing User Profiles ---" -ForegroundColor Yellow
$PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
$profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | 
            Where-Object { $_.PSChildName -match $PatternSID }

foreach ($profile in $profiles) {
    $sid = $profile.PSChildName
    $userName = Split-Path $profile.ProfileImagePath -Leaf
    
    if (Test-Path "HKU:\$sid") {
        # User is active; no load/unload needed
        Apply-RegistrySettings "HKU:\$sid" "${userName} (Active/Logged In)"
    } else {
        $hivePath = "$($profile.ProfileImagePath)\NTUSER.DAT"
        if (Test-Path $hivePath) {
            Write-Host "[*] Action: Loading hive for ${userName}..." -ForegroundColor Magenta
            reg load "HKU\$sid" $hivePath | Out-Null
            
            Apply-RegistrySettings "HKU:\$sid" "${userName} (Offline Hive)"
            
            [gc]::Collect()
            Start-Sleep -Milliseconds 200
            
            Write-Host "[*] Action: Unloading hive for ${userName}..." -ForegroundColor Magenta
            reg unload "HKU\$sid" | Out-Null
        } else {
            Write-Host "[!] Skipping ${userName}: NTUSER.DAT not found." -ForegroundColor Red
        }
    }
}

Write-Host "`n[SUCCESS] Settings applied to all user profiles." -ForegroundColor Green

# ----------------------------------------------------------------------------------------------------------------------

# 1. Create the directory if it doesn't exist
$path = "C:\tmp"
New-Item -Path $path -ItemType Directory -Force

# 2. Define the log file path
$logFile = "C:\tmp\mylog.log"

# 3. Create a timestamp and message
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$logMessage = "[$timestamp] Script executed successfully."

# 4. Write the line to the log file
Add-Content -Path $logFile -Value $logMessage

