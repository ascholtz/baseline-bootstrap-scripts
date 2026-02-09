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

# Define the registry settings to apply
$RegistrySettings = @(
    @{ Path = "Software\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0; Type = "DWord" },
    @{ Path = "Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Value = 0; Type = "DWord" }
)

# 1. Update the "Default" profile for all NEW users created in the future
$defaultHivePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
reg load HKU\DefaultUser $defaultHivePath
foreach ($setting in $RegistrySettings) {
    $keyPath = "HKU:\DefaultUser\$($setting.Path)"
    if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force }
    Set-ItemProperty -Path $keyPath -Name $setting.Name -Value $setting.Value -Type $setting.Type
}
[gc]::Collect() # Trigger garbage collection to help release the file lock
reg unload HKU\DefaultUser

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

