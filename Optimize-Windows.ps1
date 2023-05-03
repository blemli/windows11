
$Report = "$env:TEMP\Optimize-Windows-Report-$(Get-Date -Format "yyyy-MM-dd").md" # todo: midnight?
Out-File -FilePath $Report -InputObject "# make it clean and powerfull `n $(Get-Date -Format "yyyy-MM-dd")" -Encoding utf8

Function Update-Progress() {
    param(
    [Parameter(Mandatory = $true)]
    [string]$Activity,
    [string]$Rationale = ""
    )
    $global:Progress++
    $Percent = [math]::Round(($global:Progress / $global:Total) * 100, 0)
    Write-Progress -Activity $Activity -Status "$Percent% Complete" -PercentComplete $Percent
    $StepNumber = $Global:Progress.PadLeft(3, '0')
    if ( $Rationale -ne "") { $Rationale = "BECAUSE $Rationale" }
    Out-File -Append -File $Global:Report -InputObject "✅ $StepNumber $Activity $Rationale" -Encoding utf8
}

Function Enable-Resume {
    param(
    [string]$TaskName = "Resume$PsScriptName"
    )
    $TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (!$TaskExists) {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File $($PSScriptRoot)\Optimize-Windows.ps1"
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal
    }
}

Function Set-BlueLightReductionSettings {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)] [ValidateRange(0, 23)] [int]$StartHour,
        [Parameter(Mandatory=$true)] [ValidateSet(0, 15, 30, 45)] [int]$StartMinutes,
        [Parameter(Mandatory=$true)] [ValidateRange(0, 23)] [int]$EndHour,
        [Parameter(Mandatory=$true)] [ValidateSet(0, 15, 30, 45)] [int]$EndMinutes,
        [Parameter(Mandatory=$true)] [bool]$Enabled,
        [Parameter(Mandatory=$true)] [ValidateRange(1200, 6500)] [int]$NightColorTemperature
    )
    $data = (0x43, 0x42, 0x01, 0x00, 0x0A, 0x02, 0x01, 0x00, 0x2A, 0x06)
    $epochTime = [System.DateTimeOffset]::new((date)).ToUnixTimeSeconds()
    $data += $epochTime -band 0x7F -bor 0x80
    $data += ($epochTime -shr 7) -band 0x7F -bor 0x80
    $data += ($epochTime -shr 14) -band 0x7F -bor 0x80
    $data += ($epochTime -shr 21) -band 0x7F -bor 0x80
    $data += $epochTime -shr 28
    $data += (0x2A, 0x2B, 0x0E, 0x1D, 0x43, 0x42, 0x01, 0x00)
    If ($Enabled) {$data += (0x02, 0x01)}
    $data += (0xCA, 0x14, 0x0E)
    $data += $StartHour
    $data += 0x2E
    $data += $StartMinutes
    $data += (0x00, 0xCA, 0x1E, 0x0E)
    $data += $EndHour
    $data += 0x2E
    $data += $EndMinutes
    $data += (0x00, 0xCF, 0x28)
    $data += ($NightColorTemperature -band 0x3F) * 2 + 0x80
    $data += ($NightColorTemperature -shr 6)
    $data += (0xCA, 0x32, 0x00, 0xCA, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00)
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.bluelightreduction.settings\windows.data.bluelightreduction.settings' -Name 'Data' -Value ([byte[]]$data) -Type Binary
}
function force-mkdir($path) {
    if (!(Test-Path $path)) {
        #Write-Host "-- Creating full path to: " $path -ForegroundColor White -BackgroundColor DarkGreen
        New-Item -ItemType Directory -Force -Path $path
    }}
Function Remove-OneDrive{

    ###This script will remove and disable OneDrive integration. ###
###Author of this script: https://github.com/W4RH4WK/Debloat-Windows-10###
###Requires -RunSilent

Install-Module TakeOwn
Import-Module Takeown

Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

Write-Output "Removing additional OneDrive leftovers"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    Remove-Item -Recurse -Force $item.FullName
}

}


function Write-Notification(){
    # The Text that is displayed in the notification
    [Parameter(Mandatory=$true)][String]$text
	New-BurntToastNotification -Text "$text" -AppLogo ./assets/windows11.jpg
}

Function Restart-Explorer {
    <#
    .Synopsis
    Restart the Windows Explorer process.
    #>
    [cmdletbinding(SupportsShouldProcess)]
    [Outputtype("None")]
    Param()

    Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Starting $($myinvocation.mycommand)"
    Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Stopping Explorer.exe process"
    Get-Process -Name Explorer | Stop-Process -Force
    #give the process time to start
    Start-Sleep -Seconds 2
    Try {
        Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Verifying Explorer restarted"
        $p = Get-Process -Name Explorer -ErrorAction stop
    }
    Catch {
        Write-Warning "Manually restarting Explorer"
        Try {
            Start-Process explorer.exe
        }
        Catch {
            #this should never be called
            Throw $_
        }
    }
    Write-Verbose "[$((Get-Date).TimeofDay) END    ] Ending $($myinvocation.mycommand)"
}
function New-TemporaryDirectory {
    # https://stackoverflow.com/a/34559554
    # Parameter help description
    [Parameter()]
    [System.Management.Automation.SwitchParameter]$cd=$false

    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    $path = Join-Path $parent $name
    New-Item -ItemType Directory -Path $path
    if($cd -eq $true ) { Set-Location $path }
    return $path
    
}



Function Optimize-Windows {#todo: workflow?
    param (
    [string] $ComputerName = $env:COMPUTERNAME
    )
    
    Import-Module Win10-Initial-Setup-Script/Win10.psm1 -Force
    $Env:PSModulePath.Split(";")[1] # todo install module?
    Enable-Resume
    
    
    
    $Progress = 0
    $Total = 150
    

    # Enable Restore Points on C Drive
    # Rationale: Restore Points are disabled by default, but it's always good to have a fallback.
    Update-Progress -Activity "Enable Restore Points on C Drive" -Rationale "its good to have a fallback"
    Enable-ComputerRestore -Drive C:\
    Checkpoint-Computer -Description "Optimize Windows"
    

    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

    # Check for Windows Updates
    # Rationale: do this early, because it needs some time
    Update-Progress -Activity "Search for Windows Updates" -Rationale "viruses"
    Install-Module PSWindowsUpdate
    Import-Module PSWindowsUpdate
    Get-WindowsUpdate

    # Install Scoop
    # scoop scoop scoopedidoop
    Update-Progress -Activity "Install Scoop" -Rationale "installing apps with an oneliner is fun"
    Invoke-RestMethod get.scoop.sh | Invoke-Expression
    scoop install aria2 # makes scoop faster
    scoop install git # needed for scoop update
    scoop bucket add extras
    scoop update

    Update-Progress -Activity "Install some tools" -Rationale "they are needed for this script"
    
    Install-Module -Name BurntToast
    Import-Module BurntToast
    scoop install sudo # cannot live without sudo


    # Remove German Keyboard
    # Rationale: When choosing de-CH as Keyboard Layout, Windows also adds de-DE.
    # This is not needed and only clutters the tray.
    $1 = Get-WinUserLanguageList
    $1.RemoveAll( { $args[0].LanguageTag -clike 'de-DE' } )
    Set-WinUserLanguageList $1 -Force
    Update-Progress -Activity "Remove German Keyboard" -Rationale "we are swiss"
    
    
    New-ItemProperty "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "0" -PropertyType Dword -Force
    Update-Progress -Activity "align taskbar to the left" -Rationale "humans are creatures of habit"
    
    Get-AppxPackage MicrosoftTeams* | Remove-AppxPackage
    New-ItemProperty "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value "0" -PropertyType Dword -Force
    Update-Progress -Activity "remove chat from taskbar" -Rationale "clutter"
    
    
    
    # Hide Account Protection warning in Defender about not using a Microsoft account
    # Rationale: This is not really a problem for us, just for Microsoft ;)
    HideAccountProtectionWarn
    Update-Progress -Activity "Hide Account Protection warning in defender" -Rationale "it's a false alarm"
    
    get-appxpackage *QuickAssist* | Remove-AppxPackage
    Update-Progress -Activity "Remove QuickAssist" -Rationale "not usable without MS-Account"
    
    DisableWebSearch
    Update-Progress -Activity "Disable Web Search in Start Menu" -Rationale "unclutter, also there is no edge to open the search results"

    DisableAppSuggestions
    Update-Progress -Activity "Disable App Suggestions" -Rationale "it is patronizing"
    
    Get-AppxPackage *WebExperience* | Remove-AppxPackage
    Update-Progress -Activity "Remove Widgets" -Rationale "we have enough distractions in our lives"
    DisableAdminShares
    Update-Progress -Activity "Disable Admin Shares" -Rationale "security"

    DisableDownloadBlocking
    Update-Progress -Activity "Disable Download Blocking" -Rationale "we know what we are downloading, right?"
    
    EnableUpdateMSProducts
    Update-Progress -Activity "Enable Update of Microsoft Products" -Rationale "the more updates, the better"

    HideTaskView
    Update-Progress -Activity "Hide Task View Button" -Rationale "we already have alt+tab"

    HideTaskbarSearch
    Update-Progress -Activity "Hide Taskbar Search" -Rationale "hitting the windows key is faster"


    RemoveFaxPrinter
    Update-Progress -Activity "Remove Fax Printer" -Rationale "this is not the 80ies"
    
    UninstallXPSPrinter
    Update-Progress -Activity "Uninstall XPSPrinter" -Rationale "what the heck is XPS?"
    
    ShowKnownExtensions
    Update-Progress -Activity "Show known file extensions" -Rationale "we want to know what we are clicking on"
    
    ShowHiddenFiles # todo: remove?
    Update-Progress -Activity "Show hidden files" -Rationale "we want to see everything in our folders"

    DisableSearchAppInStore
    Update-Progress -Activity "Disable Search App in Store" -Rationale "we can't use the store because we don't have a microsoft account"

    #disable snap window button
    reg add "HKCU\Control Panel\Desktop" /V "WindowArrangementActive" /D "0" /F #todo: needs reboot
    Update-Progress -Activity "Disable Snap Window Button" -Rationale "clutter"

    update-progress -Activity "hide annoying news in search" -Rationale "clutter, and distraction"
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -PropertyType DWORD -Value 0


    Set-BlueLightReductionSettings -StartHour 20 -EndHour 04 -StartMinutes 0 -EndMinutes 0 -NightColorTemperature 3500 -Enabled $true
    Update-Progress -Activity "Enable Blue Light Reduction" -Rationale "better sleep"
    get-AppxPackage  *Solitaire* | Remove-AppxPackage
    Update-Progress -Activity "Remove Solitaire" -Rationale "we have better things to do"

    get-appxPackage *xbox* | Remove-AppxPackage -AllUsers
    Update-Progress -Activity "Remove Xbox" -Rationale "we are not gamers"

    get-AppxPackage -allusers *ToDo* | remove-appxpackage
    Update-Progress -Activity "Remove ToDo" -Rationale "If you have to MANAGE them, then you have to many tasks"

    DisableCortana
    Update-Progress -Activity "Disable Cortana" -Rationale "it is not available in switzerland"

    Write-Notification "Please gather your 1Password Security Keys"
    Update-Progress -Activity "Install 1Password" -Rationale "No one should have to remember their passwords"
    scoop bucket add Samiya321_scoop-samiya https://github.com/Samiya321/scoop-samiya
    scoop install 1password
    Start-Process 1password
    Write-Notification -Text "Please Log in to your 1password vaults"

    scoop bucket add blemli-bucket https://github.com/blemli/blemli-bucket
    scoop install edge-blocker
    edgeblock_x64.exe /b
    Update-Progress -Activity "Install Edge Blocker" -Rationale "edge is a cluttery mess"

    scoop install phpstorm
    Update-Progress -Activity "Install PHPStorm" -Rationale "still the best IDE for PHP"

    scoop install github
    Start-Process GitHubDesktop -WindowStyle Maximized
    Write-Notification "Please log in to github"
    Update-Progress -Activity "Install Github Desktop" -Rationale "its just easier than the console"

    scoop bucket add hoilc_scoop-lemon https://github.com/hoilc/scoop-lemon
    scoop install droppoint
    Update-Progress -Activity "Install droppoint" -Rationale "it makes drag&drop more enjoyable"
    
    scoop install regshot
    Update-Progress -Activity "Install Regshot" -Rationale "we want to monitor registry changes"

    winget install DevToys --source msstore
    Update-Progress -Activity "Install DevToys" -Rationale "we don't want to paste confidential text into webtools"
    
    scoop install wiztree
    Update-Progress -Activity "Install WizTree" -Rationale "it is the fastest way to find out what is taking up space on your drive"

    scoop install Spotify
    Update-Progress -Activity "Install Spotify" -Rationale "music is good for the soul"
    Write-Notification "Please log in to Spotify"

    Install-WindowsUpdate
    Update-Progress -Activity "Install Windows Updates" -Rationale "downloading them is not enough"

    Enable-Resume
    Checkpoint-Workflow
    Restart-Computer -Wait
    
    # 200 Cleaning up
    Unregister-ScheduledTask -TaskName "ResumeOptimizeWindows" -Confirm:$false
    Get-Content $Report
}

Optimize-Windows