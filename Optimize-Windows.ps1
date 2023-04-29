
$Report = "$env:TEMP\Optimize-Windows-Report-$(Get-Date -Format "yyyy-MM-dd").md" # todo: midnight?
Out-File -FilePath $Report -InputObject "# make it clean and powerfull $(Get-Date -Format "yyyy-MM-dd")" -Encoding utf8

Function Update-Progress(){
    param(
        [Parameter(Mandatory=$true)]
        [string]$Activity,
        [string]$Rationale=""
    )
    $global:Progress++
    $Percent = [math]::Round(($global:Progress/$global:Total)*100,0)
    Write-Progress -Activity $Activity -Status "$Percent% Complete" -PercentComplete $Percent
    $StepNumber = $Global:Progress.PadLeft(3,'0')
    if $Rationale -eq ""{$Rationale=" BECAUSE $Rationale"}
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



workflow Optimize-Windows {
    param (
        [string] $ComputerName = $env:COMPUTERNAME
    )

    Import-Module Win10-Initial-Setup-Script/Win10.psm1 -Force
    $Env:PSModulePath.Split(";")[1] # todo install module?
    Enable-Resume


    $Progress = 0
    $Total = 150

    # Check for Windows sUpdates
    # Rationale: do this early, because it needs some time
    Update-Progress -Activity "Search for Windows Updates" -Rationale "viruses"
    Get-WindowsUpdate


    # 001: Install Scoop
    # scoop scoop scoopedidoop
    Update-Progress -Activity "Install Scoop" -Rationale "installing apps with an oneliner is fun"
    irm get.scoop.sh | iex
    scoop install aria2 # makes scoop faster
    scoop install git # needed for scoop update
    scoop update
    scoop install sudo # cannot live without sudo


    # Enable Restore Points on C Drive
    # Rationale: Restore Points are disabled by default, but it's always good to have a fallback.
    Update-Progress -Activity "Enable Restore Points on C Drive" -Rationale "its good to have a fallback"
    Enable-ComputerRestore -Drive C:\
    Checkpoint-Computer -Description "Optimize Windows"

    # Remove German Keyboard
    # Rationale: When choosing de-CH as Keyboard Layout, Windows also adds de-DE.
    # This is not needed and only clutters the tray.
    Update-Progress -Activity "Remove German Keyboard" -Rationale "we are swiss"
    $1 = Get-WinUserLanguageList
    $1.RemoveAll( { $args[0].LanguageTag -clike 'de-DE' } )
    Set-WinUserLanguageList $1 -Force


    Update-Progress -Activity "align taskbar to the left" -Rationale "humans are creatures of habit"
    New-ItemProperty "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "0" -PropertyType Dword -Force

    Update-Progress -Activity "remove chat from taskbar" -Rationale "clutter"
    Get-AppxPackage MicrosoftTeams* | Remove-AppxPackage
    New-ItemProperty "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value "0" -PropertyType Dword -Force



    # Hide Account Protection warning in Defender about not using a Microsoft account
    # Rationale: This is not really a problem for us, just for Microsoft ;)
    Update-Progress -Activity "Hide Account Protection warning in defender" -Rationale "it's a false alarm"
    HideAccountProtectionWarn


    Update-Progress -Activity "Remove QuickAssist" -Rationale "not usable without MS-Account"
    get-appxpackage *QuickAssist* | Remove-AppxPackage



    Enable-Resume
    Checkpoint-Workflow
    Restart-Computer -Wait

    # 200 Cleaning up
    Unregister-ScheduledTask -TaskName "ResumeOptimizeWindows" -Confirm:$false
    Get-Content $Report
}

Optimize-Windows