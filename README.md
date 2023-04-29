# windows11

Windows is great ...but just not out of the box.
Out of the box it is cluttered, patronizing and missing crucial functionality.
Let's fix this!

*This has been tested with Win11 Pro, build 22621 (22H2) in english and powershellv7 (pwsh)*
*We are working with powershellv7 because it is faster and newer than v5*
*Device: HP EliteBook x360 1030 G3*

## how to use it
>1. open an **elevated** powershell
>2. download ps7: `iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"`
>3. `pwsh`
>4. `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`
>5. `irm https://github.com/blemli/windows11/Optimize-Windows.ps1 | iex`

## note
- It's best to run this on a really fresh Windows Install
- Enable Virtualization in BIOS: UEFI BIOS (Advanced > CPU Configuration > SVM Mode or VirtualizationTechnology --> enabled
- this does heavy modifications of your system
- The computer might restart multiple times during optimization
- Your input might be required

## opininons
To help you decide if you should use this Script here are some of my opinions that inform it:
- Unclutter: I don't need 10 (bad) ways to do something, just one good one
- A Time and a Place: Start-Menu  for Programs, TaskBar only for *running* programs, Desktop only for files
- avoid microsoft login at all cosast: Its my device, I don't want to authenticate with microsoft to install stuff. ergo no Store!
- convention > configuration. Uniformity makes working fast and breezy

## content
- [Microsoft.PowerShell_profile.ps1](assets/Microsoft.PowerShell_profile.ps1) Powershell Profile
- [policies.json](assets/policies.json) Firefox Configuration
- [Win10-Initial-Setup-Script](Win10-Initial-Setup-Script\Win10.psm1) Many useful functions
- [settings.json](settings.json) Windows Terminal Presets

## what it does in detail
