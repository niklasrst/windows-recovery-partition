# 📎 Windows Recovery Partition Injector 📎

This tool is used to customize a local Windows Recovery Partition and Environment.
It will resize the Recovery Partition to 984MB (1031798784 Bytes), add `.cab` files for e.g. PowerShell support (remember to add the matching language files for installation).

![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/niklasrst/windows-recovery-partition/total)

## Requirements
Download the current `mul_languages_and_optional_features_for_windows_11` ISO (available in MSDN), containing the `.cab` files for optional features and languages.

## Customizations

### Company Name
Set the company name which will be used for the detection.
``` powershell
# Script settings
$companyName = "YourCompanyNameHere"
```

### Features
Copy `.cab` files into the `tools\amd64` or `tools\arm64cpu` folder, depending on which cpu architecture youre using and dont forget to include the matching language cab files for the features that you want to install in the `..\lang\` folder of the cpu architecture folder.

## How to deploy?

Install: 
``` powershell
`C:\Windows\SysNative\WindowsPowershell\v1.0\PowerShell.exe -ExecutionPolicy Bypass -Command .\customize-winre.ps1 -verbose`
```
<span style="color:cornflowerblue;font-weight:bold">🛈  HINT</span><br/>
    There is an optional parameter `-backupOemWinre` to keep the OEM recovery image if needed.

Uninstall: 
``` powershell
"There is no way back :)"
```

Detection:
 Check if the Registry key `DesiredState` located in 
``` powershell
"HKLM:\SOFTWARE\YourCompanyNameHere\Client-Recovery" with a value of "1.0.0".
```

---

Made with ❤️ by [Niklas Rast](https://github.com/niklasrst)
