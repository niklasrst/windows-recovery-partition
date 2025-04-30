<#
.SYNOPSIS
    This script creates a Windows Recovery Environment (WinRE) partition on the system drive and injects custom scripts and tools.

.DESCRIPTION
    This script creates a Windows Recovery Environment (WinRE) partition on the system drive and injects custom scripts and tools.
    It checks if a recovery partition exists, resizes the primary partition if necessary, and mounts the recovery partition.
    The script also copies necessary files to the recovery partition and configures the Windows Recovery Environment.

.PARAMETER -Verbose
   Enable verbose output.

.EXAMPLE
    .\inject-wifi-to-winre.ps1 -Verbose

.NOTES
    Use this script to edit the Windows Recovery Environment (WinRE) to add custom scripts and tools.

.LINK
    https://github.com/niklasrst/windows-recovery-partition

.HELP
https://answers.microsoft.com/en-us/windows/forum/all/unhide-windows-11-recovery-partition-and-add/94abbf0d-1b01-42ff-b362-a226053102ff
https://superuser.com/questions/487136/startup-script-for-windows-recovery-environment
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions?view=windows-11
https://learn.microsoft.com/en-us/powershell/module/storage/new-partition?view=windowsserver2025-ps#-gpttype
https://learn.microsoft.com/de-de/windows-hardware/manufacture/desktop/winpeshlini-reference-launching-an-app-when-winpe-starts?view=windows-11

.AUTHOR
    Niklas Rast
#>

[CmdletBinding()]
param()
    [Parameter(Mandatory = $false, ParameterSetName = 'backupOemWinre')]
    [switch]$backupOemWinre,

# Script settings
$companyName = "NiklasRast"

# LOG
$logFile = ('{0}\{1}.log' -f "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs", [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name))
Start-Transcript -path $logFile -Append
if ($true -ne (Test-Path -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery")) {
    New-Item -Path "HKLM:\SOFTWARE\" -Name "$companyName" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\$companyName\" -Name "Client-Recovery" | Out-Null
}

# Variables
$primaryPartition = Get-Partition | Where-Object { ($_.Type -eq 'Basic') -and ($_.DriveLetter -eq 'C') }
$primaryPartitionSizeInByte = $primaryPartition.Size
$recoveryPartitionSizeInByte = 1031798784
$winrepath
$winreagentpath

# Check if RE Partition exists
if ($null -eq (Get-Partition | Where-Object { ($_.Type -eq 'Recovery') })) {

    Write-Verbose "Checking if Winre.wim and ReAgent.xml exists on the system"
    if ([System.IO.File]::Exists("C:\Windows\System32\Recovery\Winre.wim")) {
        Write-Verbose "Found Winre.wim in C:\Windows\System32\Recovery"
    } else {
        Write-Error "Winre.wim not found. Cannot create RE without it." 
        exit 1
    }
    if ([System.IO.File]::Exists("C:\Windows\System32\Recovery\ReAgent.xml")) {
        Write-Verbose "Found Winre.wim in C:\Windows\System32\Recovery"
    } else {
        Write-Error "ReAgent.xml not found. Cannot create RE without it."
        exit 1
    }

    Write-Verbose "No Recovery Partition found on the system drive. Creating the partition."
    Resize-Partition -DriveLetter $primaryPartition.DriveLetter -Size ($primaryPartitionSizeInByte - $recoveryPartitionSizeInByte) -Confirm:$false
    Write-Verbose "Create Recovery Partition with $recoveryPartitionSizeInByte bytes and GPT Type {de94bba4-06d1-4d40-a16a-bfd50179d6ac}"
    New-Partition -DiskNumber $recoveryPartition.DiskNumber -Size $recoveryPartitionSizeInByte -DriveLetter R -GptType "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}"
    Write-Verbose "Add GPT Attributes: 0x8000000000000001"
    $null = @"
select disk $($recoveryPartition.DiskNumber)
select partition $($recoveryPartition.PartitionNumber)
gpt attributes=0x8000000000000001
exit
"@ | diskpart.exe
    Write-Verbose "Format Recovery Partition with NTFS and Label Recovery"
    Format-Volume -DriveLetter R -FileSystem NTFS -NewFileSystemLabel "Recovery" -Confirm:$false
    New-ItemProperty -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery" -Name "REPartitionSize" -PropertyType "String" -Value $recoveryPartitionSizeInByte -Force | Out-Null
} else {
    Write-Verbose "Recovery Partition found on the system drive."
}

# Temporary Mount Recovery Partition
Write-Verbose "Mounting Recovery Partition to R:\"
Set-Partition -InputObject (Get-Partition | Where-Object { ($_.Type -eq 'Recovery') }) -NewDriveLetter R
$recoveryPartition = Get-Partition | Where-Object { ($_.Type -eq 'Recovery') -and ($_.DriveLetter -eq 'R')}

# Check if Recovery Partition needs to be resized and resize it to $recoveryPartitionSizeInByte bytes
if ($recoveryPartition.Size -lt $recoveryPartitionSizeInByte) {
    Write-Verbose "Recovery Partition is smaller than $recoveryPartitionSizeInByte bytes. Need to recreate it. Shrinking Primary Partition by $recoveryPartitionSizeInByte bytes"
    Resize-Partition -DriveLetter $primaryPartition.DriveLetter -Size ($primaryPartitionSizeInByte - $recoveryPartitionSizeInByte) -Confirm:$false
    Remove-Partition -DriveLetter $recoveryPartition.DriveLetter -Confirm:$false
    Write-Verbose "Create Recovery Partition with $recoveryPartitionSizeInByte bytes and GPT Type {de94bba4-06d1-4d40-a16a-bfd50179d6ac}"
    New-Partition -DiskNumber $recoveryPartition.DiskNumber -Size $recoveryPartitionSizeInByte -DriveLetter R -GptType "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}"
    Write-Verbose "Add GPT Attributes: 0x8000000000000001"
    $null = @"
select disk $($recoveryPartition.DiskNumber)
select partition $($recoveryPartition.PartitionNumber)
gpt attributes=0x8000000000000001
exit
"@ | diskpart.exe
    Write-Verbose "Format Recovery Partition with NTFS and Label Recovery"
    Format-Volume -DriveLetter R -FileSystem NTFS -NewFileSystemLabel "Recovery" -Confirm:$false
    New-ItemProperty -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery" -Name "REPartitionSize" -PropertyType "String" -Value $recoveryPartitionSizeInByte -Force | Out-Null
} else {
    Write-Verbose "Recovery Partition is already $recoveryPartitionSizeInByte bytes. No need to resize it"
    New-ItemProperty -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery" -Name "REPartitionSize" -PropertyType "String" -Value $recoveryPartitionSizeInByte -Force | Out-Null
}

# Disable Recovery Partition while working on it
Write-Verbose "Disable Recovery Partition"
Start-Process -FilePath "Reagentc.exe" -ArgumentList "/disable" -Wait

# Mount Recovery WIM
Write-Verbose "Creating Temp folder"
New-Item -Name "WINRE" -Path "C:\Windows\Temp" -ItemType Directory -Force | Out-Null

Write-Verbose "Mount Recovery WIM to C:\Windows\Temp\WINRE"
if ([System.IO.File]::Exists("C:\Windows\System32\Recovery\Winre.wim")) {
    Write-Verbose "Found Winre.wim in C:\Windows\System32\Recovery"
    $winrepath = "C:\Windows\System32\Recovery\Winre.wim"
    $winreagentpath = "C:\Windows\System32\Recovery\ReAgent.xml"
} elseif ([System.IO.File]::Exists("R:\Recovery\WindowsRE\Winre.wim")) {
    Write-Verbose "Found Winre.wim in R:\Recovery\WindowsRE"
    $winrepath = "R:\Recovery\WindowsRE\Winre.wim"
    $winreagentpath = "R:\Recovery\WindowsRE\ReAgent.xml"
} else {
    Write-Verbose "Winre.wim not found"
    exit 1
}

# Backup OEM winre.wim if configured
if ($backupOemWinre) {
    Write-Verbose "Backup original Winre.wim to C:\Windows\System32\Recovery\OemWinre.wim"
    Copy-Item -Path $winrepath -Destination "C:\Windows\System32\Recovery\OemWinre.wim" -Force | Out-Null
}

Mount-WindowsImage -ImagePath $winrepath -Path "C:\Windows\Temp\WINRE" -Index 1  | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery" -Name "WinREPath" -PropertyType "String" -Value $winrepath -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery" -Name "WinREAgentPath" -PropertyType "String" -Value $winreagentpath -Force | Out-Null

# Extend RE capabilities
switch ((Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture) {
    "ARM 64-bit Processor" { 
        Write-Verbose "Adding ARM64 packages to RE"
        foreach ($file in Get-ChildItem -Path "$PSScriptRoot\tools\arm64cpu" -Filter *.cab) {
            $fileName = ($($file.Name) -replace '\.cab$', '')
            $fileLang = ($($file.Name) -replace '\.cab$', '_en-us')

            Write-Verbose "Adding $fileName.cab to RE"
            dism /image:C:\Windows\Temp\WINRE /add-package /packagepath:"$PSScriptRoot\tools\arm64cpu\$fileName.cab" | Out-Null
            Write-Verbose "Adding $fileLang.cab to RE"
            dism /image:C:\Windows\Temp\WINRE /add-package /packagepath:"$PSScriptRoot\tools\arm64cpu\lang\$fileLang.cab" | Out-Null
        }
        New-ItemProperty -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery" -Name "CPUArch" -PropertyType "String" -Value "arm64" -Force | Out-Null
     }
    "64-bit" {
        Write-Verbose "Adding amd64 packages to RE"
        foreach ($file in Get-ChildItem -Path "$PSScriptRoot\tools\amd64" -Filter *.cab) {
            $fileName = ($($file.Name) -replace '\.cab$', '')
            $fileLang = ($($file.Name) -replace '\.cab$', '_en-us')

            Write-Verbose "Adding $fileName.cab to RE"
            dism /image:C:\Windows\Temp\WINRE /add-package /packagepath:"$PSScriptRoot\tools\amd64\$fileName.cab" | Out-Null
            Write-Verbose "Adding $fileLang.cab to RE"
            dism /image:C:\Windows\Temp\WINRE /add-package /packagepath:"$PSScriptRoot\tools\amd64\lang\$fileLang.cab" | Out-Null
        }
        New-ItemProperty -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery" -Name "CPUArch" -PropertyType "String" -Value "amd64" -Force | Out-Null
    }
    Default { 
        Write-Host "Unknown Architecture. No packages added to RE." 
    }
}

# Add other customizations here
#TODO: SOMETHING MORE

# Unmount and move Recovery WIM
Write-Verbose "Unmount Recovery WIM"
Dismount-WindowsImage -Path "C:\Windows\Temp\WINRE" -Save -CheckIntegrity | Out-Null

Write-Verbose "Create structure on Recovery Partition"
New-Item -Path "R:\" -Name "Recovery" -ItemType Directory -Force | Out-Null
New-Item -Path "R:\Recovery" -Name "WindowsRE" -ItemType Directory -Force | Out-Null
Write-Verbose "Checking if Windows Recovery Environment needs to be moved to the Recovery Partition"
if ($winreagentpath -like "R:\Recovery\WindowsRE*") {
    Write-Verbose "Windows Recovery Environment is already on Recovery Partition. No need to move it."
} else {
    Write-Verbose "Moving Windows Recovery Environment to Recovery Partition"
    Copy-Item -Path $winreagentpath -Destination "R:\Recovery\WindowsRE" -Force
    Copy-Item -Path $winrepath -Destination "R:\Recovery\WindowsRE" -Force -PassThru
}

# Re-Enable Recovery Partition
Write-Verbose "Configuring Reagentc to use the new Winre.wim"
Start-Process -FilePath "Reagentc.exe" -ArgumentList "/SetReImage /path R:\Recovery\WindowsRE /target C:\Windows" -Wait
Write-Verbose "Enable Recovery Partition"
Start-Process -FilePath "Reagentc.exe" -ArgumentList "/Enable /target C:\Windows" -Wait

# Detatch RE Partition
Write-Verbose "Unmount Recovery Partition from R drive"
Get-Volume -DriveLetter R | Get-Partition | Remove-PartitionAccessPath -AccessPath "R:\"

# Write RE Version to Registry
New-ItemProperty -Path "HKLM:\SOFTWARE\$companyName\Client-Recovery" -Name "DesiredWinREState" -PropertyType "String" -Value "1.0.0" -Force | Out-Null
Stop-Transcript