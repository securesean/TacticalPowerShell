# Processes 
Get-Process | Out-GridView -PassThru | Stop-Process
## Adding Command line
Get-Process | Select-Object Id, Name, StartTime, @{Name='CommandLine';Expression={(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}} | Out-GridView -PassThru | Stop-Process
## Executables running out of temp
Get-Process | Where-Object { $_.Path -like '*Temp*' } | Out-GridView -PassThru | Stop-Process


# Network Connections
Get-NetTCPConnection | Out-GridView 
## Processes Listening for connections
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | 
    ForEach-Object { Get-Process -Id $_.OwningProcess } | 
    Select-Object Id, Name | 
    Out-GridView -PassThru | 
    Stop-Process
## Listening processes with command lines
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Where-Object { $_.LocalAddress -ne '127.0.0.1' } | 
    ForEach-Object { 
        $process = Get-Process -Id $_.OwningProcess
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            ProcessId = $process.Id
            ProcessName = $process.Name
            CmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($process.Id)").CommandLine
        }
    } | 
    Out-GridView -PassThru | 
    Stop-Process
## List Established TCP Connections
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Where-Object { $_.LocalAddress -ne '127.0.0.1' } | 
    ForEach-Object { 
        $process = Get-Process -Id $_.OwningProcess
        [PSCustomObject]@{
            LocalPort = $_.LocalPort
            RemotePort = $_.RemotePort
            RemoteAddress = $_.RemoteAddress
            ProcessId = $process.Id
            ProcessName = $process.Name
            CmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($process.Id)").CommandLine
        }
    } | 
    Out-GridView -PassThru | 
    Stop-Process

# Blocking Listening Processes 
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | 
    Select-Object LocalAddress, LocalPort, OwningProcess | 
    Out-GridView -PassThru | 
    ForEach-Object { New-NetFirewallRule -DisplayName "Block Port $_.LocalPort" -Direction Inbound -Action Block -LocalPort $_.LocalPort -Protocol TCP }

# Blocking Active network connections 
# Block Remote IP
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Where-Object { $_.LocalAddress -ne '127.0.0.1' } | 
    ForEach-Object { 
        $process = Get-Process -Id $_.OwningProcess
        [PSCustomObject]@{
            LocalPort = $_.LocalPort
            RemotePort = $_.RemotePort
            RemoteAddress = $_.RemoteAddress
            ProcessId = $process.Id
            ProcessName = $process.Name
            Path = $process.Path
            CmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($process.Id)").CommandLine
        }
    } | 
    Out-GridView -PassThru | 
    ForEach-Object { New-NetFirewallRule -DisplayName "Block Host ${$_.RemoteAddress}" -Direction Outbound -Action Block -RemoteAddress $_.RemoteAddress }
# Block by Executable
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Where-Object { $_.LocalAddress -ne '127.0.0.1' } | 
    ForEach-Object { 
        $process = Get-Process -Id $_.OwningProcess
        [PSCustomObject]@{
            LocalPort = $_.LocalPort
            RemotePort = $_.RemotePort
            RemoteAddress = $_.RemoteAddress
            ProcessId = $process.Id
            ProcessName = $process.Name
            Path = $process.Path
            CmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($process.Id)").CommandLine
        }
    } | 
    Out-GridView -PassThru | 
    ForEach-Object { New-NetFirewallRule -DisplayName "Block Program ${$_.Path}" -Direction Outbound -Action Block -Program $_.Path }


# Listing Services
Get-Service | Out-GridView -PassThru | Stop-Service

# Get Windows users | Out-GridView | Delete users
Get-LocalUser | Out-GridView -PassThru | ForEach-Object { Disable-LocalUser -Name $_.Name }
Get-LocalUser | Out-GridView -PassThru | ForEach-Object { Remove-LocalUser -Name $_.Name }

# Scheduled tasks | Out-GridView | Disable task
Get-ScheduledTask | Out-GridView -PassThru | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath }

# Scheduled tasks | Out-GridView | Display action and trigger | Disable task
Get-ScheduledTask | ForEach-Object {
    $TaskDetails = $_ | Get-ScheduledTaskInfo
    $Triggers = ($_ | Get-ScheduledTaskTrigger | ForEach-Object { $_.At })
    $Actions = ($_ | Get-ScheduledTaskAction | ForEach-Object { $_.Execute + " " + $_.Arguments })
    [PSCustomObject]@{
        TaskName  = $_.TaskName
        TaskPath  = $_.TaskPath
        State     = $TaskDetails.State
        LastRun   = $TaskDetails.LastRunTime
        NextRun   = $TaskDetails.NextRunTime
        Triggers  = ($Triggers -join ", ")
        Actions   = ($Actions -join ", ")
    }
} | Out-GridView -PassThru | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath }

# List recently created or modified files in key directories
Get-ChildItem -Path "C:\Windows\Temp", "C:\ProgramData", "$env:USERPROFILE\AppData" -Recurse |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
    Select-Object FullName, LastWriteTime | Out-GridView

# List programs set to run on startup
# Check common Windows startup registry locations for potential malware persistence
# Registry Startup Locations
$RegistryStartupKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
# Retrieve registry startup entries
$RegistryStartup = $RegistryStartupKeys | ForEach-Object {
    Get-Item -Path $_ -ErrorAction SilentlyContinue |
        ForEach-Object {
            $key = $_
            $_.Property | ForEach-Object{
                $value = $key.GetValue($_)
                [PSCustomObject]@{
                    RegistryKey = $key.PSPath
                    EntryName   = $_
                    Value       = $value
            }
        }
}
}
# Display registry startup entries in Out-GridView
$SelectedItems = $RegistryStartup | Out-GridView -PassThru -Title "Select Registry Keys to Disable"
# Delete selected registry keys
if ($SelectedItems) {
    foreach ($Item in $SelectedItems) {
        Write-Host "Deleting registry entry: $($Item.EntryName) from $($Item.RegistryKey)" -ForegroundColor Yellow
        Remove-ItemProperty -Path $Item.RegistryKey -Name $Item.EntryName 
        Write-Host "Deleted: $($Item.EntryName)" -ForegroundColor Green
    }
} else {
    Write-Host "No items selected. No changes made." -ForegroundColor Cyan
}



# Check common Windows startup file locations for potential malware persistence
# Common startup folders
$StartupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
# Retrieve startup files
$StartupFiles = $StartupFolders | ForEach-Object {
    Get-ChildItem -Path $_ -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            [PSCustomObject]@{
                Location = $_.DirectoryName
                FileName = $_.Name
                FullPath = $_.FullName
                LastWriteTime = $_.LastWriteTime
            }
        }
}
# Display startup files in Out-GridView
$SelectedFiles = $StartupFiles | Out-GridView -PassThru -Title "Select Startup Files to Delete"
# Delete selected startup files
if ($SelectedFiles) {
    foreach ($File in $SelectedFiles) {
        Write-Host "Deleting file: $($File.FullPath)" -ForegroundColor Yellow
        Remove-Item -Path $File.FullPath -Force
        Write-Host "Deleted: $($File.FileName)" -ForegroundColor Green
    }
} else {
    Write-Host "No items selected. No changes made." -ForegroundColor Cyan
}


# List installed programs
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", 
"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-GridView

# Find hidden files
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match "Hidden" } |
    Select-Object FullName, Attributes | Out-GridView

# Show firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } | Select-Object Name, DisplayName, Enabled, Action, Direction, LocalAddress, RemoteAddress |
    Out-GridView

# Hash running processes and check with VirusTotal (requires API key)
Get-Process | ForEach-Object {
    $Path = $_.Path
    if ($Path) {
        $Hash = Get-FileHash -Path $Path -Algorithm SHA256
        [PSCustomObject]@{
            ProcessName = $_.Name
            FilePath    = $Path
            Hash        = $Hash.Hash
        }
    }
} | Out-GridView


# Check for recent security log events
Get-EventLog -LogName Security -Newest 100 |
    Select-Object EventID, TimeGenerated, EntryType, Message | Out-GridView

# List successful logons events, group by username, and display in Out-GridView
Get-WinEvent -FilterHashtable @{
    ID=4624
    LogName='Security'
    } |
    ForEach-Object {
        [PSCustomObject]@{
            UserSid      = $_.Properties[4].Value # Account SID
            UserName      = $_.Properties[5].Value # Account name
            Source   = $_.Properties[6].Value # Source
            LogonType = $_.Properties[8].Value # Logon Type
            AuthMethod = $_.Properties[14].Value # Auth method
            IPSource = $_.Properties[18].Value # IP Source
        }
    } |
    Group-Object -Property UserName |
    Sort-Object Count -Descending |
    Out-GridView
## List all the properties of logon events
Get-WinEvent -FilterHashtable @{
    ID=4624
    LogName='Security'
    } | 
    ForEach-Object {
        $PropertiesObject = [PSCustomObject]@{} # Create an empty object
        $Index = 0
        foreach ($Property in $_.Properties) {
            $PropertyName = "Property$Index" # Assign a unique property name (Property0, Property1, etc.)
            $PropertiesObject | Add-Member -MemberType NoteProperty -Name $PropertyName -Value $Property.Value
            $Index++
        }
        $PropertiesObject
    } | Out-GridView


# Then use these CSV-test scripts to demo working through csv outputse
# Example:
# autorunsc 