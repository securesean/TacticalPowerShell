# Quick Tactical Cyber Commands
PowerShell can be incredibly useful for more on-host hand-to-hand combat for events like CCDC. This is a little crash course in how to leverage PowerShell when working with a compromised Windows system. We will start with the simple examples and work our way up.

## Using Out-GridView
`Out-GridView` is amazing because it can let you quickly visualize, sort, search, filter, and select objects. Let's start exploration with the simple example of listing processes:

```Get-Process | Out-GridView```

Now let's assume you see a suspicious process and want to want to kill it. That's easy! We can pipe the objects to `Stop-Process`:

```Get-Process | Out-GridView -PassThru | Stop-Process```

Now let's assume you want to see far more data than the default. We can use `select-Object` to show ALL the properties within that object:

```Get-Process | Select-Object * | Out-GridView -PassThru | Stop-Process```

Now let's assume you want to see the actual command, and it's command line arguments. In Windows, that information is not a part of the Process Object that is returned with the `Get-Process` cmdlet and we will need to query WMI for it. We can enrich the data in the pipe and display that information like this:

```Get-Process | Select-Object Id, Name, @{Name='CommandLine';Expression={(Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}} | Out-GridView -PassThru | Stop-Process```

Now let's say you want to see all network connections. We can follow the same formula and use:

```Get-NetTCPConnection | Out-GridView ```

Now let's say you want to kill a process with a specific connection. We can also similarly enrich that data in the pipe:

```Get-NetTCPConnection | ForEach-Object { Get-Process -Id $_.OwningProcess } | Out-GridView -PassThru | Stop-Process```

Now let's say you want to look for a bind shell/payload which is listening on a port and kill it. We could use `Out-GridView` to sort & filter but we can also do this in PowerShell, and write it a bit cleaner:

```PowerShell
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | 
    ForEach-Object { Get-Process -Id $_.OwningProcess } | 
    Select-Object Id, Name | 
    Out-GridView -PassThru | 
    Stop-Process
```

Now what if you want to do a bit more filtering (like only programs that can actually receive remote network connections) and a bit more enrichment (like displaying the processes command line above). Now in-line enrichment is great, but it can get ugly very fast so here we are constructing our own custom object to hold the exact information we want:

```PowerShell
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
```

We can do similar things with Services:
```Get-Service | Out-GridView -PassThru | Stop-Service```

We can do similar things with Users:
```Get-LocalUser | Out-GridView -PassThru | ForEach-Object { Disable-LocalUser -Name $_.Name }```

We can do similar things with Scheduled Tasks:
```Get-ScheduledTask | Out-GridView -PassThru | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath }```


## Using Group-Object and Sort-Object
`Group-Object` can be useful if you're trying to get a handle on your data. It's good for summarization and anomaly detection For example, if you want to know how many instances of a program is running you can easily get the count like this:

```Get-Process | Group-Object Path | Out-GridView```

`Group-Object` produces an array. Each element is basically a count and the name of the property that was counted. It will also return a list of all the instances of that thing it counted up which is useful when programming but if you're just trying to get a sense of the data you can specify, ```-NoElement``` to not return that list. For example, if you want to quickly know security logs are being recorded, you can list all of the event Id's:

```Get-WinEvent -LogName Security | Group-Object -Property Id -NoElement```

Leveraging early examples, we can see which processes are spawning the most child processes, (it's not uncommon for malware to do this) then we can sort it with `Sort-Object`:
```PowerShell
# Group running processes by parent process
Get-CimInstance -Class Win32_Process |
    Group-Object -Property ParentProcessId |
    ForEach-Object {
        [PSCustomObject]@{
            ParentProcessId = $_.Name
            Count           = $_.Count
            ParentProcess   = (Get-Process -Id $_.Name -ErrorAction SilentlyContinue).Name
        }
    } | Sort-Object Count -Descending | Out-GridView
```

Let's say you want to see which IP addresses have the most connections:
```PowerShell
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } |
    Group-Object -Property RemoteAddress |
    Sort-Object Count -Descending |
    Select-Object Name, Count | Out-GridView
```

And to finish it off we can combine creating a custom object, grouping that object, sorting, and visualizing via `Out-GridView`

```PowerShell
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
```


# Loading and Saving to CSV Files
Many of the commands above are only the basics. There are several utilities (primarily in SysInternals) that do a far better job at dialing into the things we want. For example, this script below can show us many common auto run locations Windows that is heavily used by malware:

```PowerShell
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
```

However there are many more locations that are better covered by SysInternals autorunc.exe (command line version of SysInternals Autoruns.exe). This binary has many GUI fanstastic features but if you are forced to work on the command line, we can use the autorunsc.exe to output the information in CSV format, and we can use PowerShell (and it's cmdlet's such as Out-GridView) to filter for information we want:

```PowerShell
.\autorunsc64.exe -c -nobanner > autorunOutput.csv
import-csv -Path .\autorunOutput.csv | Out-GridView
```

And we can also use `Group-Object` and `Sort-Object` to print most common Persistence locations:
```PowerShell
$data | Group-Object "Entry Location" -NoElement | Sort-Object Count -Descending
```

Now say you want to investigate each entry on this list we can wrap a while true loop while selecting one or more things from the `Out-GridView` at a time. We can do that with the script below (also in `Demo-CSV.ps1`) to pipe my `Out-GridView` selection to a clipboard, and re-launch/re-populate the list without our selection:

```PowerShell
# Config
$inputFilePath = ".\autorunOutput.csv"
$exclusionFilePath = ".\exclude.csv"

class CustomCsvObject {
    CustomCsvObject($csvData) {
        foreach ($property in $csvData.PSObject.Properties) { 
            # Add a property to the class with the same name and value as the CSV column 
            Add-Member -InputObject $this -MemberType NoteProperty -Name $property.Name -Value $property.Value 
        } 
    }

    # Override Equals method to compare all properties
    [bool] Equals([object]$obj) {
        if ($null -eq $obj -or $this.GetType() -ne $obj.GetType()) {
            return $false
        }

        $other = [CustomCsvObject]$obj

        foreach ($property in $this.PSObject.Properties) {
            if ($this.$($property.Name) -ne $other.$($property.Name)) {
                return $false
            }
        }
        return $true
    }

    # Override GetHashCode method to use all properties
    [int] GetHashCode() {
        $hash = 17
        foreach ($property in $this.PSObject.Properties) {
            $hash = $hash * 23 + ($this.$($property.Name)).GetHashCode()
        }
        return $hash
    }
}

# Read in the CSV as an array of objects, turn them into hash tables, then turn them into my custom object, then turn the array into an arraylist 
$data = @()
$data += Import-Csv -Path $inputFilePath | ForEach-Object { 
    [CustomCsvObject]::new($_) 
}
$data = [System.Collections.ArrayList]$data

$exclusions = @()
if(Test-Path $exclusionFilePath){
    $exclusions += Import-Csv -Path $exclusionFilePath | ForEach-Object { 
        [CustomCsvObject]::new($_) 
    }
    $exclusions = [System.Collections.ArrayList]$exclusions

    # Show how to remove from our array list 
    foreach($exclusion in $exclusions){
        $data.Remove($exclusion)
    }
}

# Display to the user
while($data.Count -ne 0){
    $selected = $data | Out-GridView -PassThru -Title "Select one or more to cross off your list"
    $selected | Export-Csv -Append -LiteralPath $exclusionFilePath
    $selected | Set-Clipboard
    Write-Output "Copied to clipboard: $selected"
}
```
