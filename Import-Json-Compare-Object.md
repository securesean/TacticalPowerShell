# Compare-Objects
In powershell you can't simply compare arrays and dictionaries with `=` or `-eq` so we use, `Compare-Object`:

```PowerShell
$folders1 = Get-ChildItem -Directory -Path C:\
mkdir -Path C:\newFolder
$folders2 = Get-ChildItem -Directory -Path C:\
Compare-Object $folders1 $folders2
```



# Using Json in PowerShell
Json is a very common data structure and it's useful to know how to use it. For example if we wanted to get the time or IP address.


Json can also contain more structured information than CSV. For Example, Proceess Objects are more complex than a CSV would allow and we can export all of the process objects to JSON with:
`ps | ConvertTo-Json | ConvertFrom-Json`

We can save them to a file and load them like this:
```powershell
ps | ConvertTo-Json | Out-File .\data.json
$data = cat .\data.json | ConvertFrom-Json
```
This can take a little while to export (serializialize) in part because when 
The Process Object being serializialized means that 

We can easily compare (Start a process) and we can see:
```
ps | ConvertTo-Json | Out-File .\baseline.json
$baseline = cat .\data.json | ConvertFrom-Json
$current = ps | ConvertTo-Json | ConvertFrom-Json

Compare-Object -ReferenceObject $baseline -DifferenceObject $current
```

Malware, especailly high interaction C2's such as MSF and cobalt strike will cause new modules (Dll's) to be spradically loaded. We can new modules by comparing on that specific property:
```
Compare-Object -ReferenceObject $baseline -DifferenceObject $current -Property Modules
```

We can polish the script and even add code to alert us when particularly note worthy modules (Dll's) are loaded such as `System.Management.Automation.dll` which malware will load up to execute powershell without executing powershell.exe. Or 

```PowerShell
$baseline = Get-Content $filePath -Raw | ConvertFrom-Json
$current = ps | ConvertTo-Json -Depth 5 | ConvertFrom-Json
while($true){
    $current | foreach {
        $proc = $_
        $baseProc = $baseline | Where-Object { $_.Id -eq $proc.Id }
        if ($baseProc){
            if($baseProc.Modules -ne $null){
                $diff = Compare-Object -ReferenceObject $baseProc.Modules -DifferenceObject $proc.Modules -SyncWindow 0 
                if ($diff){
                    $loadedModules = $diff | Where-Object { $_.SideIndicator -eq "=>"} 
                    if($loadedModules.Count -gt 0){
                        echo "Process $($proc.Name) ($($proc.Id)) loaded new modules:"
                        $loadedModules | ForEach-Object { echo "    $($_.InputObject.FileName)"  }
                    }

                    # Alert on suspicious modules (such as System.Management.Automation.dll for powershell)
                    $suspiciousModules = $diff | Where-Object { $_.SideIndicator -eq "=>" -and $_.InputObject.FileName -match "System.Management.Automation.dll" }
                    if ($suspiciousModules.Count -gt 0){
                        echo "Process $($proc.Name) ($($proc.Id)) loaded suspicious modules:"
                        $suspiciousModules | ForEach-Object { echo "    $($_.InputObject.FileName)"  }
                    }
                }
            }
        } else {
            echo "New Process: $($proc.Name) ($($proc.Id))"
        }
    }
}
```
More can be found in [Demo-Json.ps1](./Demo-Json.ps1)

It would be a good exercise for the reader to checkout https://hijacklibs.net/ and to write a script that hunts for commonly abused/hijacked libraries.


# Event Driven
`Register-ObjectEvent for files suddenly existing in auto start locations. A log event happens. A process just executed cmd.exe/powershell.exe.


