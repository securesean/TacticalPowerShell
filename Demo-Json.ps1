

$filePath = ".\Demo-Json.json"
if(!(Test-Path $filePath)){
    Write-Output "Creating baseline file $($filePath)"
    # Output Json
    Get-Process | ConvertTo-Json -Depth 5 | Out-File $filePath -Force
} else {
    Write-Output "Using existing baseline file $($filePath)"
}

# Import-Json 
$baseline = Get-Content $filePath -Raw | ConvertFrom-Json

while($true){
    Write-Output "Taking new process snapshot and comparing to baseline..."
    $current = Get-Process | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    # Print any new modules
    $current | foreach {
        $proc = $_
        $baseProc = $baseline | Where-Object { $_.Id -eq $proc.Id }
        if ($baseProc){
            if($baseProc.Modules -ne $null){
                $diff = Compare-Object -ReferenceObject $baseProc.Modules -DifferenceObject $proc.Modules -SyncWindow 0 
                if ($diff){
                    $loadedModules = $diff | Where-Object { $_.SideIndicator -eq "=>"} 
                    if($loadedModules.Count -gt 0){
                        Write-Output "Process $($proc.Name) ($($proc.Id)) loaded new modules:"
                        $loadedModules | ForEach-Object { Write-Output "    $($_.InputObject.FileName)"  }
                    }

                    # Alert on suspicious modules (such as System.Management.Automation.dll for powershell)
                    $suspiciousModules = $diff | Where-Object { $_.SideIndicator -eq "=>" -and $_.InputObject.FileName -match "System.Management.Automation.dll|dbghelp.dll|dbgcore.dll|BitsProxy.dll|VBE7.DLL|System.ComponentModel.Composition.ni.dll|wbemdisp.dll|fastprox.dll" }
                    if ($suspiciousModules.Count -gt 0){
                        Write-Output "Process $($proc.Name) ($($proc.Id)) loaded suspicious modules:"
                        $suspiciousModules | ForEach-Object { Write-Output "    $($_.InputObject.FileName)"  }
                    }

                    # Alert on suspicious paths (such as AppData, Temp, or Downloads)
                    $suspiciousPaths = $diff | Where-Object { $_.SideIndicator -eq "=>" -and $_.InputObject.FileName -match "AppData|Temp|Downloads" }
                    if ($suspiciousPaths.Count -gt 0){
                        Write-Output "Process $($proc.Name) ($($proc.Id)) loaded suspicious paths:"
                        $suspiciousPaths | ForEach-Object { Write-Output "    $($_.InputObject.FileName)"  }
                    }

                    # Alert on unsigned modules being loaded into trusted processes
                    $trustedProcesses = @("explorer.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "services.exe", "spoolsv.exe", "dwm.exe", "taskhostw.exe")
                    if ($trustedProcesses -contains $proc.Name){
                        $unsignedModules = $diff | Where-Object { $_.SideIndicator -eq "=>" -and $_.InputObject.Signature -eq $null }
                        if ($unsignedModules.Count -gt 0){
                            Write-Output "Trusted Process $($proc.Name) ($($proc.Id)) loaded unsigned modules:"
                            $unsignedModules | ForEach-Object { Write-Output "    $($_.InputObject.FileName)"  }
                        }
                    }

                    # Alert on modules loaded from network paths
                    $networkModules = $diff | Where-Object { $_.SideIndicator -eq "=>" -and $_.InputObject.FileName -match "^(\\\\|//|[a-zA-Z]:\\{2,})" }
                    if ($networkModules.Count -gt 0){
                        Write-Output "Process $($proc.Name) ($($proc.Id)) loaded network path modules:"
                        $networkModules | ForEach-Object { Write-Output "    $($_.InputObject.FileName)"  }
                    }

                }
            }
        } else {
            Write-Output "New Process: $($proc.Name) ($($proc.Id))"
        }
    }

    $baseline = $current
}

