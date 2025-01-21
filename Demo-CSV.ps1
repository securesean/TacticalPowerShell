# This is a PoC for 
# Useful for triaging by leveraging Out-GridView's searching, filtering, ordering and pass-through functionality 
# Also useful for being able to leverage built-in collection functionality that leverages comparison's such as searching, sorting, and removal from collections.
# ToDo: test save-back functionality  

# Custom class to hold data in a hashtable and override Equals method
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

# Config
$inputFilePath = ".\autorunOutput.csv"
$exclusionFilePath = ".\exclude.csv"

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

