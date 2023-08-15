# VirusTotalQuery.ps1

param (
    [Parameter(Mandatory=$true)]
    [Alias('input')]
    [string]$InputFile,
    
    [Parameter(Mandatory=$true)]
    [Alias('out')]
    [string]$OutputFile
)

# Display ASCII Art Name
$asciiArt = @"
...................
.+===============*.
...:=*..........**.
.....:=*........**.
.......:=*......**.
.......+=+......**.
.....+=:........**.
...*=:..........**.
.+****************.                                                      
"@
Write-Host $asciiArt

# Your VirusTotal API Key
$apiKey = '<Your VirusTotal API Key>'

# Read the CSV file
$items = Import-Csv -Path $InputFile

# Array to store the results
$results = @()

# Process each item in the CSV
foreach ($item in $items) {
    $type = $item.Type.ToLower()
    $value = $item.Value.Trim()

    Write-Host "Processing $type : $value ..."
    
    $headers = @{
        'accept' = 'application/json'
        'x-apikey' = $apiKey
    }

    # Determine the endpoint URL based on the item type
    switch ($type) {
        'ip' {
            $url = "https://www.virustotal.com/api/v3/ip_addresses/$value"
        }
        'url' {
            $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))
            $urlSafeBase64 = $base64 -replace '\+', '-' -replace '/', '_' -replace '='
            $url = "https://www.virustotal.com/api/v3/urls/$urlSafeBase64"
        }
        'hash' {
            $url = "https://www.virustotal.com/api/v3/files/$value"
        }
        default {
            Write-Warning "Unknown type: $type"
            continue
        }
    }

    # Send request to VirusTotal API
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    }
    catch {
        Write-Warning "Resource not found for $type : $value"
        continue
    }

    # Create a custom object for the result
    # Arranging properties in the desired order: Value, Type, Vendor Flags
    $result = [PSCustomObject]@{
        "Value"        = $value
        "Type"         = $type
        "Vendor Flags" = 0
    }

    # Check and set the number of security vendors that flagged this as malicious
    if ($response -ne $null -and $response.data.attributes.last_analysis_stats -ne $null) {
        $maliciousCount = $response.data.attributes.last_analysis_stats.malicious
        $result."Vendor Flags" = $maliciousCount
    }
    else {
        Write-Host "No information found for this query."
    }

    # Add the result to the results array
    $results += $result
}

# Export the results to a CSV file
$results | Export-Csv -Path $OutputFile -NoTypeInformation

# Inform the user of completion and where the results have been saved
Write-Host "Processing completed. Results saved to $OutputFile"

# Output the results to the console
$results | Format-Table -AutoSize

   
