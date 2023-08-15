**Description**

This PowerShell script allows you to query VirusTotal API for threat intelligence data. Given an input CSV file containing a list of IPs, URLs, or file hashes, the script will contact VirusTotal API and retrieve information about how many security vendors have flagged the input as malicious. The script will then output the results in a CSV file.

**Parameters**
-InputFile (Mandatory): The path to the input CSV file that contains the IPs, URLs, or hashes to be checked. The CSV file should have two columns: "Type" (ip, url, hash) and "Value" (the actual value to be checked).

-OutputFile (Mandatory): The path where the resulting CSV file should be saved. This file will contain columns for the "Value", "Type", and the number of "Vendor Flags" indicating malicious behavior.

# Usage

.\VirusTotalQuery.ps1 -InputFile input.csv -OutputFile results.csv

# Example Input File
```
Type,Value
ip,8.8.8.8
url,http://example.com
hash,44d88612fea8a8f36de82e1278abb02f
```

# Notes
To run this script, you need to replace the $apiKey variable in the script with your actual VirusTotal API key.
