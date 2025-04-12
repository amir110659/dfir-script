
function Analyze-MRURegistry {
   $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = Join-Path $PWD "MRU_Registry_Analysis_$timestamp.txt"

Start-Transcript -Path $outputFile -Force

function Format-ByteArrayAsHex {
    param([byte[]]$Bytes, $Width = 16)
    
    for($i = 0; $i -lt $Bytes.Length; $i += $Width) {
        $line = $Bytes[$i..([Math]::Min($i + $Width - 1, $Bytes.Length - 1))]
        $hex = ($line | ForEach-Object { $_.ToString('X2') }) -join ' '
        $ascii = ($line | ForEach-Object { if ($_ -ge 0x20 -and $_ -le 0x7E) { [char]$_ } else { '.' } }) -join ''
        
        '{0:X8}: {1,-48} {2}' -f $i, $hex, $ascii
    }
}

function Analyze-RegistryValue {
    param($Value)
    
    if ($Value -is [byte[]]) {
        Write-Host "As Hex dump:"
        Format-ByteArrayAsHex $Value
        
        Write-Host "`nAs Unicode string:"
        try { Write-Host ([System.Text.Encoding]::Unicode.GetString($Value)) } catch { Write-Host "Failed to decode as Unicode" }
        
        Write-Host "`nAs ASCII string:"
        try { Write-Host ([System.Text.Encoding]::ASCII.GetString($Value)) } catch { Write-Host "Failed to decode as ASCII" }
        
        if ($Value.Length -ge 2 -and $Value[0] -eq 0x3A -and $Value[1] -eq 0x00) {
            Write-Host "`nLooks like a PIDL structure. Analyzing..."
            $offset = 2
            while ($offset -lt $Value.Length) {
                $itemSize = [BitConverter]::ToUInt16($Value, $offset)
                if ($itemSize -eq 0) { break }
                
                Write-Host "ItemID at offset $offset, size: $itemSize bytes"
                $itemData = $Value[($offset + 2)..($offset + $itemSize - 1)]
                Format-ByteArrayAsHex $itemData
                
                $offset += $itemSize
            }
        }
    }
    else {
        Write-Host "Value: $Value"
    }
}

Write-Host "=== Registry MRU Analysis ===" -ForegroundColor Cyan
Write-Host "Analysis started at: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Output saved to: $outputFile`n" -ForegroundColor Cyan

# Test the registry paths
$paths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\ps1",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\sln"
)

foreach ($path in $paths) {
    Write-Host "`n=== Analyzing $path ===`n" -ForegroundColor Cyan
    
    $values = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    if ($values) {
        $values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Host "Value Name: $($_.Name)" -ForegroundColor Yellow
            Analyze-RegistryValue $_.Value
            Write-Host "`n---`n"
        }
    }
}

Stop-Transcript
}


function Invoke-ShellBagHunter {
#requires -version 5.1

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "ShellBagHunter",
    
    [Parameter(Mandatory=$false)]
    [switch]$ProcessAllUsers,
    
    [Parameter(Mandatory=$false)]
    [string]$UserSID,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDeleted,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML", "CSV", "JSON", "ALL")]
    [string]$OutputFormat = "ALL",
    
    [Parameter(Mandatory=$false)]
    [string]$FilterPath,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 0,
    
    [Parameter(Mandatory=$false)]
    [DateTime]$StartDate,
    
    [Parameter(Mandatory=$false)]
    [DateTime]$EndDate
)

<#
.SYNOPSIS
    Extracts and analyzes Windows ShellBag data from the registry.

.DESCRIPTION
    This script extracts and analyzes Windows ShellBag data from the registry
    to identify folder access history, including evidence of deleted folder access.
    It can generate detailed reports in HTML, CSV, and JSON formats.

    Use PowerShell's standard -Verbose parameter to get detailed diagnostic information
    about the script's execution, including which registry paths are being checked,
    how many items are found, and other useful troubleshooting information.

.PARAMETER OutputPath
    The base path/filename to use for output files. Default is "ShellBagHunter".

.PARAMETER ProcessAllUsers
    If specified, attempts to analyze ShellBag data for all user profiles.

.PARAMETER UserSID
    If specified, only analyzes ShellBag data for the specified user SID. Default is current user.

.PARAMETER IncludeDeleted
    If specified, the script will attempt to identify and highlight evidence of deleted folder access.

.PARAMETER OutputFormat
    The format to export results. Accepts: HTML, CSV, JSON, or ALL. Default is ALL.

.PARAMETER FilterPath
    If specified, only includes ShellBag entries containing this path substring.

.PARAMETER DaysBack
    If specified, only shows ShellBag entries from the last N days. Default is 0 (show all).

.PARAMETER StartDate
    If specified, only shows ShellBag entries from this date onwards.

.PARAMETER EndDate
    If specified, only shows ShellBag entries until this date.

.NOTES
    File Name      : shellBagHunter.ps1
    Prerequisite   : PowerShell 5.1 or later
    Author         : The Haag
    
.EXAMPLE
    .\shellBagHunter.ps1 -OutputFormat HTML
    Analyzes ShellBag data and generates only an HTML report.

.EXAMPLE
    .\shellBagHunter.ps1 -IncludeDeleted -Verbose
    Analyzes ShellBag data with detailed diagnostic output, including evidence of deleted folders.

.EXAMPLE
    .\shellBagHunter.ps1 -DaysBack 7
    Shows only ShellBag entries from the last 7 days and generates all report formats.

.EXAMPLE
    .\shellBagHunter.ps1 -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)
    Shows only ShellBag entries from the last 30 days.

.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>

$AsciiArt = @"
    +-+-+-+-+-+-+-+-+-+ 
    |S|h|e|l|l|B|a|g|s| 
    +-+-+-+-+-+-+-+-+-+ 
                                                                           
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |P|o|w|e|r|S|h|e|l|l| |H|U|N|T|E|R|
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+

        [ Hunt smarter, Hunt harder ]
"@

Write-Host $AsciiArt -ForegroundColor Cyan
Write-Host "`nShellBag Analysis Tool" -ForegroundColor Green
Write-Host "----------------------`n" -ForegroundColor DarkGray

Write-Verbose "Setting up registry PSDrives..."
if (-not (Get-PSDrive -Name HKCU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKCU -PSProvider Registry -Root HKEY_CURRENT_USER | Out-Null
}

if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

$possibleRegistryPaths = @(
    @{
        BagMRU = "HKCU:\Software\Microsoft\Windows\Shell\BagMRU"
        Bags = "HKCU:\Software\Microsoft\Windows\Shell\Bags"
    },
    @{
        BagMRU = "HKCU:\Software\Microsoft\Windows\ShellNoRoam\BagMRU"
        Bags = "HKCU:\Software\Microsoft\Windows\ShellNoRoam\Bags"
    },
    @{
        BagMRU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        Bags = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
    },
    @{
        BagMRU = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
        Bags = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
    },
    @{
        BagMRU = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
        Bags = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
    },
    @{
        BagMRU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        Bags = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    },
    @{
        BagMRU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        Bags = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    }
)

if ($UserSID) {
    Write-Host "Analyzing ShellBag data for user SID: $UserSID" -ForegroundColor Yellow
    
    if (-not (Test-Path "HKU:\$UserSID")) {
        Write-Warning "User profile not loaded. Attempting to load user registry hive..."
        
        $ProfileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID" -ErrorAction SilentlyContinue
        if ($ProfileList -and $ProfileList.ProfileImagePath) {
            $NTUserDatPath = Join-Path $ProfileList.ProfileImagePath "NTUSER.DAT"
            if (Test-Path $NTUserDatPath) {
                reg load "HKU\$UserSID" $NTUserDatPath
                Write-Host "Successfully loaded user registry hive." -ForegroundColor Green
                
                for ($i = 0; $i -lt $possibleRegistryPaths.Count; $i++) {
                    $possibleRegistryPaths[$i].BagMRU = $possibleRegistryPaths[$i].BagMRU -replace "HKCU:", "HKU:\$UserSID"
                    $possibleRegistryPaths[$i].Bags = $possibleRegistryPaths[$i].Bags -replace "HKCU:", "HKU:\$UserSID"
                }
            } else {
                Write-Error "Could not find NTUSER.DAT for SID $UserSID."
                exit
            }
        } else {
            Write-Error "Could not find profile information for SID $UserSID."
            exit
        }
    } else {
        for ($i = 0; $i -lt $possibleRegistryPaths.Count; $i++) {
            $possibleRegistryPaths[$i].BagMRU = $possibleRegistryPaths[$i].BagMRU -replace "HKCU:", "HKU:\$UserSID"
            $possibleRegistryPaths[$i].Bags = $possibleRegistryPaths[$i].Bags -replace "HKCU:", "HKU:\$UserSID"
        }
    }
}

if (-not $UserSID) {
    if ($ProcessAllUsers) {
        $userProfiles = Get-ChildItem "HKU:\" -ErrorAction SilentlyContinue | 
                        Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' }
        
        if ($userProfiles) {
            Write-Verbose "Found $($userProfiles.Count) user profiles to check"
            
            foreach ($profile in $userProfiles) {
                $sid = $profile.PSChildName
                Write-Verbose "Adding paths for user SID: $sid"
                
                $possibleRegistryPaths += @{
                    BagMRU = "HKU:\$sid\Software\Microsoft\Windows\Shell\BagMRU"
                    Bags = "HKU:\$sid\Software\Microsoft\Windows\Shell\Bags"
                }
                
                $possibleRegistryPaths += @{
                    BagMRU = "HKU:\$sid\Software\Microsoft\Windows\ShellNoRoam\BagMRU"
                    Bags = "HKU:\$sid\Software\Microsoft\Windows\ShellNoRoam\Bags"
                }
            }
        } else {
            Write-Verbose "No additional user profiles found in the registry"
        }
    } else {
        Write-Verbose "ProcessAllUsers not specified, only analyzing current user"
    }
}

function Convert-FileTime {
    param ([byte[]]$Bytes)
    if ($Bytes.Length -ge 8) {
        try {
            $FileTime = [System.BitConverter]::ToInt64($Bytes, 0)
            return [System.DateTime]::FromFileTime($FileTime)
        } catch {
            return $null
        }
    }
    return $null
}
function Extract-Text {
    param ([byte[]]$Bytes)
    
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return ""
    }
    
    $Text = ""
    $AsciiStartIndex = -1
    $AsciiLength = 0
    
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        if ($Bytes[$i] -ge 32 -and $Bytes[$i] -le 126) {
            if ($AsciiStartIndex -eq -1) {
                $AsciiStartIndex = $i
            }
            $AsciiLength++
        } elseif ($Bytes[$i] -eq 0 -and $AsciiStartIndex -ne -1 -and $AsciiLength -gt 2) {
            $Text = [System.Text.Encoding]::ASCII.GetString($Bytes, $AsciiStartIndex, $AsciiLength)
            break
        } else {
            $AsciiStartIndex = -1
            $AsciiLength = 0
        }
    }
    
    if ([string]::IsNullOrEmpty($Text) -and $Bytes.Length -gt 2) {
        try {
            $IsUnicode = $true
            for ($i = 0; $i -lt [Math]::Min(10, $Bytes.Length); $i += 2) {
                if ($i + 1 -lt $Bytes.Length -and $Bytes[$i + 1] -ne 0) {
                    $IsUnicode = $false
                    break
                }
            }
            
            if ($IsUnicode) {
                $Text = [System.Text.Encoding]::Unicode.GetString($Bytes).TrimEnd("`0")
            }
        } catch {
        }
    }
    
    return $Text
}

function Test-DeletedPath {
    param ([string]$Path)
    
    if ([string]::IsNullOrEmpty($Path)) {
        return $false
    }
    
    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) {
        if ($Path -match "^[A-Za-z]:\\|^\\\\|^[A-Za-z]:") {
            return $true
        }
    }
    
    return $false
}

function Get-ShellBagMRU {
    param (
        $Path, 
        $BagsPath,
        $Level = 0, 
        $ParentPath = "",
        [switch]$IncludeDeleted,
        [int]$DaysBack = 0
    )
    
    $Results = @()
    $CutoffDate = $null
    
    if ($DaysBack -gt 0) {
        $CutoffDate = (Get-Date).AddDays(-$DaysBack)
    }
    
    if (-not (Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
        Write-Verbose "Path not found: $Path"
        return @()
    }
    
    Write-Verbose "Examining: $Path"
    $Items = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
    
    if (-not $Items -or $Items.Count -eq 0) {
        Write-Verbose "No items found at: $Path"
        return @()
    }
    
    Write-Verbose "Found $($Items.Count) items at: $Path"
    
    foreach ($Item in $Items) {
        $Props = Get-ItemProperty -Path $Item.PSPath -ErrorAction SilentlyContinue
        
        if ($Props.PSObject.Properties.Name -contains "MRUListEx") {
            Write-Verbose "Found MRUListEx in: $($Item.PSPath)"
            $NodeSlot = $null
            $LastModified = $null
            
            if ($Props.PSObject.Properties.Name -contains "NodeSlot") {
                $NodeSlot = $Props.NodeSlot
                Write-Verbose "Found NodeSlot: $NodeSlot"
                
                $BagPath = "$BagsPath\$NodeSlot"
                if (Test-Path $BagPath) {
                    Write-Verbose "Found corresponding Bag entry: $BagPath"
                    $BagProps = Get-ItemProperty -Path $BagPath -ErrorAction SilentlyContinue
                    
                    if ($BagProps.PSObject.Properties.Name -contains "LastWriteTime") {
                        $LastModified = Convert-FileTime -Bytes $BagProps.LastWriteTime
                        Write-Verbose "Extracted LastModified time: $LastModified"
                    }
                } else {
                    Write-Verbose "No corresponding Bag entry found at: $BagPath"
                }
            }
            
            if ($CutoffDate -and $LastModified -and $LastModified -lt $CutoffDate) {
                Write-Verbose "Skipping item older than cutoff date: $LastModified < $CutoffDate"
                continue
            }
            
            foreach ($Prop in $Props.PSObject.Properties) {
                if ($Prop.Name -match "^Item\d+$") {
                    Write-Verbose "Processing $($Prop.Name)"
                    $BinData = $Prop.Value
                    
                    if ($BinData -is [byte[]]) {
                        $PathName = Extract-Text -Bytes $BinData
                        
                        if (-not [string]::IsNullOrEmpty($PathName)) {
                            Write-Verbose "Extracted path: $PathName"
                            
                            $FullPath = if ([string]::IsNullOrEmpty($ParentPath)) { $PathName } else { Join-Path $ParentPath $PathName }
                            
                            $MightBeDeleted = Test-DeletedPath -Path $FullPath
                            
                            if (-not $IncludeDeleted -and $MightBeDeleted) {
                                Write-Verbose "Skipping deleted path: $FullPath"
                                continue
                            }
                            
                            $Result = [PSCustomObject]@{
                                Level        = $Level
                                NodeSlot     = $NodeSlot
                                LastModified = $LastModified
                                KeyPath      = $Item.PSPath -replace "Microsoft\.PowerShell\.Core\\Registry::", ""
                                ItemName     = $Prop.Name
                                FullPath     = $FullPath
                                PathName     = $PathName
                                IsDeleted    = $MightBeDeleted
                            }
                            
                            $Results += $Result
                            
                            $FolderStatus = if ($MightBeDeleted) { "[DELETED]" } else { "[FOLDER]" }
                            Write-Host (" " * ($Level * 4) + "$FolderStatus $PathName") -ForegroundColor $(if ($MightBeDeleted) { "Red" } else { "Yellow" })
                        } else {
                            Write-Verbose "Could not extract path from binary data in $($Prop.Name)"
                        }
                    } else {
                        Write-Verbose "$($Prop.Name) is not a byte array, skipping"
                    }
                }
            }
            
            Write-Verbose "Recursively processing: $Path\$($Item.PSChildName)"
            $SubResults = Get-ShellBagMRU -Path "$Path\$($Item.PSChildName)" -BagsPath $BagsPath -Level ($Level + 1) -ParentPath $FullPath -IncludeDeleted:$IncludeDeleted -DaysBack $DaysBack
            $Results += $SubResults
        } else {
            Write-Verbose "No MRUListEx property in: $($Item.PSPath)"
        }
    }
    
    return $Results
}

function Create-HtmlReport {
    param(
        [array]$ShellBagData,
        [string]$HtmlPath,
        [switch]$IsServerOS
    )
    
    $Css = @"
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #0078D7;
        }
        h1 {
            text-align: center;
            padding-bottom: 10px;
            border-bottom: 2px solid #0078D7;
            margin-bottom: 30px;
        }
        .section {
            margin-bottom: 30px;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
            border-left: 5px solid #0078D7;
        }
        .deleted-section {
            border-left: 5px solid #D70000;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th {
            background-color: #0078D7;
            color: white;
            padding: 12px;
            text-align: left;
        }
        .deleted-table th {
            background-color: #D70000;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #e6f3ff;
        }
        .deleted-row {
            background-color: #ffe6e6 !important;
        }
        .deleted-row:hover {
            background-color: #ffcccc !important;
        }
        .summary {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .stat-box {
            flex: 1;
            min-width: 200px;
            margin: 10px;
            padding: 15px;
            background-color: #e6f3ff;
            border-radius: 5px;
            text-align: center;
            box-shadow: 0 0 5px rgba(0,0,0,0.05);
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #0078D7;
        }
        .deleted-stat {
            background-color: #ffe6e6;
        }
        .deleted-value {
            color: #D70000;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #777;
        }
        .path-column {
            max-width: 400px;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        .chart-container {
            width: 100%;
            height: 400px;
            margin: 20px 0;
        }
        .chart-fallback {
            width: 100%;
            height: 100px;
            margin: 20px 0;
            background-color: #f9f9f9;
            border: 1px dashed #ccc;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #666;
        }
        .tree {
            margin: 20px 0;
        }
        .tree-item {
            margin: 5px 0;
            padding: 3px 0;
        }
        .tree-folder {
            font-weight: bold;
        }
        .tree-deleted {
            color: #D70000;
            text-decoration: line-through;
        }
        .note {
            background-color: #fffde7;
            padding: 10px;
            border-left: 5px solid #fbc02d;
            margin: 15px 0;
        }
    </style>
"@

    $ChartJs = @"
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    // Fallback for Chart.js
    window.addEventListener('load', function() {
        if (typeof Chart === 'undefined') {
            console.error('Chart.js failed to load');
            document.querySelectorAll('.chart-container').forEach(function(container) {
                container.innerHTML = '<div class="chart-fallback">Chart library could not be loaded. Please check your internet connection or try a different browser.</div>';
            });
        }
    });
    </script>
"@

    $totalEntries = $ShellBagData.Count
    $lastDay = ($ShellBagData | Where-Object { $_.LastModified -gt (Get-Date).AddDays(-1) }).Count
    $last7Days = ($ShellBagData | Where-Object { $_.LastModified -gt (Get-Date).AddDays(-7) }).Count
    $deletedCount = ($ShellBagData | Where-Object { $_.IsDeleted }).Count
    
    $pathsByLevel = $ShellBagData | Group-Object -Property Level
    
    $recentEntries = $ShellBagData | Where-Object { $_.LastModified -gt (Get-Date).AddDays(-7) } | Sort-Object -Property LastModified -Descending
    
    $deletedEntries = $ShellBagData | Where-Object { $_.IsDeleted } | Sort-Object -Property LastModified -Descending
    
    $serverNote = if ($IsServerOS) {
        @"
        <div class="note">
            <strong>Note:</strong> This analysis was performed on a Windows Server environment. 
            ShellBag artifacts may be limited compared to desktop Windows environments.
            Users access the server through protocols like RDP, which may not generate the same ShellBag records as a full desktop session.
        </div>
"@
    } else {
        ""
    }
    
    $HtmlContent = @"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ShellBag Analysis Report - $(Get-Date -Format 'yyyyMMdd_HHmmss')</title>
        $Css
        $ChartJs
    </head>
    <body>
        <div class="container">
            <h1>Windows ShellBag Analysis Report</h1>
            <p>Report generated on $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')</p>
            $serverNote
            
            <div class="summary">
                <div class="stat-box">
                    <div>Total ShellBag Entries</div>
                    <div class="stat-value">$totalEntries</div>
                </div>
                <div class="stat-box">
                    <div>Accessed in Last 24h</div>
                    <div class="stat-value">$lastDay</div>
                </div>
                <div class="stat-box">
                    <div>Accessed in Last 7d</div>
                    <div class="stat-value">$last7Days</div>
                </div>
                <div class="stat-box deleted-stat">
                    <div>Potentially Deleted Folders</div>
                    <div class="stat-value deleted-value">$deletedCount</div>
                </div>
            </div>
"@

    if ($recentEntries.Count -gt 0) {
        $recentTable = "<table><thead><tr><th>Path</th><th>Last Modified</th><th>Status</th></tr></thead><tbody>"
        
        foreach ($item in $recentEntries) {
            $trClass = if ($item.IsDeleted) { "deleted-row" } else { "" }
            $status = if ($item.IsDeleted) { "Deleted" } else { "Exists" }
            
            $recentTable += "<tr class='$trClass'>
                <td class='path-column'>$($item.FullPath)</td>
                <td>$($item.LastModified)</td>
                <td>$status</td>
            </tr>"
        }
        
        $recentTable += "</tbody></table>"
        
        $HtmlContent += @"
            <div class="section">
                <h2>Recent Folder Activity (Last 7 Days)</h2>
                <p>The following $($recentEntries.Count) folders were accessed in the last 7 days:</p>
                $recentTable
            </div>
"@
    } else {
        $HtmlContent += @"
            <div class="section">
                <h2>Recent Folder Activity (Last 7 Days)</h2>
                <p>No folders were accessed in the last 7 days.</p>
                $(if ($IsServerOS) { "<p>Note: Limited ShellBag data may be expected in server environments.</p>" } else { "" })
            </div>
"@
    }

    if ($deletedEntries.Count -gt 0) {
        $deletedTable = "<table class='deleted-table'><thead><tr><th>Path</th><th>Last Modified</th><th>Registry Key</th></tr></thead><tbody>"
        
        foreach ($item in $deletedEntries) {
            $deletedTable += "<tr>
                <td class='path-column'>$($item.FullPath)</td>
                <td>$($item.LastModified)</td>
                <td>$($item.KeyPath)</td>
            </tr>"
        }
        
        $deletedTable += "</tbody></table>"
        
        $HtmlContent += @"
            <div class="section deleted-section">
                <h2>Potentially Deleted Folders</h2>
                <p>The following $($deletedEntries.Count) folders appear to be deleted but were previously accessed:</p>
                $deletedTable
            </div>
"@
    }

    $treeHtml = "<div class='tree'>"
    foreach ($level in ($pathsByLevel | Sort-Object -Property Name)) {
        foreach ($item in $level.Group) {
            $indent = "&nbsp;&nbsp;" * $item.Level
            $folderIconText = if ($item.IsDeleted) { "[DELETED]" } else { "[FOLDER]" }
            $itemClass = if ($item.IsDeleted) { "tree-item tree-folder tree-deleted" } else { "tree-item tree-folder" }
            
            $treeHtml += "<div class='$itemClass'>$indent$folderIconText $($item.PathName)</div>"
        }
    }
    $treeHtml += "</div>"
    
    $HtmlContent += @"
            <div class="section">
                <h2>Folder Hierarchy</h2>
                <p>Visual representation of the folder structure:</p>
                $treeHtml
            </div>
"@

    if ($ShellBagData.Count -gt 0) {
        $allTable = "<table><thead><tr><th>Path</th><th>Last Modified</th><th>Status</th><th>Registry Key</th></tr></thead><tbody>"
        
        foreach ($item in ($ShellBagData | Sort-Object -Property LastModified -Descending)) {
            $trClass = if ($item.IsDeleted) { "deleted-row" } else { "" }
            $status = if ($item.IsDeleted) { "Deleted" } else { "Exists" }
            
            $allTable += "<tr class='$trClass'>
                <td class='path-column'>$($item.FullPath)</td>
                <td>$($item.LastModified)</td>
                <td>$status</td>
                <td>$($item.KeyPath)</td>
            </tr>"
        }
        
        $allTable += "</tbody></table>"
        
        $HtmlContent += @"
            <div class="section">
                <h2>All ShellBag Entries</h2>
                <p>Total of $($ShellBagData.Count) ShellBag entries found:</p>
                $allTable
            </div>
"@
    } else {
        $HtmlContent += @"
            <div class="section">
                <h2>All ShellBag Entries</h2>
                <p>No ShellBag entries were found.</p>
                $(if ($IsServerOS) { 
                    "<p>This is common in Windows Server environments where file explorer activity is limited.</p>
                    <p>Consider checking:</p>
                    <ul>
                        <li>User remote desktop sessions</li>
                        <li>File sharing access logs</li>
                        <li>Event logs for file access</li>
                    </ul>"
                } else {
                    "<p>This might be because:</p>
                    <ul>
                        <li>The registry paths don't exist on this system</li>
                        <li>There are no ShellBag entries for the current user</li>
                        <li>The script is not running with Administrator privileges</li>
                    </ul>"
                })
            </div>
"@
    }
    
    $HtmlContent += @"
            <div class="footer">
                <p>Generated by ShellBag Hunter - PowerShell Hunter Toolkit</p>
                <p>https://github.com/MHaggis/PowerShell-Hunter</p>
            </div>
        </div>
    </body>
    </html>
"@

    $HtmlContent | Out-File -FilePath $HtmlPath
}

function Export-ResultsToFormats {
    param(
        [array]$ShellBagData,
        [string]$OutputPath,
        [string]$OutputFormat,
        [bool]$IsServerOS = $false
    )
    
    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $ExportBaseName = if ([string]::IsNullOrEmpty($OutputPath)) {
        "ShellBagHunter_$($Timestamp)"
    } else {
        "$($OutputPath)_$($Timestamp)"
    }
    
    $HtmlPath = "$ExportBaseName.html"
    
    if ($ShellBagData) {
        if ($OutputFormat -eq "CSV" -or $OutputFormat -eq "ALL") {
            $CSVPath = "$ExportBaseName.csv"
            $ShellBagData | Export-Csv -Path $CSVPath -NoTypeInformation
            Write-Host "`nData exported to CSV: $CSVPath" -ForegroundColor Green
        }
        
        if ($OutputFormat -eq "JSON" -or $OutputFormat -eq "ALL") {
            $JSONPath = "$ExportBaseName.json"
            $ShellBagData | ConvertTo-Json -Depth 4 | Out-File $JSONPath
            Write-Host "Data exported to JSON: $JSONPath" -ForegroundColor Green
        }
        
        if ($OutputFormat -eq "HTML" -or $OutputFormat -eq "ALL") {
            Create-HtmlReport -ShellBagData $ShellBagData -HtmlPath $HtmlPath -IsServerOS:$IsServerOS
            Write-Host "HTML report generated: $HtmlPath" -ForegroundColor Green
            
            return $HtmlPath
        }
    } else {
        Write-Host "No data to export." -ForegroundColor Yellow
        return $null
    }
}

function Get-QuickAccessHistory {
    param(
        [switch]$IncludeDeleted,
        [int]$DaysBack = 0
    )
    
    Write-Verbose "Checking Quick Access and Recent Files history as alternative data source"
    $Results = @()
    $CutoffDate = $null
    
    if ($DaysBack -gt 0) {
        $CutoffDate = (Get-Date).AddDays(-$DaysBack)
    }
    
    try {
        Write-Verbose "Getting Quick Access items from shell COM object"
        
        $shell = New-Object -ComObject Shell.Application
        $quickAccess = $shell.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}")
        if ($quickAccess -ne $null) {
            foreach ($item in $quickAccess.Items()) {
                if ($item -ne $null) {
                    try {
                        $path = $item.Path
                        $lastModified = $null
                        
                        if ($item.ModifyDate) {
                            $lastModified = $item.ModifyDate
                        } elseif ($item.ExtendedProperty("System.DateModified")) {
                            $lastModified = $item.ExtendedProperty("System.DateModified")
                        }
                        
                        if ($CutoffDate -and $lastModified -and $lastModified -lt $CutoffDate) {
                            continue
                        }
                        
                        $mightBeDeleted = Test-DeletedPath -Path $path
                        
                        if (-not $IncludeDeleted -and $mightBeDeleted) {
                            continue
                        }
                        
                        $Result = [PSCustomObject]@{
                            Level        = 0
                            NodeSlot     = "QuickAccess"
                            LastModified = $lastModified
                            KeyPath      = "Quick Access - Windows 11"
                            ItemName     = "QuickAccessItem"
                            FullPath     = $path
                            PathName     = Split-Path $path -Leaf
                            IsDeleted    = $mightBeDeleted
                        }
                        
                        $Results += $Result
                        
                        $FolderStatus = if ($mightBeDeleted) { "[DELETED]" } else { "[FOLDER]" }
                        Write-Host "$FolderStatus $path" -ForegroundColor $(if ($mightBeDeleted) { "Red" } else { "Yellow" })
                    } catch {
                        Write-Verbose "Error processing Quick Access item: $_"
                        Write-Warning "Could not process a Quick Access item: $($_.Exception.Message)"
                    }
                }
            }
        } else {
            Write-Warning "Could not access Quick Access namespace. This might be expected on Windows Server."
        }
    } catch {
        Write-Verbose "Error accessing Quick Access: $_"
        Write-Warning "Could not access Quick Access namespace: $($_.Exception.Message)"
        
        $isServerOS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -ne 1
        if ($isServerOS) {
            Write-Host "Note: Quick Access is not typically available on Windows Server editions." -ForegroundColor Yellow
        }
    }
    
    try {
        Write-Verbose "Getting Recent Items from the Start Menu"
        $recentFolder = [System.Environment]::GetFolderPath('Recent')
        
        if (Test-Path $recentFolder) {
            $recentItems = Get-ChildItem -Path $recentFolder -File | Where-Object { $_.Extension -eq ".lnk" }
            
            if ($recentItems.Count -eq 0) {
                Write-Host "No recent items found in $recentFolder" -ForegroundColor Yellow
            }
            
            foreach ($item in $recentItems) {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($item.FullName)
                    $path = $shortcut.TargetPath
                    
                    if ([string]::IsNullOrEmpty($path)) {
                        Write-Verbose "Skipping shortcut with empty target path: $($item.Name)"
                        continue
                    }
                    
                    if ($CutoffDate -and $item.LastWriteTime -and $item.LastWriteTime -lt $CutoffDate) {
                        continue
                    }
                    
                    $mightBeDeleted = Test-DeletedPath -Path $path
                    
                    if (-not $IncludeDeleted -and $mightBeDeleted) {
                        continue
                    }
                    
                    $Result = [PSCustomObject]@{
                        Level        = 0
                        NodeSlot     = "RecentItems"
                        LastModified = $item.LastWriteTime
                        KeyPath      = "Recent Items - Windows 11"
                        ItemName     = $item.Name
                        FullPath     = $path
                        PathName     = Split-Path $path -Leaf
                        IsDeleted    = $mightBeDeleted
                    }
                    
                    $Results += $Result
                    
                    $FolderStatus = if ($mightBeDeleted) { "[DELETED]" } else { "[FOLDER]" }
                    Write-Host "$FolderStatus $path" -ForegroundColor $(if ($mightBeDeleted) { "Red" } else { "Yellow" })
                } catch {
                    Write-Verbose "Error processing Recent Item $($item.Name): $_"
                    Write-Warning "Could not process recent item '$($item.Name)': $($_.Exception.Message)"
                }
            }
        } else {
            Write-Warning "Recent Items folder not found at: $recentFolder"
        }
    } catch {
        Write-Verbose "Error accessing Recent Items: $_"
        Write-Warning "Could not access Recent Items: $($_.Exception.Message)"
    }
    
    return $Results
}

try {
    Write-Host "Scanning ShellBag registry keys..." -ForegroundColor Blue
    
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osName = $osInfo.Caption
    $osVersion = $osInfo.Version
    $isServerOS = $osInfo.ProductType -ne 1
    
    Write-Host "Detected OS: $osName ($osVersion)" -ForegroundColor Yellow
    
    if ($isServerOS) {
        Write-Host "Windows Server detected - ShellBag artifacts may be limited on server environments" -ForegroundColor Yellow
        Write-Host "Note: Desktop features like Quick Access may not be available" -ForegroundColor Yellow
    } elseif ($osName -like "*Windows 11*") {
        Write-Host "Windows 11 detected - will check additional registry locations" -ForegroundColor Yellow
        Write-Host "Note: Windows 11 may require a restart for all ShellBag data to be committed to registry" -ForegroundColor Yellow
    }
    
    $allResults = @()
    $pathsChecked = 0
    $pathsWithData = 0
    
    foreach ($pathSet in $possibleRegistryPaths) {
        $BagMRUPath = $pathSet.BagMRU
        $BagsPath = $pathSet.Bags
        
        $pathsChecked++
        Write-Verbose "`nChecking path set #${pathsChecked}"
        Write-Verbose "BagMRU: $BagMRUPath"
        Write-Verbose "Bags: $BagsPath"
        
        if (Test-Path -Path $BagMRUPath -ErrorAction SilentlyContinue) {
            Write-Verbose "BagMRU path exists, attempting to extract data..."
            
            $shellBagData = Get-ShellBagMRU -Path $BagMRUPath -BagsPath $BagsPath -IncludeDeleted:$IncludeDeleted -DaysBack $DaysBack
            
            if ($shellBagData -and $shellBagData.Count -gt 0) {
                Write-Verbose "Found $($shellBagData.Count) ShellBag entries at: $BagMRUPath"
                $allResults += $shellBagData
                $pathsWithData++
            } else {
                Write-Verbose "No ShellBag data found at: $BagMRUPath"
            }
        } else {
            Write-Verbose "BagMRU path does not exist: $BagMRUPath"
        }
    }
    
    if ($StartDate -or $EndDate) {
        Write-Host "Applying date filtering..." -ForegroundColor Yellow
        
        $filteredResults = $allResults
        
        if ($StartDate) {
            $filteredResults = $filteredResults | Where-Object { -not $_.LastModified -or $_.LastModified -ge $StartDate }
            Write-Host "Filtered to entries on or after: $($StartDate.ToString('yyyy-MM-dd'))" -ForegroundColor Yellow
        }
        
        if ($EndDate) {
            $filteredResults = $filteredResults | Where-Object { -not $_.LastModified -or $_.LastModified -le $EndDate }
            Write-Host "Filtered to entries on or before: $($EndDate.ToString('yyyy-MM-dd'))" -ForegroundColor Yellow
        }
        
        Write-Host "Date filtering complete. $($filteredResults.Count) entries remain." -ForegroundColor Yellow
        $allResults = $filteredResults
    }
    
    if (-not [string]::IsNullOrEmpty($FilterPath)) {
        Write-Host "Applying path filtering..." -ForegroundColor Yellow
        $preFilterCount = $allResults.Count
        
        $allResults = $allResults | Where-Object { $_.FullPath -like "*$FilterPath*" }
        
        Write-Host "Filtered to paths containing: $FilterPath" -ForegroundColor Yellow
        Write-Host "Path filtering complete. $($allResults.Count) of $preFilterCount entries remain." -ForegroundColor Yellow
    }
    
    if ($allResults.Count -gt 0) {
        Write-Host "`nAnalyzed a total of $($allResults.Count) ShellBag entries from $pathsWithData locations." -ForegroundColor Green
        
        $deletedFolders = $allResults | Where-Object { $_.IsDeleted }
        if ($deletedFolders.Count -gt 0) {
            Write-Host "Found $($deletedFolders.Count) potentially deleted folders!" -ForegroundColor Red
        }
        
        $reportPath = Export-ResultsToFormats -ShellBagData $allResults -OutputPath $OutputPath -OutputFormat $OutputFormat -IsServerOS $isServerOS
        
        if ($reportPath) {
            Write-Host "`nAnalysis complete. Open $reportPath to view the full report." -ForegroundColor Green
            
            try {
                Write-Host "Launching HTML report in default browser..." -ForegroundColor Cyan
                Invoke-Item $reportPath
            } catch {
                Write-Warning "Unable to automatically open the HTML report: $_"
                Write-Host "Please open the report manually: $reportPath" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "No ShellBag data found after checking $pathsChecked possible locations." -ForegroundColor Yellow
        Write-Host "This might be because:" -ForegroundColor Yellow
        Write-Host "  1. The registry paths don't exist on this system" -ForegroundColor Yellow
        Write-Host "  2. There are no ShellBag entries for the current user" -ForegroundColor Yellow
        Write-Host "  3. The script is not running with Administrator privileges" -ForegroundColor Yellow
        
        if ($osName -like "*Windows 11*") {
            Write-Host "`nWindows 11 detected - checking alternative folder history sources..." -ForegroundColor Yellow
            
            $quickAccessResults = Get-QuickAccessHistory -IncludeDeleted:$IncludeDeleted -DaysBack $DaysBack
            
            if ($quickAccessResults -and $quickAccessResults.Count -gt 0) {
                Write-Host "`nFound $($quickAccessResults.Count) items in Windows 11 Quick Access and Recent Items." -ForegroundColor Green
                
                $allResults += $quickAccessResults
                
                $reportPath = Export-ResultsToFormats -ShellBagData $allResults -OutputPath $OutputPath -OutputFormat $OutputFormat -IsServerOS $isServerOS
                
                if ($reportPath) {
                    Write-Host "`nAnalysis complete. Open $reportPath to view the full report." -ForegroundColor Green
                    
                    try {
                        Write-Host "Launching HTML report in default browser..." -ForegroundColor Cyan
                        Invoke-Item $reportPath
                    } catch {
                        Write-Warning "Unable to automatically open the HTML report: $_"
                        Write-Host "Please open the report manually: $reportPath" -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "No folder history found in alternative Windows 11 data sources." -ForegroundColor Yellow
                Write-Host "Try running with -Verbose switch for detailed diagnostic information." -ForegroundColor Yellow
                Write-Host "`nSuggestions for Windows 11:" -ForegroundColor Cyan
                Write-Host "  1. Run createTestShellBags.ps1 and REBOOT before running shellBagHunter.ps1" -ForegroundColor White
                Write-Host "  2. Make sure to run PowerShell as Administrator" -ForegroundColor White
                Write-Host "  3. Browse more folders in File Explorer to generate activity" -ForegroundColor White
            }
        } else {
            Write-Host "`nTry running with -Verbose switch for detailed diagnostic information." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Error "An error occurred while processing ShellBag data: $_"
    Write-Error $_.ScriptStackTrace
} finally {
    if ($UserSID -and (Test-Path "HKU:\$UserSID")) {
        [gc]::Collect()
        reg unload "HKU\$UserSID"
        Write-Host "Unloaded user registry hive." -ForegroundColor Green
    }
}
}
function Prefetch {
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML", "CSV", "JSON", "ALL")]
    [string]$ExportFormat = "ALL",

    [Parameter(Mandatory=$false)]
    [string]$PrefetchPath = "C:\Windows\Prefetch",

    [Parameter(Mandatory=$false)]
    [switch]$SortByLastExecution,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExecutedInLast24Hours,
    
    [Parameter(Mandatory=$false)]
    [int]$TopExecuted = 0,
    
    [Parameter(Mandatory=$false)]
    [switch]$ReturnHtmlContent
)

<#
.SYNOPSIS
    Analyzes Windows Prefetch files to identify program execution history.

.DESCRIPTION
    This script extracts and analyzes Windows Prefetch files to identify application execution
    history, frequency, and patterns. It can generate detailed reports in HTML, CSV, and JSON formats.

.PARAMETER ExportFormat
    The format to export results. Accepts: HTML, CSV, JSON, or ALL. Default is ALL.

.PARAMETER PrefetchPath
    The path to the Prefetch directory. Default is "C:\Windows\Prefetch".

.PARAMETER SortByLastExecution
    If specified, results will be sorted by last execution time instead of execution count.

.PARAMETER ExecutedInLast24Hours
    If specified, only shows programs executed in the last 24 hours.

.PARAMETER TopExecuted
    If specified, only shows the top N most executed programs. Default is 0 (show all).

.PARAMETER ReturnHtmlContent
    If specified, the function will return the HTML content instead of writing to file.

.NOTES
    File Name      : Prefetch_Hunter.ps1
    Prerequisite   : PowerShell 5.1 or later, Administrator rights
    Author         : The Haag
    
.EXAMPLE
    .\Prefetch_Hunter.ps1 -ExportFormat HTML
    Analyzes Prefetch data and generates only an HTML report.

.EXAMPLE
    .\Prefetch_Hunter.ps1 -TopExecuted 10 -SortByLastExecution
    Shows the top 10 most recently executed programs and generates all report formats.

.EXAMPLE
    .\Prefetch_Hunter.ps1 -ExecutedInLast24Hours
    Shows only programs executed in the last 24 hours and generates all report formats.

.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>

$AsciiArt = @"
    +-+-+-+-+-+-+-+-+ 
    |P|r|e|f|e|t|c|h| 
    +-+-+-+-+-+-+-+-+ 
                                                                           
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |P|o|w|e|r|S|h|e|l|l| |H|U|N|T|E|R|
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+

        [ Hunt smarter, Hunt harder ]
"@

Write-Host $AsciiArt -ForegroundColor Cyan
Write-Host "`nPrefetch Data Analysis Tool" -ForegroundColor Green
Write-Host "----------------------------`n" -ForegroundColor DarkGray

function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Warning "This script requires Administrator privileges to access Prefetch files!"
    exit
}

function Parse-PrefetchFiles {
    param(
        [string]$PrefetchPath,
        [switch]$SortByLastExecution,
        [switch]$ExecutedInLast24Hours,
        [int]$TopExecuted = 0
    )
    
    Write-Host "Analyzing Prefetch files from $PrefetchPath..." -ForegroundColor Yellow

    if (-not (Test-Path -Path $PrefetchPath)) {
        Write-Warning "Prefetch directory not found at $PrefetchPath"
        return @()
    }
    
    $prefetchFiles = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
    
    if ($prefetchFiles.Count -eq 0) {
        Write-Warning "No prefetch files found in $PrefetchPath"
        return @()
    }
    
    Write-Host "Found $($prefetchFiles.Count) prefetch files. Extracting data..." -ForegroundColor Green
    
    $results = @()
    
    foreach ($file in $prefetchFiles) {
        try {
            $programName = ($file.Name -split '-')[0]
            $fileInfo = Get-ItemProperty -Path $file.FullName
            
            $prefetchInfo = [PSCustomObject]@{
                ProgramName      = $programName
                LastExecution    = $fileInfo.LastWriteTime
                CreationTime     = $fileInfo.CreationTime
                PrefetchFile     = $file.Name
                PrefetchSize     = "{0:N2} KB" -f ($file.Length / 1KB)
                FilePath         = $file.FullName
                SizeInBytes      = $file.Length
                AccessTime       = $fileInfo.LastAccessTime
                HashValue        = ($file.Name -split '-')[1] -replace ".pf", ""
                RunCount         = $null
                DaysSinceCreated = [math]::Round(((Get-Date) - $fileInfo.CreationTime).TotalDays, 1)
                DaysSinceLastRun = [math]::Round(((Get-Date) - $fileInfo.LastWriteTime).TotalDays, 1)
                RunsPerDay       = $null
            }
            
            $baseSize = 2KB  # Minimum size for a prefetch file
            $estimatedRunCount = [math]::Max(1, [math]::Round(($file.Length - $baseSize) / 512) + 1)
            $prefetchInfo.RunCount = $estimatedRunCount
            
            if ($prefetchInfo.DaysSinceCreated -gt 0) {
                $prefetchInfo.RunsPerDay = [math]::Round($estimatedRunCount / $prefetchInfo.DaysSinceCreated, 2)
            } else {
                $prefetchInfo.RunsPerDay = $estimatedRunCount
            }
            
            $results += $prefetchInfo
        }
        catch {
            Write-Warning "Error processing $($file.Name): $_"
        }
    }
    
    if ($ExecutedInLast24Hours) {
        $cutoffTime = (Get-Date).AddDays(-1)
        $results = $results | Where-Object { $_.LastExecution -gt $cutoffTime }
        Write-Host "Filtered to $($results.Count) programs executed in the last 24 hours." -ForegroundColor Yellow
    }
    
    if ($SortByLastExecution) {
        $results = $results | Sort-Object -Property LastExecution -Descending
    } else {
        $results = $results | Sort-Object -Property RunCount -Descending
    }
    
    if ($TopExecuted -gt 0 -and $results.Count -gt $TopExecuted) {
        $results = $results | Select-Object -First $TopExecuted
        Write-Host "Showing top $TopExecuted programs." -ForegroundColor Yellow
    }
    
    return $results
}

function Get-NotableExecutions {
    param(
        [array]$PrefetchData
    )
    
    $notable = @()
    
    # Get baseline statistics
    $avgRunsPerDay = ($PrefetchData | Measure-Object -Property RunsPerDay -Average).Average
    $stdDevRunsPerDay = [Math]::Sqrt(($PrefetchData | ForEach-Object { [Math]::Pow(($_.RunsPerDay - $avgRunsPerDay), 2) } | Measure-Object -Average).Average)
    
    # Calculate time-based statistics
    $executionsByHour = @{}
    foreach ($item in $PrefetchData) {
        $hour = $item.LastExecution.Hour
        if (-not $executionsByHour.ContainsKey($hour)) {
            $executionsByHour[$hour] = 0
        }
        $executionsByHour[$hour]++
    }
    
    # Calculate average executions per hour
    $avgExecPerHour = ($executionsByHour.Values | Measure-Object -Average).Average
    $stdDevExecPerHour = [Math]::Sqrt(($executionsByHour.Values | ForEach-Object { [Math]::Pow(($_ - $avgExecPerHour), 2) } | Measure-Object -Average).Average)
    
    # Identify off-hours with unusual activity (2+ standard deviations)
    $unusualHours = @()
    foreach ($hour in $executionsByHour.Keys) {
        if (($hour -ge 22 -or $hour -le 5) -and ($executionsByHour[$hour] -gt ($avgExecPerHour + (2 * $stdDevExecPerHour)))) {
            $unusualHours += $hour
        }
    }
    
    # Get first-seen dates for all programs
    $firstSeenDates = @{}
    foreach ($item in $PrefetchData) {
        if (-not $firstSeenDates.ContainsKey($item.ProgramName)) {
            $firstSeenDates[$item.ProgramName] = $item.CreationTime
        } elseif ($item.CreationTime -lt $firstSeenDates[$item.ProgramName]) {
            $firstSeenDates[$item.ProgramName] = $item.CreationTime
        }
    }
    
    # Fetch LOLBAS data
    Write-Host "Fetching LOLBAS data to identify potentially abusable binaries..." -ForegroundColor Yellow
    $lolbasData = $null
    try {
        $lolbasUrl = "https://lolbas-project.github.io/api/lolbas.json"
        $webClient = New-Object System.Net.WebClient
        $lolbasJson = $webClient.DownloadString($lolbasUrl)
        $lolbasData = ConvertFrom-Json -InputObject $lolbasJson
        Write-Host "Successfully loaded LOLBAS data with $($lolbasData.Count) entries" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to fetch LOLBAS data: $_"
        Write-Host "Continuing without LOLBAS integration..." -ForegroundColor Yellow
    }
    
    $lolbasBinaries = @{}
    $lolbasDescriptions = @{}
    $lolbasCategoryMap = @{}
    $lolbasUrls = @{}
    
    if ($lolbasData) {
        foreach ($entry in $lolbasData) {
            $filename = $entry.Name
            $lolbasBinaries[$filename.ToUpper()] = $true
            $lolbasBinaries[$filename.ToLower()] = $true
            
            $lolbasDescriptions[$filename.ToUpper()] = $entry.Description
            $lolbasUrls[$filename.ToUpper()] = $entry.url
            
            $categories = $entry.Commands | ForEach-Object { $_.Category } | Select-Object -Unique
            $lolbasCategoryMap[$filename.ToUpper()] = $categories -join ", "
        }
        Write-Host "Processed $($lolbasBinaries.Count / 2) unique LOLBAS binaries" -ForegroundColor Green
    }
    
    $systemDirs = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64", 
        "$env:SystemRoot\WinSxS",
        "$env:SystemRoot"
    )
    
    $securityTools = @(
        '^MIMIKATZ\.EXE$',
        '^PSEXEC\.EXE$',
        '^PSEXESVC\.EXE$',
        '^NETCAT\.EXE$',
        '^NC\.EXE$',
        '^NMAP\.EXE$',
        '^LAZAGNE\.EXE$',
        '^PWDUMP\d*\.EXE$',
        '^PROCDUMP\.EXE$',
        '^RUBEUS\.EXE$',
        '^BLOODHOUND\.EXE$',
        '^SHARPHOUND\.EXE$',
        '^WCESERVICE\.EXE$',
        '^WINPCAP\.EXE$',
        '^ETTERCAP\.EXE$',
        '^RESPONDER\.EXE$',
        '^HASHCAT\.EXE$',
        '^JOHN\.EXE$',
        '^CAIN\.EXE$',
        '^HYDRA\.EXE$',
        '^WIRESHARK\.EXE$',
        '^TCPDUMP\.EXE$'
    )
    
    foreach ($item in $PrefetchData) {
        $isNotable = $false
        $categories = @()
        $insights = @()
        
        $isLolbas = $false
        $lolbasDetails = ""
        $lolbasUrl = ""
        $binaryCategoriesString = ""
        
        if ($lolbasBinaries -and $lolbasBinaries.ContainsKey($item.ProgramName.ToUpper())) {
            $isLolbas = $true
            $isNotable = $true
            $categories += "LOLBAS Binary"
            
            $lolbasDetails = $lolbasDescriptions[$item.ProgramName.ToUpper()]
            if ($lolbasCategoryMap.ContainsKey($item.ProgramName.ToUpper())) {
                $binaryCategoriesString = $lolbasCategoryMap[$item.ProgramName.ToUpper()]
            } else {
                $binaryCategoriesString = "Unknown"
            }
            $lolbasUrl = $lolbasUrls[$item.ProgramName.ToUpper()]
            
            $insights += "Known LOLBAS binary that could be abused for $binaryCategoriesString - $lolbasDetails"
        }
        
        $isSecurityTool = $false
        foreach ($pattern in $securityTools) {
            if ($item.ProgramName -match $pattern) {
                $isSecurityTool = $true
                $isNotable = $true
                $categories += "Security Tool Usage"
                $insights += "Known penetration testing or security tool detected"
                break
            }
        }
        
        # Check for system utilities executed in unusual contexts
        if (-not $isSecurityTool -and $item.ProgramName -match '(?i)(powershell|cmd|wmic|reg|schtasks|bitsadmin)\.exe$') {
            # Check context - high frequency or unusual hours
            $hourOfDay = $item.LastExecution.Hour
            $unusualHours = ($hourOfDay -ge 22 -or $hourOfDay -le 5)
            $highFrequency = ($item.RunsPerDay -gt ($avgRunsPerDay + $stdDevRunsPerDay * 2))
            
            if ($unusualHours -or $highFrequency) {
                $isNotable = $true
                $categories += "System Utility Anomaly"
                if ($unusualHours) { $insights += "Executed during non-business hours (10PM-5AM)" }
                if ($highFrequency) { $insights += "Unusually high execution frequency compared to system baseline" }
            }
        }
        
        # Statistical outliers - only consider significant deviations
        if ($item.RunsPerDay -gt ($avgRunsPerDay + $stdDevRunsPerDay * 3)) {
            $isNotable = $true
            $categories += "Statistical Outlier"
            $insights += "Execution frequency significantly above normal system baseline"
        }
        
        # New or recently introduced programs with significant usage
        $firstSeen = $firstSeenDates[$item.ProgramName]
        $daysSinceFirstSeen = [math]::Round(((Get-Date) - $firstSeen).TotalDays, 1)
        if ($daysSinceFirstSeen -le 7 -and $item.RunCount -gt 20) {
            $isNotable = $true
            $categories += "Recently Introduced Program"
            $insights += "Program first appeared $daysSinceFirstSeen days ago with significant usage"
        }
        
        # Time-based unusual execution patterns
        $hourOfDay = $item.LastExecution.Hour
        if ($unusualHours -contains $hourOfDay -and $item.RunCount -gt 5) {
            $isNotable = $true
            $categories += "Off-Hours Activity"
            $insights += "Unusual execution during off-hours (10PM-5AM) with significant activity"
        }
        
        $dayOfWeek = $item.LastExecution.DayOfWeek
        if (($dayOfWeek -eq 'Saturday' -or $dayOfWeek -eq 'Sunday') -and 
            $item.ProgramName -match '(?i)(excel|word|powerpoint|outlook|teams|skype|zoom)') {
            $isNotable = $true
            $categories += "Weekend Business Activity"
            $insights += "Business software executed during weekend"
        }
        
        if ($item.RunCount -eq 1 -and $item.DaysSinceLastRun -lt 2 -and 
            -not ($item.ProgramName -match '(?i)(install|setup|update|config|uninstall)')) {
            $likelySystemBinary = $false
            foreach ($dir in $systemDirs) {
                $potentialPath = Join-Path -Path $dir -ChildPath $item.ProgramName
                if (Test-Path -Path $potentialPath -ErrorAction SilentlyContinue) {
                    $likelySystemBinary = $true
                    break
                }
            }
            
            if (-not $likelySystemBinary) {
                $isNotable = $true
                $categories += "One-time Execution"
                $insights += "Single execution of program that doesn't appear to be an installer/updater"
            }
        }
        
        if ($isNotable) {
            $notableItem = $item.PSObject.Copy()
            $notableItem | Add-Member -MemberType NoteProperty -Name "Categories" -Value ($categories -join "; ")
            $notableItem | Add-Member -MemberType NoteProperty -Name "AnalysisInsights" -Value ($insights -join "; ")
            $notableItem | Add-Member -MemberType NoteProperty -Name "FirstSeen" -Value $firstSeen
            
            if ($isLolbas) {
                $notableItem | Add-Member -MemberType NoteProperty -Name "IsLolbas" -Value $true
                $notableItem | Add-Member -MemberType NoteProperty -Name "LolbasUrl" -Value $lolbasUrl
            } else {
                $notableItem | Add-Member -MemberType NoteProperty -Name "IsLolbas" -Value $false
            }
            
            $notable += $notableItem
        }
    }
    
    return $notable
}

function Create-HtmlReport {
    param(
        [array]$PrefetchData,
        [array]$NotableData,
        [string]$HtmlPath,
        [switch]$ReturnContent = $false
    )
    
    $Css = @"
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #0078D7;
        }
        h1 {
            text-align: center;
            padding-bottom: 10px;
            border-bottom: 2px solid #0078D7;
            margin-bottom: 30px;
        }
        .section {
            margin-bottom: 30px;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
            border-left: 5px solid #0078D7;
        }
        .notable-section {
            border-left: 5px solid #FF8C00;
        }
        .lolbas-section {
            border-left: 5px solid #9C27B0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th {
            background-color: #0078D7;
            color: white;
            padding: 12px;
            text-align: left;
        }
        .notable-table th {
            background-color: #FF8C00;
        }
        .lolbas-table th {
            background-color: #9C27B0;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #e6f3ff;
        }
        tr.lolbas-row {
            background-color: #f3e5f5;
        }
        tr.lolbas-row:hover {
            background-color: #e1bee7;
        }
        .summary {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .stat-box {
            flex: 1;
            min-width: 200px;
            margin: 10px;
            padding: 15px;
            background-color: #e6f3ff;
            border-radius: 5px;
            text-align: center;
            box-shadow: 0 0 5px rgba(0,0,0,0.05);
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #0078D7;
        }
        .notable-stat {
            background-color: #FFF3E0;
        }
        .notable-value {
            color: #FF8C00;
        }
        .lolbas-stat {
            background-color: #f3e5f5;
        }
        .lolbas-value {
            color: #9C27B0;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #777;
        }
        .program-name {
            max-width: 300px;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        .chart-container {
            width: 100%;
            height: 400px;
            margin: 20px 0;
        }
        .insight-cell {
            max-width: 500px;
        }
        .lolbas-link {
            display: inline-block;
            padding: 2px 8px;
            background-color: #9C27B0;
            color: white;
            text-decoration: none;
            border-radius: 3px;
            font-size: 12px;
            margin-left: 5px;
        }
        .lolbas-link:hover {
            background-color: #7B1FA2;
        }
        .infobox {
            padding: 10px 15px;
            margin: 10px 0;
            border-radius: 5px;
            background-color: #E3F2FD;
            border-left: 5px solid #2196F3;
        }
        .legend {
            margin: 15px 0;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin-right: 15px;
        }
        .legend-color {
            width: 15px;
            height: 15px;
            margin-right: 5px;
            border-radius: 3px;
        }
        .legend-color.notable {
            background-color: #FF8C00;
        }
        .legend-color.lolbas {
            background-color: #9C27B0;
        }
        .legend-text {
            font-size: 14px;
        }
        .category-tag {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            margin-right: 3px;
            color: white;
            background-color: #607D8B;
        }
        .category-tag.security-tool {
            background-color: #F44336;
        }
        .category-tag.lolbas {
            background-color: #9C27B0;
        }
        .category-tag.anomaly {
            background-color: #FF9800;
        }
        .category-tag.outlier {
            background-color: #2196F3;
        }
        .category-tag.naming {
            background-color: #009688;
        }
    </style>
"@

    $ChartJs = @"
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
"@

    $totalPrograms = $PrefetchData.Count
    $last24Hours = ($PrefetchData | Where-Object { $_.LastExecution -gt (Get-Date).AddDays(-1) }).Count
    $last7Days = ($PrefetchData | Where-Object { $_.LastExecution -gt (Get-Date).AddDays(-7) }).Count
    $notableCount = $NotableData.Count
    $lolbasCount = ($NotableData | Where-Object { $_.IsLolbas -eq $true }).Count
    $mostExecuted = $PrefetchData | Sort-Object -Property RunCount -Descending | Select-Object -First 1
    $mostRecent = $PrefetchData | Sort-Object -Property LastExecution -Descending | Select-Object -First 1

    $top10Executed = $PrefetchData | Sort-Object -Property RunCount -Descending | Select-Object -First 10

    $chartLabels = $top10Executed.ProgramName | ForEach-Object { 
        $name = $_
        if ($name.Length -gt 20) { $name = $name.Substring(0, 17) + "..." }
        "`"$name`""
    }
    $chartData = $top10Executed.RunCount
    
    $HtmlContent = @"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Prefetch Analysis Report - $(Get-Date -Format 'yyyyMMdd_HHmmss')</title>
        $Css
        $ChartJs
    </head>
    <body>
        <div class="container">
            <h1>Windows Prefetch Analysis Report</h1>
            <p>Report generated on $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')</p>
            
            <div class="infobox">
                <p><strong>About Prefetch Analysis:</strong> Prefetch files are created by Windows to speed up application launching. They contain metadata about program executions including launch times and frequency. Analyzing these files provides insights into system usage patterns and can help identify potentially unusual activity.</p>
            </div>
            
            <div class="summary">
                <div class="stat-box">
                    <div>Total Programs</div>
                    <div class="stat-value">$totalPrograms</div>
                </div>
                <div class="stat-box">
                    <div>Executed in Last 24h</div>
                    <div class="stat-value">$last24Hours</div>
                </div>
                <div class="stat-box">
                    <div>Executed in Last 7d</div>
                    <div class="stat-value">$last7Days</div>
                </div>
                <div class="stat-box notable-stat">
                    <div>Notable Executions</div>
                    <div class="stat-value notable-value">$notableCount</div>
                </div>
                <div class="stat-box lolbas-stat">
                    <div>LOLBAS Binaries</div>
                    <div class="stat-value lolbas-value">$lolbasCount</div>
                </div>
            </div>
            
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color notable"></div>
                    <div class="legend-text">Notable Execution</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color lolbas"></div>
                    <div class="legend-text">LOLBAS Binary</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Most Frequently Executed Programs</h2>
                <div class="chart-container">
                    <canvas id="executionChart"></canvas>
                </div>
                <script>
                    var ctx = document.getElementById('executionChart').getContext('2d');
                    var executionChart = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: [$($chartLabels -join ', ')],
                            datasets: [{
                                label: 'Execution Count',
                                data: [$($chartData -join ', ')],
                                backgroundColor: 'rgba(0, 120, 215, 0.7)',
                                borderColor: 'rgba(0, 120, 215, 1)',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                </script>
            </div>
"@

    $lolbasBinaries = $NotableData | Where-Object { $_.IsLolbas -eq $true }
    if ($lolbasBinaries.Count -gt 0) {
        $lolbasTable = "<table class='lolbas-table'><thead><tr><th>Program Name</th><th>Last Execution</th><th>Run Count</th><th>Runs Per Day</th><th>Categories</th><th>Analysis Insights</th><th>LOLBAS</th></tr></thead><tbody>"
        
        foreach ($item in $lolbasBinaries) {
            $categoryTags = ($item.Categories -split ';') | ForEach-Object { 
                $class = "category-tag"
                if ($_ -match 'Security Tool') { $class += " security-tool" }
                elseif ($_ -match 'LOLBAS') { $class += " lolbas" }
                elseif ($_ -match 'Anomaly') { $class += " anomaly" }
                elseif ($_ -match 'Outlier') { $class += " outlier" }
                elseif ($_ -match 'Naming') { $class += " naming" }
                
                "<span class='$class'>$($_.Trim())</span>" 
            }
            $formattedCategories = $categoryTags -join " "
            
            $lolbasTable += "<tr class='lolbas-row'>
                <td class='program-name'>$($item.ProgramName)</td>
                <td>$($item.LastExecution)</td>
                <td>$($item.RunCount)</td>
                <td>$($item.RunsPerDay)</td>
                <td>$formattedCategories</td>
                <td class='insight-cell'>$($item.AnalysisInsights)</td>
                <td><a href='$($item.LolbasUrl)' target='_blank' class='lolbas-link'>LOLBAS Info</a></td>
            </tr>"
        }
        
        $lolbasTable += "</tbody></table>"
        
        $HtmlContent += @"
            <div class="section lolbas-section">
                <h2>LOLBAS (Living Off The Land Binaries and Scripts)</h2>
                <p>The following $($lolbasBinaries.Count) programs are known LOLBAS binaries that could potentially be abused for various purposes:</p>
                <div class="infobox">
                    <p><strong>What is LOLBAS?</strong> The LOLBAS project documents Windows binaries, scripts, and libraries that can be used for legitimate purposes but may also be abused by attackers for malicious activities like execution, persistence, or data exfiltration while evading security tools.</p>
                </div>
                $lolbasTable
            </div>
"@
    }

    $otherNotable = $NotableData | Where-Object { $_.IsLolbas -ne $true }
    if ($otherNotable.Count -gt 0) {
        $notableTable = "<table class='notable-table'><thead><tr><th>Program Name</th><th>Last Execution</th><th>Run Count</th><th>Runs Per Day</th><th>First Seen</th><th>Categories</th><th>Analysis Insights</th></tr></thead><tbody>"
        
        foreach ($item in $otherNotable) {
            $categoryTags = ($item.Categories -split ';') | ForEach-Object { 
                $class = "category-tag"
                if ($_ -match 'Security Tool') { $class += " security-tool" }
                elseif ($_ -match 'System Utility') { $class += " anomaly" }
                elseif ($_ -match 'Statistical Outlier') { $class += " outlier" }
                elseif ($_ -match 'Naming') { $class += " naming" }
                
                "<span class='$class'>$($_.Trim())</span>" 
            }
            $formattedCategories = $categoryTags -join " "
            
            $notableTable += "<tr>
                <td class='program-name'>$($item.ProgramName)</td>
                <td>$($item.LastExecution)</td>
                <td>$($item.RunCount)</td>
                <td>$($item.RunsPerDay)</td>
                <td>$($item.FirstSeen)</td>
                <td>$formattedCategories</td>
                <td class='insight-cell'>$($item.AnalysisInsights)</td>
            </tr>"
        }
        
        $notableTable += "</tbody></table>"
        
        $HtmlContent += @"
            <div class="section notable-section">
                <h2>Other Notable Program Executions</h2>
                <p>The following $($otherNotable.Count) programs exhibited potentially interesting execution patterns:</p>
                $notableTable
            </div>
"@
    }

    $prefetchTable = "<table><thead><tr><th>Program Name</th><th>Last Execution</th><th>Run Count</th><th>Runs Per Day</th><th>Days Since Last Run</th><th>Prefetch File</th></tr></thead><tbody>"
    
    foreach ($item in $PrefetchData) {
        $rowClass = ""
        $lolbasLink = ""
        
        $matchedItem = $NotableData | Where-Object { $_.ProgramName -eq $item.ProgramName } | Select-Object -First 1
        if ($matchedItem) {
            if ($matchedItem.IsLolbas -eq $true) {
                $rowClass = "class='lolbas-row'"
                $lolbasLink = " <a href='$($matchedItem.LolbasUrl)' target='_blank' class='lolbas-link'>LOLBAS</a>"
            }
        }
        
        $prefetchTable += "<tr $rowClass>
            <td class='program-name'>$($item.ProgramName)$lolbasLink</td>
            <td>$($item.LastExecution)</td>
            <td>$($item.RunCount)</td>
            <td>$($item.RunsPerDay)</td>
            <td>$($item.DaysSinceLastRun)</td>
            <td>$($item.PrefetchFile)</td>
        </tr>"
    }
    
    $prefetchTable += "</tbody></table>"
    
    $HtmlContent += @"
            <div class="section">
                <h2>All Prefetch Files</h2>
                <p>Total of $($PrefetchData.Count) prefetch files analyzed:</p>
                $prefetchTable
            </div>
            
            <div class="footer">
                <p>Generated by Prefetch Hunter - PowerShell Hunter Toolkit</p>
                <p>Enhanced with <a href="https://lolbas-project.github.io/" target="_blank">LOLBAS Project</a> integration</p>
                <p>https://github.com/MHaggis/PowerShell-Hunter</p>
            </div>
        </div>
    </body>
    </html>
"@

    $HtmlContent | Out-File -FilePath $HtmlPath
    
    if ($ReturnContent) {
        return $HtmlContent
    }
}

function Export-ResultsToFormats {
    param(
        [array]$PrefetchData,
        [array]$NotableData,
        [string]$ExportFormat,
        [string]$BasePath,
        [switch]$ReturnHtmlContent = $false
    )
    
    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $ExportBaseName = "$($BasePath)_$($Timestamp)"
    $HtmlPath = "$ExportBaseName.html"
    
    if ($PrefetchData) {
        if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "ALL") {
            $CSVPath = "$ExportBaseName.csv"
            $PrefetchData | Export-Csv -Path $CSVPath -NoTypeInformation
            Write-Host "`nData exported to CSV: $CSVPath" -ForegroundColor Green
        }
        
        if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "ALL") {
            $JSONPath = "$ExportBaseName.json"
            $PrefetchData | ConvertTo-Json -Depth 4 | Out-File $JSONPath
            Write-Host "Data exported to JSON: $JSONPath" -ForegroundColor Green
        }
        
        if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "ALL") {
            if ($ReturnHtmlContent) {
                $htmlContent = Create-HtmlReport -PrefetchData $PrefetchData -NotableData $NotableData -HtmlPath $HtmlPath -ReturnContent
                Write-Host "HTML content generated (not saved to file)" -ForegroundColor Green
                return $htmlContent
            } else {
                Create-HtmlReport -PrefetchData $PrefetchData -NotableData $NotableData -HtmlPath $HtmlPath
                Write-Host "HTML report generated: $HtmlPath" -ForegroundColor Green
                return $HtmlPath
            }
        }
    } else {
        Write-Host "No data to export." -ForegroundColor Yellow
        return $null
    }
}

$prefetchData = Parse-PrefetchFiles -PrefetchPath $PrefetchPath -SortByLastExecution:$SortByLastExecution -ExecutedInLast24Hours:$ExecutedInLast24Hours -TopExecuted $TopExecuted
$notableData = Get-NotableExecutions -PrefetchData $prefetchData

if ($prefetchData.Count -gt 0) {
    Write-Host "`nAnalyzed $($prefetchData.Count) prefetch files." -ForegroundColor Green
    
    if ($notableData.Count -gt 0) {
        Write-Host "Found $($notableData.Count) potentially interesting executions!" -ForegroundColor Yellow
    }
    
    $result = Export-ResultsToFormats -PrefetchData $prefetchData -NotableData $notableData -ExportFormat $ExportFormat -BasePath "PrefetchHunter" -ReturnHtmlContent:$ReturnHtmlContent
    
    if ($result -and -not $ReturnHtmlContent) {
        $reportPath = $result
        Write-Host "`nAnalysis complete. Open $reportPath to view the full report." -ForegroundColor Green
        
        try {
            Write-Host "Launching HTML report in default browser..." -ForegroundColor Cyan
            Invoke-Item $reportPath
        } catch {
            Write-Warning "Unable to automatically open the HTML report: $_"
        }
    } else {
        return $result
    }
} else {
    Write-Host "No Prefetch data found to analyze." -ForegroundColor Yellow
} 
}

function Show-Menu {
    while ($true) {
        Clear-Host
        Write-Host "===================="
        Write-Host "   menu"
        Write-Host "===================="
        Write-Host "1. run  Analyze-MRURegistry"
        Write-Host "2. run  ShellBagHunter"
        Write-Host "3. run  Prefetch  "
		Write-Host "4. exit"
        Write-Host "--------------------"
        $choice = Read-Host "choice"
        
        switch ($choice) {
            "1" { 
                Clear-Host
                Analyze-MRURegistry 
                Pause
            }
            "2" { 
                Clear-Host
                Invoke-ShellBagHunter 
                Pause
            }
			"3"
			{
				Clear-Host
				Prefetch
				Pause
			}
            "4" { 
                Write-Host "exit"
                exit
				
            }
            default {
                Write-Host "invalid"
                Pause
            }
        }
    }
}


Show-Menu