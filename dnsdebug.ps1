
function Enable-DNSDebug {
    param (
        [string]$DebugFilePath = "C:\Windows\System32\DNS\Debug.log",
        [switch]$Enable,
        [switch]$Disable
    )
    try {
        if ($Enable) {
            Set-DnsServerDiagnostics -DebugLogging $true
            Write-Host "DNS Debug logging enabled. Logs will be written to: $DebugFilePath"
        }
        elseif ($Disable) {
            Set-DnsServerDiagnostics -DebugLogging $false
            Write-Host "DNS Debug logging disabled."
        }
        else {
            Write-Host "Please specify -Enable or -Disable switch."
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}

function Start-DNSTrace {
    param (
        [string]$TraceFilePath = "C:\Windows\System32\DNS\Trace.log",
        [int]$Duration = 300
    )
    try {
        Start-Trace -Path $TraceFilePath -Duration $Duration
        Write-Host "DNS tracing started. Trace will be saved to: $TraceFilePath for $Duration seconds."
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}

function Search-DnsIssues {
    param (
        [string]$SearchPath = "C:\Windows\System32\drivers\etc\hosts",
        [switch]$EnableDebug,
        [switch]$DebugLog,
        [int]$SleepInterval = 300
    )
    try {
        $dnsFile = Get-Content -Path $SearchPath -ErrorAction Stop
        $isDebugEnabled = $EnableDebug.IsPresent
        $logPath = "C:\Logs\DnsDiagnostics.log"

        if ($isDebugEnabled) {
            Write-Host "Debug mode enabled. Logging to $logPath" -ForegroundColor Green
            $dnsFile | Out-File -FilePath $logPath -Append
        }

        $dnsEntries = $dnsFile | Where-Object { $_ -match "^\s*#" -or $_ -match "\d+\.\d+\.\d+\.\d+" }
        $filteredEntries = $dnsEntries | Sort-Object -Property { $_ -replace "^\s*#|\s+", "" } -Descending

        Write-Host "DNS Entries Found:" -ForegroundColor Yellow
        $filteredEntries | ForEach-Object {
            Write-Host $_
        }

        Start-Sleep -Seconds $SleepInterval
    }
    catch {
        Write-Error "An error occurred: $_"
    }
    finally {
        if ($DebugLog.IsPresent) {
            Write-Host "Debug log has been created at $logPath" -ForegroundColor Cyan
        }
    }
}


$logFile = "C:\DNSDebug.log"
$logTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = "$logFile_$logTime.txt"


Start-Transcript -Path $logPath -Append


function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append
}

try {
    $debugHost = "dns01.example.com"
    $debugLevel = "Verbose"
    $debugDuration = 300 

    Write-Log "Starting DNS debug on $debugHost with level $debugLevel for $debugDuration seconds"
    Set-DnsServerDiagnostics -ComputerName $debugHost -Enable $true -DebugLogging $true


    Start-Sleep -Seconds $debugDuration

    Set-DnsServerDiagnostics -ComputerName $debugHost -Enable $false

    Write-Log "DNS debugging completed on $debugHost"
}
catch {
    Write-Log "Error occurred: $_"
}
finally {

    Stop-Transcript
}


Get-ChildItem -Path "C:\Windows\System32\DNS\*" -File | 
    Sort-Object LastWriteTime -Descending


$i = 1
$iterations = 1
$sourcePath = "C:\Source"
try {
    Write-Host "Iterations: $i" -ForegroundColor Yellow
    if ($iterations -eq 0) {
        exit
    }
    else {
        $tempDir = Join-Path -Path $env:TEMP -ChildPath ("debug_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
      
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        $zipFile = Join-Path -Path $tempDir -ChildPath "debug.zip"
        Copy-Item -Path "$sourcePath\*" -Destination $tempDir -Recurse -Force
        Compress-Archive -Path "$tempDir\*" -DestinationPath $zipFile -Force
    }
}
catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}
finally {
    Write-Host "Done." -ForegroundColor Green
}


$DebugPath = "C:\Windows\System32\DNS\Debug.log"
$TracePath = "C:\Windows\System32\DNS\Trace.log"

Enable-DNSDebug -Enable -DebugFilePath $DebugPath


Start-DNSTrace -TraceFilePath $TracePath -Duration 300


Get-ChildItem -Path "C:\Windows\System32\DNS\" | 
    Sort-Object -Property LastWriteTime -Descending


Search-DnsIssues -EnableDebug -DebugLog -SearchPath "C:\Windows\System32\drivers\etc\hosts" اینو بررسی کن بهم بگو اگر جاییش ایراد داره لطفا همون یه تیکه رو درستش رو بهمب گو