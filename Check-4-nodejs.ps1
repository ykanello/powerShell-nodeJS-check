
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$Url,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "nodejs_audit_results.csv"
)

function Test-NodeSite {
    param (
        [string]$TargetUrl,
        [string]$AppName = "N/A"
    )

    if ([string]::IsNullOrWhiteSpace($TargetUrl)) {
        return [PSCustomObject]@{
            "Application"   = $AppName
            "URL"           = $TargetUrl
            "Node Detected" = "No"
            "Framework"     = "N/A"
            "Brotli (br)"   = "N/A"
            "Evidence"      = "Skipped (Empty URL)"
            "Status"        = "Skipped"
        }
    }

    $cleanUrl = if ($TargetUrl -match '^https?://') { $TargetUrl.Trim() } else { "https://$($TargetUrl.Trim())" }
    
    $isNode = "No"
    $detectedFramework = "Unknown"
    $indicators = @()
    $usesBrotli = "No"
    $status = "Scanned"

    try {
        # Request with Accept-Encoding to see if Brotli (br) is served
        $headersToSend = @{
            "Accept-Encoding" = "gzip, deflate, br"
            "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NodeAudit/1.0"
        }

        $response = Invoke-WebRequest -Uri $cleanUrl -Method Get -Headers $headersToSend -MaximumRedirection 3 -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        
        $headers = $response.Headers
        $body = $response.Content

        # 1. Check Brotli usage
        if ($headers['Content-Encoding'] -and $headers['Content-Encoding'] -match 'br') {
            $usesBrotli = "Yes (Content-Encoding: br)"
        }

        # 2. Inspect X-Powered-By header
        if ($headers['X-Powered-By']) {
            $poweredBy = [string]$headers['X-Powered-By']
            if ($poweredBy -match 'Express') {
                $isNode = "Yes"
                $detectedFramework = "Express"
                $indicators += "Header: X-Powered-By: $poweredBy"
            } elseif ($poweredBy -match 'Next\.js') {
                $isNode = "Yes"
                $detectedFramework = "Next.js"
                $indicators += "Header: X-Powered-By: $poweredBy"
            } elseif ($poweredBy -match 'Nuxt') {
                $isNode = "Yes"
                $detectedFramework = "Nuxt"
                $indicators += "Header: X-Powered-By: $poweredBy"
            } elseif ($poweredBy -match 'NestJS') {
                $isNode = "Yes"
                $detectedFramework = "NestJS"
                $indicators += "Header: X-Powered-By: $poweredBy"
            }
        }

        # 3. Inspect Cookies
        $setCookie = [string]$headers['Set-Cookie']
        if ($setCookie) {
            if ($setCookie -match 'connect\.sid') {
                $isNode = "Yes"
                if ($detectedFramework -eq "Unknown") { $detectedFramework = "Express (connect.sid)" }
                $indicators += "Cookie: connect.sid"
            }
            if ($setCookie -match 'sails\.sid') {
                $isNode = "Yes"
                $detectedFramework = "Sails.js"
                $indicators += "Cookie: sails.sid"
            }
            if ($setCookie -match 'koa:sess') {
                $isNode = "Yes"
                $detectedFramework = "Koa"
                $indicators += "Cookie: koa:sess"
            }
        }

        # 4. Inspect Body / SSR Scripts
        if ($body) {
            if ($body -match '__NEXT_DATA__') {
                $isNode = "Yes"
                if ($detectedFramework -eq "Unknown") { $detectedFramework = "Next.js (SSR)" }
                $indicators += "DOM: __NEXT_DATA__"
            }
            if ($body -match 'window\.__NUXT__') {
                $isNode = "Yes"
                if ($detectedFramework -eq "Unknown") { $detectedFramework = "Nuxt.js (SSR)" }
                $indicators += "DOM: window.__NUXT__"
            }
            if ($body -match 'id="__remix"') {
                $isNode = "Yes"
                if ($detectedFramework -eq "Unknown") { $detectedFramework = "Remix" }
                $indicators += "DOM: Remix context"
            }
        }

        # 5. Check Server Header
        if ($headers['Server']) {
            $server = [string]$headers['Server']
            if ($server -match 'Node\.js' -or $server -match 'Node') {
                $isNode = "Yes"
                $indicators += "Header: Server: $server"
            }
        }

    } catch {
        $status = "Failed: $($_.Exception.Message)"
    }

    [PSCustomObject]@{
        "Application"   = $AppName
        "URL"           = $cleanUrl
        "Node Detected" = $isNode
        "Framework"     = if ($isNode -eq "Yes") { $detectedFramework } else { "N/A" }
        "Brotli (br)"   = $usesBrotli
        "Evidence"      = if ($indicators.Count -gt 0) { $indicators -join "; " } else { "None" }
        "Status"        = $status
    }
}

# --- Execution Logic ---

if ($Url) {
    # Single URL Mode
    Test-NodeSite -TargetUrl $Url | Format-List
} elseif ($CsvPath) {
    # Batch CSV Mode
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV path not found: $CsvPath"
        exit
    }

    $rows = Import-Csv -Path $CsvPath
    $results = foreach ($row in $rows) {
        $urlField = if ($row.'URL / Access') { $row.'URL / Access' } elseif ($row.URL) { $row.URL } else { $null }
        $appField = if ($row.'Application Name') { $row.'Application Name' } elseif ($row.Name) { $row.Name } else { "Unknown" }

        Test-NodeSite -TargetUrl $urlField -AppName $appField
    }

    $results | Format-Table -AutoSize
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nScan complete. Results saved to $OutputPath" -ForegroundColor Green
} else {
    Write-Host "Usage examples:" -ForegroundColor Yellow
    Write-Host "  Single URL: .\Check-NodeJsInventory.ps1 -Url 'https://example.com'"
    Write-Host "  From CSV:   .\Check-NodeJsInventory.ps1 -CsvPath .\applications.csv"
}
