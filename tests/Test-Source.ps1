# Run against inert fixtures only. Do not scan the actual computer.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = Split-Path $PSScriptRoot -Parent
$source = Join-Path $repository 'NikkeTrace.ps1'
$fixture = Join-Path $PSScriptRoot ('fixtures-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$checks = 0
$savedLocal = $env:LOCALAPPDATA
$savedTemp = $env:TEMP

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
    $script:checks++
    Microsoft.PowerShell.Utility\Write-Host "OK: $Message"
}

try {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0) 'Windows PowerShell syntax is valid'
    $text = [IO.File]::ReadAllText($source)
    Assert ($text -notmatch '(?i)[a-z]:\\Users\\(?!Public\\|Default\\|\$|%)[^\\\s''"]+\\|/mnt/[a-z]/[Uu]sers/') 'source has no hardcoded personal profile path'
    Assert ($text -notmatch '-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}') 'source has no recognizable private key or GitHub token'
    . $source -NoPrompt
    Assert ($script:Language -eq 'en') 'English is the default language'
    Assert ((Convert-UiText '0  Quitter') -eq '0  Quit') 'default interface is English'
    $script:Language = 'fr'
    Assert ((Convert-UiText '0  Quitter') -eq '0  Quitter') 'French remains available'
    $script:Language = 'en'
    Initialize-Report
    Assert ($Findings.Count -eq 0) 'loading the source does not perform a scan'

    [void][IO.Directory]::CreateDirectory($fixture)
    $env:LOCALAPPDATA = $fixture
    $env:TEMP = Join-Path $fixture 'Temp'
    [void][IO.Directory]::CreateDirectory($env:TEMP)
    $log = Join-Path $fixture 'debug.log'
    [IO.File]::WriteAllText($log, "k2f_chan registered PRIVATE-LOG-VALUE`r`n")
    Test-LogFile $log
    Assert ($Findings.Count -eq 1 -and $Findings[0].Strong) 'known log marker is detected without any installed game'
    Assert (($Report -join "`n") -notmatch 'PRIVATE-LOG-VALUE') 'log secrets are not copied into reports'
    Initialize-Report
    Test-LogFile (Join-Path $fixture 'missing.log')
    Assert ($Issues.Count -eq 1 -and $LogsRead -eq 0) 'a failed log read is recorded as an issue'

    Initialize-Report
    $helper = Join-Path $fixture 'Google\Chrome\User Data\PlatformExperienceHelper'
    [void][IO.Directory]::CreateDirectory($helper)
    $legitimate = Join-Path $helper 'platform_experience_helper.exe'
    $configuration = Join-Path $helper 'LoadFeatures'
    [IO.File]::WriteAllText($legitimate, 'INERT LEGITIMATE FILE')
    [IO.File]::WriteAllText($configuration, 'KEEP THIS CONFIGURATION')
    $beforeExe = (Get-FileHash -LiteralPath $legitimate).Hash
    $beforeConfiguration = (Get-FileHash -LiteralPath $configuration).Hash
    $root = Join-Path $fixture 'Google\Chrome\User Data'
    $script:BrowserCheckMap['Chrome'] = [pscustomobject]@{
        Attempted = New-Object 'System.Collections.Generic.List[string]'
        Paths = New-Object 'System.Collections.Generic.List[string]'
        Reasons = New-Object 'System.Collections.Generic.List[string]'
        State = 'Absent'
    }
    Test-BrowserRoot 'Chrome' $root $true
    Assert ($Findings.Count -eq 0) 'helper directory and executable alone are not flagged'

    $dll = Join-Path $root 'platform_experience_helper.dll'
    [IO.File]::WriteAllText($dll, 'INERT DLL WITH A SIMILAR NAME')
    $script:BrowserCheckMap['Chrome'].Attempted.Clear()
    Test-BrowserRoot 'Chrome' $root $true
    Assert ($Findings.Count -eq 1) 'a matching DLL name outside the known path remains visible for review'
    $snapshot = [pscustomobject]@{ Findings = @($Findings.ToArray()) }
    Assert (@(Get-CleanupPlan $snapshot).Count -eq 0) 'a filename outside the documented path does not authorize quarantine'
    Assert ((Test-Path -LiteralPath $dll) -and (Get-FileHash -LiteralPath $legitimate).Hash -eq $beforeExe -and (Get-FileHash -LiteralPath $configuration).Hash -eq $beforeConfiguration) 'uncertain DLL and legitimate files are preserved'

    Initialize-Report
    $com = 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32'
    Test-PersistenceValue $com '' 'C:\Windows\System32\wpc.dll' 'fake HKLM entry' @{ Hive = 'LocalMachine' }
    Assert ($Findings.Count -eq 0) 'legitimate Windows HKLM CLSID is not flagged'
    Test-PersistenceValue $com '' $dll 'fake HKCU entry' @{ Hive = 'CurrentUser'; View = 'Registry64'; SubKey = $com; Name = '' }
    Assert ($Findings.Count -eq 1 -and @(Get-CleanupPlan ([pscustomobject]@{ Findings = @($Findings.ToArray()) })).Count -eq 0) 'unknown registry destination is reported without authorizing removal'
    Microsoft.PowerShell.Utility\Write-Host "SUCCESS: $checks source and safety checks on fixtures only."
} finally {
    $env:LOCALAPPDATA = $savedLocal
    $env:TEMP = $savedTemp
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
