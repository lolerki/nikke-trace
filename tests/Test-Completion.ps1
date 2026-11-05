# Synthetic installations, old tool copies and mocked Settings only. No real uninstall or user data access.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('NikkeTrace-finish-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$oldLocal = $env:LOCALAPPDATA
$oldRoaming = $env:APPDATA
$oldTemp = $env:TEMP
$checks = 0
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:checks++
}
try {
    [void][IO.Directory]::CreateDirectory($fixture)
    . (Join-Path $repository 'NikkeTrace.ps1') -NoPrompt -Language en
    $env:LOCALAPPDATA = Join-Path $fixture 'Local'
    $env:APPDATA = Join-Path $fixture 'Roaming'
    $env:TEMP = Join-Path $fixture 'Temp'
    foreach ($path in @($env:LOCALAPPDATA, $env:APPDATA, $env:TEMP)) { [void][IO.Directory]::CreateDirectory($path) }
    Initialize-Report
    $script:answers = New-Object 'System.Collections.Generic.Queue[string]'
    $script:shown = New-Object 'System.Collections.Generic.List[string]'
    $script:opened = New-Object 'System.Collections.Generic.List[string]'
    function Write-Host { param($Object, [ConsoleColor]$ForegroundColor = 'Gray') $script:shown.Add((Convert-UiText ([string]$Object))) }
    function Read-Host { param($Prompt) if ($script:answers.Count -eq 0) { throw 'Unexpected question' }; $script:answers.Dequeue() }
    function Get-Process { param($ErrorAction) @() }
    function Start-Process { param($FilePath, $ErrorAction) $script:opened.Add($FilePath) }

    $installs = @()
    foreach ($variant in @('nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google')) {
        $root = Join-Path $fixture ("SyntheticNIKKE-$variant")
        [void][IO.Directory]::CreateDirectory((Join-Path $root 'Launcher\intl_service'))
        [IO.File]::WriteAllText((Join-Path $root "Launcher\$variant.exe"), 'INERT EXECUTABLE NAME ONLY')
        Assert ((Get-ConfirmedNikkeFolder $root) -eq $root) "installation recognized: $variant"
        $installs += $root
    }
    function Get-NikkeInstallPaths { $installs }
    $script:ScanPaths = $installs
    Assert (@(Get-NikkeRemovalCandidates).Count -eq 3) 'all installation variants are discovered without registry reads'
    $answers.Enqueue('n')
    Assert ((Offer-NikkeUninstall $installs) -eq 'Declined' -and $opened.Count -eq 0) 'declining uninstall opens nothing'
    $answers.Enqueue('y')
    Assert ((Offer-NikkeUninstall $installs) -eq 'Opened' -and $opened.Count -eq 1 -and $opened[0] -eq 'ms-settings:appsfeatures') 'consent opens only the fixed Windows uninstall page'
    Assert (@($script:CleanupOutcomes | Where-Object { $_.Outcome -eq 'Done' }).Count -eq 0) 'opening Settings never claims a completed uninstall'
    Assert (@($installs | Where-Object { Test-Path -LiteralPath $_ }).Count -eq 3 -and @(Get-ChildItem -LiteralPath $fixture -Directory -Filter '*.NIKKE-quarantaine-*').Count -eq 0) 'uninstall guidance neither renames nor deletes installation folders'
    function Start-Process { param($FilePath, $ErrorAction) throw 'INERT SETTINGS FAILURE' }
    $answers.Enqueue('y')
    Assert ((Offer-NikkeUninstall $installs) -eq 'Failed') 'Settings failure is reported instead of claiming removal'
    $quoted = '"' + (Join-Path $installs[2] 'Launcher\nikke_launcher_google.exe') + '",0'
    Assert ((Get-NikkeLauncherDirectory $quoted) -eq (Join-Path $installs[2] 'Launcher')) 'quoted Google launcher icon path is parsed without executing it'
    Assert (@(Get-NikkeLauncherDirectory 'C:\unrelated.exe --anything').Count -eq 0) 'unrelated executable commands are not installation paths'

    $payload = Join-Path $installs[2] 'Launcher\log\tinyget\tinyget.20261103-123456.log'
    [void][IO.Directory]::CreateDirectory((Split-Path $payload))
    [IO.File]::WriteAllBytes($payload, (New-Object byte[] 205135))
    Initialize-Report
    Test-LogFile $payload
    $payloadFinding = @($script:Findings | Where-Object { $_.Target.ContainsKey('OfficialPayload') })
    Assert ($payloadFinding.Count -eq 1 -and -not $payloadFinding[0].Strong -and @(Get-CleanupPlan ([pscustomobject]@{ Findings = $payloadFinding })).Count -eq 1) 'complete official filename, size and installation criteria permit a separately described cleanup'
    $stream = [IO.File]::OpenWrite($payload)
    try { $stream.WriteByte(1) } finally { $stream.Dispose() }
    $blocked = $false
    try { Remove-ConfirmedFile $payloadFinding[0] } catch { $blocked = $true }
    Assert ($blocked -and (Test-Path -LiteralPath $payload)) 'changed official-criteria payload is not deleted'
    Initialize-Report
    Test-LogFile $payload
    Remove-ConfirmedFile $script:Findings[0]
    Assert (-not (Test-Path -LiteralPath $payload)) 'unchanged official-criteria fixture is deleted permanently'
    $lua = Join-Path (Split-Path $payload) 'k2f.lua'
    [IO.File]::WriteAllText($lua, 'INERT UNKNOWN LUA CONTENT')
    Initialize-Report
    Test-NikkePath $installs[2]
    Assert (@($script:Findings | Where-Object { $_.Location -eq $lua }).Count -eq 1 -and @(Get-CleanupPlan ([pscustomobject]@{ Findings = @($script:Findings.ToArray()) })).Count -eq 0 -and $script:LogsRead -eq 0) 'old Lua filename is visible without assuming execution or deleting unknown content'

    $nested = Join-Path $env:TEMP 'a\b'
    [void][IO.Directory]::CreateDirectory($nested)
    $tempNames = @('k2f-keyscan-123.db', 'k2f_screen_123_1.png', 'k2f_bcreds_123_2.db-wal')
    foreach ($name in $tempNames) { [IO.File]::WriteAllText((Join-Path $nested $name), 'INERT TEMP DATA') }
    [IO.File]::WriteAllText((Join-Path $nested 'k2f-not-agent.tmp'), 'INERT UNRELATED TEMP')
    [IO.File]::WriteAllText((Join-Path $nested 'k2f-bcreds-not-a-database.txt'), 'INERT UNCERTAIN NAME')
    Initialize-Report
    Test-TemporaryFiles
    $tempPlan = @(Get-CleanupPlan ([pscustomobject]@{ Findings = @($script:Findings.ToArray()) }))
    Assert ($tempPlan.Count -eq 3) 'nested temporary variants are recognized while unrelated or uncertain names are not cleanup targets'
    foreach ($action in $tempPlan) { Remove-ConfirmedFile $action.Finding }
    Assert ((Test-Path -LiteralPath (Join-Path $nested 'k2f-not-agent.tmp')) -and (Test-Path -LiteralPath (Join-Path $nested 'k2f-bcreds-not-a-database.txt'))) 'expanded temporary cleanup preserves unrelated and uncertain files'

    $original = Join-Path $env:LOCALAPPDATA ('Google\Chrome\User Data\PlatformExperienceHelper\' + ('a' * 64) + '\platform_experience_helper.dll')
    $legacyRoot = Join-Path $env:LOCALAPPDATA ('NIKKE-Assistance\Quarantaine\' + ('b' * 32))
    [void][IO.Directory]::CreateDirectory($legacyRoot)
    $copy = Join-Path $legacyRoot (('c' * 32) + '.quarantaine')
    [IO.File]::WriteAllText($copy, 'INERT LEGACY COPY')
    @{ Source = $original; Destination = $copy; Date = 'synthetic' } | ConvertTo-Json | Set-Content -LiteralPath ($copy + '.json') -Encoding UTF8
    Initialize-Report
    Test-LegacyQuarantine
    $copyFinding = @($script:Findings | Where-Object { $_.Target.ContainsKey('LegacySource') })
    Assert ($copyFinding.Count -eq 1 -and @(Get-CleanupPlan ([pscustomobject]@{ Findings = $copyFinding })).Count -eq 1) 'old quarantine copy with a matching record is offered for cleanup'
    [IO.File]::WriteAllText($copy, 'INERT CHANGED LEGACY COPY')
    $blocked = $false
    try { Remove-ConfirmedFile $copyFinding[0] } catch { $blocked = $true }
    Assert ($blocked -and (Test-Path -LiteralPath $copy)) 'legacy copy changed after checking is preserved'
    Initialize-Report
    Test-LegacyQuarantine
    Remove-ConfirmedFile $script:Findings[0]
    Assert (-not(Test-Path -LiteralPath $copy) -and (Test-Path -LiteralPath ($copy + '.json'))) 'recognized old copy is deleted while its non-executable record is kept'
    [IO.File]::WriteAllText($copy, 'INERT UNIDENTIFIED COPY')
    [IO.File]::WriteAllText(($copy + '.json'), '{invalid')
    Initialize-Report
    Test-LegacyQuarantine
    Assert (@(Get-CleanupPlan ([pscustomobject]@{ Findings = @($script:Findings.ToArray()) })).Count -eq 0 -and $script:Issues.Count -gt 0 -and (Test-Path -LiteralPath $copy)) 'invalid old-copy records cannot authorize deletion or a reassuring negative result'

    $archive = $installs[0] + '.NIKKE-quarantaine-abcd1234'
    [void][IO.Directory]::CreateDirectory((Join-Path $archive 'Launcher\intl_service'))
    [IO.File]::WriteAllText((Join-Path $archive 'Launcher\nikke_launcher.exe'), 'INERT OLD INSTALLATION')
    $recordFolder = Join-Path $env:LOCALAPPDATA ('NIKKE-Assistance\Sauvegardes\' + ('d' * 32))
    [void][IO.Directory]::CreateDirectory($recordFolder)
    @{ Source = $installs[0]; Destination = $archive } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $recordFolder 'retrait-jeu.json') -Encoding UTF8
    Initialize-Report
    Test-LegacyInstallationCopies
    Assert (@($script:Findings | Where-Object { $_.Location -eq $archive }).Count -eq 1 -and @(Get-CleanupPlan ([pscustomobject]@{ Findings = @($script:Findings.ToArray()) })).Count -eq 0 -and (Test-Path -LiteralPath $archive)) 'old renamed installations are explicitly reported without recursive deletion'

    $chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\PlatformExperienceHelper'
    [void][IO.Directory]::CreateDirectory($chrome)
    foreach ($name in @('platform_experience_helper.dll.old', 'old-clsid.txt', 'platform_experience_helper.exe')) { [IO.File]::WriteAllText((Join-Path $chrome $name), 'INERT LEGACY OR LEGITIMATE FILE') }
    function Get-AdditionalChromeRoots { $chrome }
    Initialize-Report
    Test-BrowserFiles
    Assert (@($script:Findings | Where-Object { $_.Location -like "$chrome*" }).Count -eq 2 -and @(Get-CleanupPlan ([pscustomobject]@{ Findings = @($script:Findings.ToArray()) })).Count -eq 0) 'legacy Chrome filenames are checked without deleting unknown files or flagging the legitimate helper'
    $localCache = Join-Path $env:LOCALAPPDATA 'nikke_launcher_google\tbs_cache\Code Cache\js\inert'
    [void][IO.Directory]::CreateDirectory((Split-Path $localCache))
    [IO.File]::WriteAllText($localCache, 'insightjs.com')
    Initialize-Report
    $cache = Invoke-CacheSnapshot
    Assert (@($cache.Findings | Where-Object { $_.Location -eq $localCache -and $_.Target.SharedCache }).Count -eq 1 -and (Test-Path -LiteralPath $localCache)) 'additional LocalAppData launcher cache is checked read-only'

    $script:session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    function Get-Process { param($ErrorAction) foreach ($name in @('nikke_launcher_google', 'nikke_launcher_hmt')) { [pscustomobject]@{ ProcessName = $name; SessionId = $script:session } } }
    Assert (@(Get-SessionProcesses).Count -eq 2) 'Google and HMT launchers are included in scoped process checks'
    $blocked = $false
    try { Assert-LauncherClosed } catch { $blocked = $true }
    Assert $blocked 'running alternate launchers still block cache deletion'
    Microsoft.PowerShell.Utility\Write-Host "SUCCESS: $checks completion checks on inert fixtures only."
} finally {
    $env:LOCALAPPDATA = $oldLocal
    $env:APPDATA = $oldRoaming
    $env:TEMP = $oldTemp
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
