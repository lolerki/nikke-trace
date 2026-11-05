# Synthetic cache fixtures only; no real profiles, UAC or antivirus.
$vectors = @{
    prefix = 'ACk/X2h0dHBzOi8vd3d3Lm5pa2tlbGF1bmNoZXIuY29tAAFrMmYuYWdlbmFQUklWQVRFLURPLU5PVC1SRVBPUlRQUklWQVRFLURPLU5PVC1SRVBPUlRQUklWQVRFLURPLU5PVC1SRVBPUlQoBz90LnN0YXRlUFJJVkFURS1ETy1OT1QtUkVQT1JUUFJJVkFURS1ETy1OT1QtUkVQT1JUUFJJVkFURS1ETy1OT1QtUkVQT1JUAAAAAAEAAAAAfce2/gABA3oAvAEAAAAAAQAAAABbYBW+AADBAQ8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFf7gIskdUfb'
    snappy0 = 'vAHwuwApP19odHRwczovL3d3dy5uaWtrZWxhdW5jaGVyLmNvbQABazJmLmFnZW5hUFJJVkFURS1ETy1OT1QtUkVQT1JUUFJJVkFURS1ETy1OT1QtUkVQT1JUUFJJVkFURS1ETy1OT1QtUkVQT1JUKAc/dC5zdGF0ZVBSSVZBVEUtRE8tTk9ULVJFUE9SVFBSSVZBVEUtRE8tTk9ULVJFUE9SVFBSSVZBVEUtRE8tTk9ULVJFUE9SVAAAAAABAAAAAZQI+HQAAQN6AMABAAAAAAEAAAAA15ad3gAAxQEPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABX+4CLJHVH2w=='
    snappy1 = 'vAHwQAApP19odHRwczovL3d3dy5uaWtrZWxhdW5jaGVyLmNvbQABazJmLmFnZW5hUFJJVkFURS1ETy1OT1QtUkVQT1JUERURFREVESoRKixSVCgHP3Quc3RhdGURSRFJEUkRXhFeEV4RczgtUkVQT1JUAAAAAAEAAAAByw2GNQABAnoAegAAAAABAAAAAGb31xcAAH8OAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAV/uAiyR1R9s='
    snappy2 = 'vAHwQAApP19odHRwczovL3d3dy5uaWtrZWxhdW5jaGVyLmNvbQABazJmLmFnZW5hUFJJVkFURS1ETy1OT1QtUkVQT1JUHhUAHhUAHhUAHioAHioALFJUKAc/dC5zdGF0ZR5JAB5JAB5JAB5eAB5eAB5eAB5zADgtUkVQT1JUAAAAAAEAAAABMkN+RgABA3oAhgEAAAAAAQAAAABboR0QAACLAQ8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFf7gIskdUfb'
    snappy3 = 'vAHwQAApP19odHRwczovL3d3dy5uaWtrZWxhdW5jaGVyLmNvbQABazJmLmFnZW5hUFJJVkFURS1ETy1OT1QtUkVQT1JUHxUAAAAfFQAAAB8VAAAAHyoAAAAfKgAAACxSVCgHP3Quc3RhdGUfSQAAAB9JAAAAH0kAAAAfXgAAAB9eAAAAH14AAAAfcwAAADgtUkVQT1JUAAAAAAEAAAABLhXsXAABA3oAngEAAAAAAQAAAAC2QFR/AACjAQ8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFf7gIskdUfb'
    bomb = 'gYCAIAEkevPHAAECegAEAAAAAAEAAAAA86dC3AAACQ4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABX+4CLJHVH2w=='
    invalidCopy = 'CAEAAeq8PBUAAQJ6AAMAAAAAAQAAAADENhDJAAAIDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFf7gIskdUfb'
    badCrc = 'ACk/X2h0dHBzOi8vd3d3Lm5pa2tlbGF1bmNoZXIuY29tAAFrMmYuYWdlbmFQUklWQVRFLURPLU5PVC1SRVBPUlRQUklWQVRFLURPLU5PVC1SRVBPUlRQUklWQVRFLURPLU5PVC1SRVBPUlQoBz90LnN0YXRlUFJJVkFURS1ETy1OT1QtUkVQT1JUUFJJVkFURS1ETy1OT1QtUkVQT1JUUFJJVkFURS1ETy1OT1QtUkVQT1JUAAAAAAEAAAAAfMe2/gABA3oAvAEAAAAAAQAAAABbYBW+AADBAQ8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFf7gIskdUfb'
    truncated = 'ACk/X2h0dHBzOi8vd3d3Lm5pa2tlbGF1bmNoZXIuY29tAAFrMmYuYWdlbmFQUklWQVRFLURPLU5PVC1SRVBPUlRQUklWQVRFLURPLU5PVC1SRVBPUlRQUklWQVRFLURPLU5PVC1SRVBPUlQoBz90LnN0YXRlUFJJVkFURS1ETy1OT1QtUkVQT1JUUFJJVkFURS1ETy1OT1QtUkVQT1JUUFJJVkFURS1ETy1OT1QtUkVQT1JUAAAAAAEAAAAAfce2/gABA3oAvAEAAAAAAQAAAABbYBW+AADBAQ8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
}
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = Split-Path $PSScriptRoot -Parent
$source = Join-Path $repository 'NikkeTrace.ps1'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('NikkeTrace-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$checks = 0
$oldLocal = $env:LOCALAPPDATA
$oldRoaming = $env:APPDATA
$oldTemp = $env:TEMP
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
    $script:checks++
    Microsoft.PowerShell.Utility\Write-Host "OK: $Message"
}
try {
    [void][IO.Directory]::CreateDirectory($fixture)
    . $source -Language en -NoPrompt
    $env:LOCALAPPDATA = Join-Path $fixture 'L'
    $env:APPDATA = Join-Path $fixture 'R'
    $env:TEMP = Join-Path $fixture 'T'
    foreach ($path in @($env:LOCALAPPDATA, $env:APPDATA, $env:TEMP)) {
        [void][IO.Directory]::CreateDirectory($path)
    }
    $LauncherPath = Join-Path $fixture 'NikkeTrace.cmd'
    Initialize-Report
    function Get-NikkeRemovalCandidates { @() }
    Initialize-CacheReader
    foreach ($name in @('prefix', 'snappy0', 'snappy1', 'snappy2', 'snappy3')) {
        $result = [NikkeTrace.CacheReader27]::Inspect([Convert]::FromBase64String($vectors[$name]), $true)
        Assert ($result.Complete -and 'k2f.agent.state' -in $result.Markers) "table reconstructs the marker hidden by shared keys: $name"
    }
    foreach ($name in @('bomb', 'invalidCopy', 'badCrc', 'truncated')) {
        $result = [NikkeTrace.CacheReader27]::Inspect([Convert]::FromBase64String($vectors[$name]), $true)
        Assert (-not $result.Complete) "invalid or oversized table never counts as complete: $name"
    }
    $result = [NikkeTrace.CacheReader27]::Inspect([Text.Encoding]::ASCII.GetBytes('https://notinsightjs.com insightjs.com.example.test'), $false)
    Assert ($result.Markers.Count -eq 0) 'similar domain names do not match'
    $result = [NikkeTrace.CacheReader27]::Inspect([byte[]](@(0) + [Text.Encoding]::Unicode.GetBytes('k2f.agent.state PRIVATE-DO-NOT-REPORT')), $false)
    Assert ('k2f.agent.state' -in $result.Markers) 'UTF-16 marker at odd alignment is detected'
    Assert ((Get-HstsKey 'insightjs.com') -ceq 'JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg=') 'HSTS DNS wire hash matches the known domain key'
    Assert (@(Get-LauncherCacheRoots).Count -eq 3) 'standard, HMT and Google Play Games caches are included'
    $roots = @(Get-LauncherCacheRoots)
    $root = $roots[0]
    $code = Join-Path $root 'Code Cache\js'
    $db = Join-Path $root 'Local Storage\leveldb'
    foreach ($path in @($code,$db)) {
        [void][IO.Directory]::CreateDirectory($path)
    }
    $loader = Join-Path $code 'a_0'
    [IO.File]::WriteAllText($loader,'https://insightjs.com/l.js PRIVATE-DO-NOT-REPORT')
    [IO.File]::WriteAllBytes((Join-Path $db '000001.ldb'),[Convert]::FromBase64String($vectors.snappy2))
    [IO.File]::WriteAllText((Join-Path $root 'TransportSecurity'),'{"version":2,"sts":[{"host":"wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw="}]}')
    [void][IO.Directory]::CreateDirectory($roots[2])
    [IO.File]::WriteAllText((Join-Path $roots[2] 'Network Persistent State'),'https://analytics.insightjs.com')
    $cef = Join-Path $env:LOCALAPPDATA 'CEF\User Data'
    $cefCache = Join-Path $cef 'Default\Code Cache\js'
    [void][IO.Directory]::CreateDirectory($cefCache)
    $cefTrace = Join-Path $cefCache 'b_0'
    [IO.File]::WriteAllText($cefTrace,'https://insightjs.org/')
    $cefLogins = Join-Path $cef 'Default\Login Data'
    [IO.File]::WriteAllText($cefLogins,'k2f_chan PRIVATE-DO-NOT-REPORT')
    $cefHash = (Get-FileHash -LiteralPath $cefTrace).Hash
    $loginHash = (Get-FileHash -LiteralPath $cefLogins).Hash
    $before = Invoke-CacheSnapshot
    Assert ($before.Checks[0].State -eq 'Effectué' -and $before.Findings.Count -eq 5) 'cache-only scan finds compressed storage, script, HSTS, Google network and CEF traces without the game'
    Assert (@($before.Findings | Where-Object {
                $_.Strong
            }).Count -eq 1) 'domain contact is historical evidence, not proof the agent ran'
    Assert (@($before.Findings | Where-Object {
                $_.Target.SharedCache
            }).Count -eq 1) 'shared CEF trace is explicitly identified'
    Assert (@($before.Findings | Where-Object {
                $_.Target.Path -eq $cefLogins
            }).Count -eq 0) 'CEF login database is never inspected'
    Assert (($Report -join "`n") -notmatch 'PRIVATE-DO-NOT-REPORT') 'no cache values or log secrets enter the report'
    Assert (@(Get-CleanupPlan $before).Count -eq 0) 'cache deletion has no implicit authorization from generic cleanup'
    $lock = [IO.File]::Open($loader,'Open','ReadWrite','None')
    try {
        $incomplete = Invoke-CacheSnapshot
        Assert ($incomplete.Checks[0].State -eq 'Partiel') 'locked cache marks coverage partial'
        [void](Compare-TraceSnapshots $before $incomplete)
        Assert (@($incomplete.Findings | Where-Object {
                    $_.Target.Path -eq $loader -and $_.Target.ContainsKey('Unverified')
                }).Count -eq 1) 'previous marker survives an unreadable recheck'
    } finally {
        $lock.Dispose()
    }

    function Get-Process {
        param($ErrorAction) @()
    }
    $rejected = $false
    try {
        Remove-NikkeCache $cef (Join-Path $fixture 'missing-report.txt')
    } catch {
        $rejected = $true
    }
    Assert ($rejected -and (Test-Path -LiteralPath $cefTrace)) 'shared CEF profile cannot enter cache deletion'
    $rejected = $false
    try {
        Remove-NikkeCache $root (Join-Path $fixture 'missing-report.txt')
    } catch {
        $rejected = $true
    }
    Assert ($rejected -and (Test-Path -LiteralPath $loader)) 'missing report prevents deletion'
    $reportInCache = Join-Path $root 'report.txt'
    [IO.File]::WriteAllText($reportInCache,'report')
    $rejected = $false
    try {
        Remove-NikkeCache $root $reportInCache
    } catch {
        $rejected = $true
    }
    Assert ($rejected -and (Test-Path -LiteralPath $loader)) 'report inside the cache cannot satisfy the backup requirement'

    $script:answers = New-Object 'System.Collections.Generic.Queue[string]'
    $script:shown = New-Object 'System.Collections.Generic.List[object]'
    function Write-Host {
        param($Object,[ConsoleColor]$ForegroundColor='Gray') $script:shown.Add([pscustomobject]@{
                Text=(Convert-UiText ([string]$Object));Color=$ForegroundColor
            })
    }
    function Read-Host {
        param($Prompt) if(-not [IO.File]::Exists($script:ReportPath)){
            throw 'Consent requested before report was saved'
        }
        $script:answers.Dequeue()
    }
    $script:answers.Enqueue('n')
    [void](Invoke-GuidedCleanup)
    Assert ((Test-Path -LiteralPath $loader) -and (Test-Path -LiteralPath $script:ReportPath)) 'declined deletion keeps cache and saves report before consent'
    Assert (([IO.File]::ReadAllText($script:ReportPath)) -match 'k2f.agent.state' -and ([IO.File]::ReadAllText($script:ReportPath)) -notmatch 'PRIVATE-DO-NOT-REPORT') 'saved report preserves indicators without their secret values'
    function Get-Process {
        param($ErrorAction) [pscustomobject]@{
            ProcessName='nikke_launcher'
            SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId
        }
    }
    $shown.Clear()
    $script:answers.Enqueue('y')
    [void](Invoke-GuidedCleanup)
    Assert ((Test-Path -LiteralPath $loader) -and @($shown | Where-Object {
                $_.Color -eq 'Green'
            }).Count -eq 0) 'running launcher blocks deletion without a green success message'
    function Get-Process {
        param($ErrorAction) @()
    }

    $outside = Join-Path $fixture 'OtherApp'
    [void][IO.Directory]::CreateDirectory($outside)
    $keep = Join-Path $outside 'keep.txt'
    [IO.File]::WriteAllText($keep,'DO NOT DELETE')
    $junction = Join-Path $root 'redirected'
    New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
    $rejected = $false
    try {
        Remove-NikkeCache $root $script:ReportPath
    } catch {
        $rejected = $true
    }
    Assert ($rejected -and (Test-Path -LiteralPath $keep) -and (Test-Path -LiteralPath $loader)) 'junction inside cache prevents deletion and preserves the other application'
    [IO.Directory]::Delete($junction,$false)
    $shown.Clear()
    $script:answers.Enqueue('y')
    [void](Invoke-GuidedCleanup)
    Assert (-not (Test-Path -LiteralPath $root) -and -not (Test-Path -LiteralPath $roots[2])) 'confirmed deletion removes only the existing NIKKE caches'
    Assert ((Get-FileHash -LiteralPath $cefTrace).Hash -ceq $cefHash -and (Get-FileHash -LiteralPath $cefLogins).Hash -ceq $loginHash -and (Test-Path -LiteralPath $keep)) 'CEF profile, its credentials database and other application stay intact'
    Assert (@(Get-ChildItem -LiteralPath (Split-Path $root) -Filter '*.NikkeTrace-delete-*').Count -eq 0) 'successful deletion leaves no staging copy'
    Assert (@($script:CurrentSnapshot.Findings | Where-Object { $_.Target.SharedCache }).Count -eq 1 -and ($shown.Text -join "`n") -match 'historical trace') 'post-deletion result retains the shared profile trace without requiring technical knowledge'
    Assert ($script:HistoricalExposure -and $script:SessionExposure) 'deleting cache does not erase the prior exposure warning'
    Assert (@($shown | Where-Object {
                $_.Color -eq 'Green' -and $_.Text -match 'cache deleted; absence confirmed'
            }).Count -eq 2) 'success is reported separately for each verified deleted cache'
    [void][IO.Directory]::CreateDirectory($code)
    [IO.File]::WriteAllText($loader,'https://insightjs.com/')
    $savedSave = ${function:Save-Report}
    function Save-Report {
        param([switch]$Required) throw 'Simulated report failure'
    }
    $shown.Clear()
    [void](Invoke-GuidedCleanup)
    Assert ((Test-Path -LiteralPath $loader) -and $answers.Count -eq 0 -and ($shown.Text -join "`n") -match 'Report not saved') 'report failure prevents even asking for destructive consent'
    Set-Item Function:\Save-Report -Value $savedSave
    $script:CurrentSnapshot=Invoke-CacheSnapshot
    $lock = [IO.File]::Open($loader,'Open','ReadWrite','None')
    try {
        $shown.Clear()
        $answers.Enqueue('y')
        [void](Invoke-GuidedCleanup)
        Assert ((Test-Path -LiteralPath $loader) -and @($shown | Where-Object {
                    $_.Color -eq 'Green'
                }).Count -eq 0) 'locked cache file prevents confirmed deletion and never produces a green result'
        Assert (@($script:CurrentSnapshot.Findings | Where-Object {
                    $_.Target.Path -eq $loader -and $_.Target.ContainsKey('Unverified')
                }).Count -eq 1) 'known result survives failures in both pre-deletion and post-deletion reads'
    } finally {
        $lock.Dispose()
    }
    $network = Join-Path $root 'TransportSecurity'
    [IO.File]::WriteAllText($network,'{"sts":["invalid-entry"]}')
    $partial = Invoke-CacheSnapshot
    Assert ($partial.Checks[0].State -eq 'Partiel') 'malformed HSTS records cannot silently count as a completed check'
    $script:Language='fr'
    Assert ((Convert-UiText 'Supprimer définitivement ces caches NIKKE ?') -eq 'Supprimer définitivement ces caches NIKKE ?') 'French destructive confirmation stays available'
    $script:Language='en'
    Assert ((Convert-UiText 'Supprimer définitivement ces caches NIKKE ?') -eq 'Permanently delete these NIKKE launcher caches?') 'English destructive confirmation is explicit'
    Microsoft.PowerShell.Utility\Write-Host "SUCCESS: $checks cache detection and deletion checks on inert fixtures only."
} finally {
    $env:LOCALAPPDATA = $oldLocal
    $env:APPDATA = $oldRoaming
    $env:TEMP = $oldTemp
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
