# All operating-system writes stay inside inert fixtures. Registry operations and boot identifiers are mocked.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('NikkeTrace-flow-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$oldLocal = $env:LOCALAPPDATA
$oldRoaming = $env:APPDATA
$oldTemp = $env:TEMP
$checks = 0
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
    $script:checks++
    Microsoft.PowerShell.Utility\Write-Host "OK: $Message"
}
function Snapshot([object[]]$Rows = @(), [switch]$Partial) {
    $groups = @('Journaux NIKKE', 'Fichiers des navigateurs', 'Registre', 'Fichiers temporaires', 'Cache NIKKE', 'Programmes en cours', 'Connexions', 'DNS', 'Hosts')
    $states = @()
    foreach ($group in $groups) {
        $states += [pscustomobject]@{
            Name=$group
            State=$(if($Partial -and $group -eq 'Cache NIKKE'){
                    'Partiel'
                }else{
                    'Effectué'
                })
            Reasons=@()
        }
    }
    [pscustomobject]@{
        Findings = $Rows
        Issues = @()
        Checks = $states
        ScopeMode = 'Verifier'
        ScopeBrowser = 'Tous'
        LogsRead = 0
        BrowserRoots = 0
        HistoryStatus = 'Indetermine'
        CheckedBrowsers = @()
        GameRemoved = $true
    }
}
try {
    [void][IO.Directory]::CreateDirectory($fixture)
    . (Join-Path $repository 'NikkeTrace.ps1') -Language en -NoPrompt
    $env:LOCALAPPDATA=Join-Path $fixture 'L'
    $env:APPDATA=Join-Path $fixture 'R'
    $env:TEMP=Join-Path $fixture 'T'
    foreach($path in @($env:LOCALAPPDATA,$env:APPDATA,$env:TEMP)){
        [void][IO.Directory]::CreateDirectory($path)
    }
    Initialize-Report
    $script:shown=New-Object 'System.Collections.Generic.List[object]'
    $script:events=New-Object 'System.Collections.Generic.List[string]'
    $script:answers=New-Object 'System.Collections.Generic.Queue[string]'
    $script:boot='boot-one'
    $script:scanCalls=0
    function Write-Host {
        param($Object,[ConsoleColor]$ForegroundColor='Gray')$script:shown.Add([pscustomobject]@{
                Text=(Convert-UiText ([string]$Object));Color=$ForegroundColor
            })
    }
    function Read-Host {
        param($Prompt)if($script:answers.Count -eq 0){
            throw 'Unexpected question'
        }
        $script:answers.Dequeue()
    }
    function Get-CleanupBootId {
        $script:boot
    }
    function Get-NikkeRemovalCandidates {
        @()
    }
    function Get-NikkeInstallPaths {
        @()
    }
    function Get-NikkeResidualPaths {
        @()
    }
    function Get-Process {
        param($ErrorAction)@()
    }
    function Offer-BrowserClosure {
        param($Scope)
    }
    function Invoke-TraceScan {
        $script:scanCalls++
        $script:events.Add('scan')
        Snapshot
    }

    $clean=Snapshot
    Assert ((Get-SnapshotConclusion $clean).Color -eq 'Green') 'all completed checks without findings give the scoped green result'
    $partial=Snapshot -Partial
    Assert ((Get-SnapshotConclusion $partial).Color -eq 'Yellow') 'one incomplete check never produces a green negative result'
    Assert ((Get-ResultCounts $partial).Completed -eq 8 -and (Get-ResultCounts $partial).Incomplete -eq 1) 'readable counts reflect the actual groups'
    $historical=[pscustomobject]@{
        Id='historical'
        Type='Historique'
        Strong=$true
        Kind='test'
        Location='fake'
        Target=@{
            Path='fake'
            Marker='k2f_chan'
        }
    }
    $past=Snapshot @($historical)
    Assert ((Get-SnapshotConclusion $past).Color -eq 'Yellow' -and (Get-ResultCounts $past).Current -eq 0) 'historical exposure is distinguished from current artifacts'
    $none=Snapshot
    foreach($check in $none.Checks){
        $check.State='Partiel'
    }
    Assert ((Get-SnapshotConclusion $none).Color -eq 'Gray') 'no completed check never certifies absence'
    $visible=@(Get-PlayerSummary $partial | ForEach-Object {
            Convert-UiText $_
        }) -join "`n"
    Assert ($visible -match 'incomplete: 1' -and $visible -notmatch '\bCEF\b|\bDLL\b|LevelDB|hosts') 'recommended summary needs no technical vocabulary'
    Add-CleanupOutcome 'Failed' 'test failure' 'inert path'
    Assert ((Get-SnapshotConclusion $clean).Color -eq 'Yellow') 'a failed cleanup cannot hide behind an otherwise negative complete scan'
    Add-CleanupOutcome 'Done' 'test success' 'inert path'
    Assert ((Get-SnapshotConclusion $clean).Color -eq 'Green') 'a later confirmed action resolves the matching previous failure'
    $script:CleanupOutcomes.Clear()

    $root=@(Get-LauncherCacheRoots)[0]
    $cacheFile=Join-Path $root 'Code Cache\js\a_0'
    [void][IO.Directory]::CreateDirectory((Split-Path $cacheFile))
    [IO.File]::WriteAllText($cacheFile,'normal cache')
    $script:CurrentSnapshot=Snapshot
    $answers.Enqueue('y')
    $result=Invoke-GuidedCleanup
    Assert ($result -eq 'Completed' -and -not(Test-Path -LiteralPath $root)) 'one guided cleanup offers a precautionary cache reset without any installed game'
    Assert ($scanCalls -eq 1) 'cleanup automatically performs a fresh final check'
    Assert (($shown.Text -join "`n") -match 'precaution') 'cache presence is not described as an infection'
    $report=[IO.File]::ReadAllText($script:ReportPath)
    Assert ($report.StartsWith('NIKKETRACE 3.0') -and $report -match 'Completed checks: 9' -and $report -match 'Confirmed actions: 1') 'report starts with a player-readable final summary and action counts'
    Assert (($report.IndexOf('TECHNICAL DETAILS')) -gt $report.IndexOf('RECOMMENDED ACTIONS')) 'technical details follow the readable recommendations'

    Initialize-Report
    $dll=Join-Path $env:LOCALAPPDATA ('Google\Chrome\User Data\PlatformExperienceHelper\'+('a'*64)+'\platform_experience_helper.dll')
    [void][IO.Directory]::CreateDirectory((Split-Path $dll))
    [IO.File]::WriteAllText($dll,'INERT KNOWN-PATH FILE')
    $dllHash=(Get-FileHash -LiteralPath $dll).Hash
    $fileFinding=[pscustomobject]@{
        Id='file'
        Kind='test'
        Type='Fichier'
        Strong=$true
        Location=$dll
        Target=@{
            Path=$dll
            Browser='Chrome'
            Sha256=$dllHash
        }
    }
    $target=@{
        Hive='CurrentUser'
        View='Registry64'
        SubKey='Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32'
        Name=''
        Fingerprint='inert'
        KnownChromeOverride=$true
    }
    $registryFinding=[pscustomobject]@{
        Id='registry'
        Kind='test'
        Type='Registre'
        Strong=$true
        Location='fake HKCU entry'
        Target=$target
    }
    $nativeMove=${function:Move-TraceToQuarantine}
    function Move-TraceToQuarantine {
        param($Finding,$Folder)$script:events.Add('file')
        & $nativeMove $Finding $Folder
    }
    $script:registryCalls=0
    function Remove-KnownRegistryOverride {
        param($Target,$BackupPath)$script:registryCalls++
        $script:events.Add('registry')
        [IO.File]::WriteAllText($BackupPath,'INERT REGISTRY BACKUP')
        return $true
    }
    $script:CurrentSnapshot=Snapshot @($fileFinding,$registryFinding)
    $answers.Enqueue('n')
    Assert ((Invoke-GuidedCleanup) -eq 'Declined' -and $registryCalls -eq 0 -and (Test-Path -LiteralPath $dll)) 'refusing the combined cleanup authorizes no registry or file change'
    [void][IO.Directory]::CreateDirectory((Split-Path $cacheFile))
    [IO.File]::WriteAllText($cacheFile,'normal cache')
    $events.Clear()
    $answers.Enqueue('y')
    $result=Invoke-GuidedCleanup
    Assert ($result -eq 'RestartRequired' -and $registryCalls -eq 1) 'startup entry removal pauses the workflow for a restart'
    Assert ((Test-Path -LiteralPath $dll) -and (Test-Path -LiteralPath $root) -and $events.Count -eq 1) 'file and cache remain untouched in the registry-removal phase'
    Assert ((Get-CleanupRestartState) -eq 'Required' -and (Test-Path -LiteralPath (Get-CleanupStatePath))) 'private checkpoint persists the required boot change'
    $beforeCalls=$registryCalls
    Assert ((Invoke-GuidedCleanup) -eq 'RestartRequired' -and $registryCalls -eq $beforeCalls -and $answers.Count -eq 0) 'rerunning without reboot cannot bypass the restart barrier or act on pending files'
    $script:boot='boot-two'
    Assert ((Get-CleanupRestartState) -eq 'Observed') 'a different boot identifier enables continuation'
    $script:CurrentSnapshot=Snapshot @($fileFinding)
    $answers.Enqueue('y')
    $result=Invoke-GuidedCleanup
    Assert ($result -eq 'Completed' -and -not(Test-Path -LiteralPath $dll) -and -not(Test-Path -LiteralPath $root)) 'after restart, a fresh confirmation permits file quarantine and cache reset'
    Assert (($events -join ',') -eq 'registry,file,scan') 'registry mutation precedes the boot barrier, file removal and fresh verification'
    Assert ((Get-CleanupRestartState) -eq 'None') 'successful continuation clears the restart checkpoint'

    Initialize-Report
    [IO.File]::WriteAllText($dll,'INERT LOCKED FILE')
    $fileFinding.Target.Sha256=(Get-FileHash -LiteralPath $dll).Hash
    $script:CurrentSnapshot=Snapshot @($fileFinding)
    $lock=[IO.File]::Open($dll,'Open','ReadWrite','None')
    try {
        $shown.Clear()
        $answers.Enqueue('y')
        $result=Invoke-GuidedCleanup
        Assert ($result -eq 'Failed' -and (Test-Path -LiteralPath $dll)) 'a locked file is reported as a partial or failed cleanup'
        Assert (@($CleanupOutcomes | Where-Object {
                    $_.Outcome -eq 'Failed'
                }).Count -eq 1) 'the final action counts retain the failed mutation'
        Assert (@($script:CurrentSnapshot.Findings | Where-Object {
                    $_.Id -eq 'file'
                }).Count -eq 1) 'fresh negative output cannot discard a still-present previously found file'
    } finally {
        $lock.Dispose()
    }

    Initialize-Report
    $fileFinding.Target.Sha256=(Get-FileHash -LiteralPath $dll).Hash
    $script:CurrentSnapshot=Snapshot @($fileFinding)
    $savedScan=${function:Invoke-TraceScan}
    function Invoke-TraceScan {
        throw 'Simulated complete recheck failure'
    }
    $answers.Enqueue('y')
    Assert ((Invoke-GuidedCleanup) -eq 'Failed' -and -not(Test-Path -LiteralPath $dll)) 'successful file isolation followed by a failed recheck is not reported as completed cleanup'
    Assert ((Get-SnapshotConclusion $script:CurrentSnapshot).Color -ne 'Green') 'an interrupted final scan cannot produce a reassuring global result'
    Set-Item Function:\Invoke-TraceScan -Value $savedScan
    [IO.File]::WriteAllText($dll,'INERT FILE RECREATED FOR THE NEXT TEST')
    $fileFinding.Target.Sha256=(Get-FileHash -LiteralPath $dll).Hash

    Initialize-Report
    $script:CurrentSnapshot=Snapshot @($fileFinding,$registryFinding)
    $savedBoot=${function:Get-CleanupBootId}
    function Get-CleanupBootId {
        throw 'Simulated inaccessible boot identity'
    }
    $callsBefore=$registryCalls
    $answers.Enqueue('y')
    Assert ((Invoke-GuidedCleanup) -eq 'Failed' -and $registryCalls -eq $callsBefore -and (Test-Path -LiteralPath $dll)) 'unreadable boot identity blocks registry mutation before a checkpoint can be trusted'
    Set-Item Function:\Get-CleanupBootId -Value $savedBoot
    Save-CleanupRestartState
    [IO.File]::WriteAllText((Get-CleanupStatePath),'{broken')
    $callsBefore=$registryCalls
    Assert ((Invoke-GuidedCleanup) -eq 'Failed' -and $registryCalls -eq $callsBefore -and $answers.Count -eq 0) 'corrupt checkpoint is never treated as permission to continue'
    Clear-CleanupRestartState

    Initialize-Report
    $callsBefore=$scanCalls
    $NoPrompt=$false
    $answers.Enqueue('1')
    $answers.Enqueue('q')
    $result=Invoke-NikkeCheck
    Assert ($result -eq 'Quitter' -and $scanCalls -eq $callsBefore+1) 'recommended route runs one complete scan with no separate game-removed or cache menu'
    Assert ($answers.Count -eq 0) 'the recommended clean result can be understood and exited with no extra wizard questions'
    Assert (($shown.Text -join "`n") -notmatch '7  ') 'standalone cache menu is removed'
    $script:Language='fr'
    Assert ((Convert-UiText '1  Vérification complète et nettoyage guidé (recommandé)') -match '^1  Vérification') 'French keeps the same single recommended workflow'
    $script:Language='en'
    Assert ((Convert-UiText '1  Vérification complète et nettoyage guidé (recommandé)') -match '^1  Full check') 'English is translated for the single recommended workflow'
    Assert (([IO.File]::ReadAllText((Join-Path $repository 'NikkeTrace.ps1'))) -notmatch 'Restart-Computer|shutdown\.exe|schtasks\.exe') 'the workflow never forces a reboot or installs startup execution'
    Microsoft.PowerShell.Utility\Write-Host "SUCCESS: $checks guided-workflow, report and restart-barrier checks on fixtures only."
} finally {
    $env:LOCALAPPDATA=$oldLocal
    $env:APPDATA=$oldRoaming
    $env:TEMP=$oldTemp
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
