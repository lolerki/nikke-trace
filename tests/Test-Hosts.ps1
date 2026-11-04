# Fixed-domain hosts editing on fake files only. UAC and Start-Process are mocked.
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$workspace=Split-Path $PSScriptRoot -Parent
$fixture=Join-Path $PSScriptRoot ('fixtures-' + [guid]::NewGuid().ToString('N').Substring(0,8))
$checks=0
function Assert([bool]$Condition,[string]$Message) {
    if(-not $Condition){
        throw "FAIL: $Message"
    }
    $script:checks++
    Microsoft.PowerShell.Utility\Write-Host "OK: $Message"
}
try {
    [void][IO.Directory]::CreateDirectory($fixture)
    $copy=Join-Path $fixture 'Verification.ps1'
    Copy-Item -LiteralPath (Join-Path $workspace 'NikkeTrace.ps1') -Destination $copy
    . $copy -NoPrompt -Language fr
    Initialize-Report
    $path=Join-Path $fixture 'hosts'
    $original=[Text.Encoding]::UTF8.GetPreamble()+[Text.Encoding]::UTF8.GetBytes("# Réglages légitimes`r`n127.0.0.1 localhost`r`n192.0.2.20 dev.internal # conserver")
    [IO.File]::WriteAllBytes($path,$original)
    $result=Add-KnownHostsBlocks $path ([guid]::NewGuid().ToString('N'))
    Assert $result.Changed 'explicit operation appends the fixed domain blocks'
    Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($result.Backup)) -ceq [Convert]::ToBase64String($original)) 'original hosts backed up byte-for-byte before modification'
    $updated=[IO.File]::ReadAllBytes($path)
    Assert ([Convert]::ToBase64String($updated[0..($original.Length-1)]) -ceq [Convert]::ToBase64String($original)) 'existing comments, BOM, Unicode and unrelated mappings are preserved exactly'
    $text=[IO.File]::ReadAllText($path)
    foreach($domain in @('insightjs.com','analytics.insightjs.com','insightjs.org')) {
        Assert ($text.Contains("0.0.0.0 $domain") -and $text.Contains("::1 $domain")) "IPv4 and IPv6 block added for $domain"
    }
    $again=Add-KnownHostsBlocks $path ([guid]::NewGuid().ToString('N'))
    Assert (-not $again.Changed -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq [Convert]::ToBase64String($updated)) 'second run is idempotent and leaves hosts untouched'
    Assert (@(Get-ChildItem -LiteralPath $fixture -Filter 'hosts.NIKKE-backup-*').Count -eq 1) 'already-blocked domains create no duplicate backup'
    Assert ((Get-Acl -LiteralPath $result.Backup).Sddl -eq (Get-Acl -LiteralPath $path).Sddl) 'backup retains the hosts access-control rules'
    [IO.File]::WriteAllText($path,'192.0.2.10 insightjs.com')
    $before=[IO.File]::ReadAllBytes($path)
    $blocked=$false
    try {
        [void](Add-KnownHostsBlocks $path ([guid]::NewGuid().ToString('N')))
    } catch {
        $blocked=$true
    }
    Assert ($blocked -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq [Convert]::ToBase64String($before)) 'conflicting domain mapping aborts without replacing an existing rule'
    [IO.File]::WriteAllText($path,'127.0.0.1 insightjs.com')
    [void](Add-KnownHostsBlocks $path ([guid]::NewGuid().ToString('N')))
    $text=[IO.File]::ReadAllText($path)
    Assert ($text.StartsWith('127.0.0.1 insightjs.com') -and -not $text.Contains('0.0.0.0 insightjs.com')) 'existing loopback mapping is preserved without a conflicting IPv4 duplicate'
    [IO.File]::WriteAllBytes($path,[Text.Encoding]::Unicode.GetBytes('127.0.0.1 localhost'))
    $before=[IO.File]::ReadAllBytes($path)
    $blocked=$false
    try {
        [void](Add-KnownHostsBlocks $path ([guid]::NewGuid().ToString('N')))
    }catch{
        $blocked=$true
    }
    Assert ($blocked -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq [Convert]::ToBase64String($before)) 'unsupported encoding is rejected without rewriting the original'
    [IO.File]::WriteAllText($path,'127.0.0.1 localhost')
    $lock=[IO.File]::Open($path,'Open','ReadWrite','None')
    $blocked=$false
    try {
        try{
            [void](Add-KnownHostsBlocks $path ([guid]::NewGuid().ToString('N')))
        }catch{
            $blocked=$true
        }
    }finally{
        $lock.Dispose()
    }
    Assert ($blocked -and [IO.File]::ReadAllText($path) -eq '127.0.0.1 localhost') 'locked hosts file is left unchanged'
    $blocked=$false
    try{
        [void](Add-KnownHostsBlocks $path '../unsafe')
    }catch{
        $blocked=$true
    }
    Assert $blocked 'backup token cannot supply a path or code'

    $grouped="192.0.2.22 project.example.test`r`n0.0.0.0 insightjs.com analytics.insightjs.com`r`n:: insightjs.com analytics.insightjs.com`r`n127.0.0.1 INSIGHTJS.ORG.`r`n::1 insightjs.org # keep"
    [IO.File]::WriteAllText($path,$grouped)
    $state=Read-HostsBlockState $path
    Assert ($state.Complete -and $state.MissingLines.Count -eq 0 -and $state.Conflicts.Count -eq 0) 'grouped domains, unspecified IPv6, case and trailing dots are recognized'
    $before=[IO.File]::ReadAllBytes($path)
    [void](Add-KnownHostsBlocks $path ([guid]::NewGuid().ToString('N')))
    Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq [Convert]::ToBase64String($before)) 'existing grouped blocks and unrelated mapping stay byte-identical'
    $state=Get-HostsRulesState ([Text.Encoding]::UTF8.GetBytes($grouped+"`r`n203.0.113.10 insightjs.com"))
    Assert (-not $state.Complete -and $state.Conflicts.Count -eq 1) 'a conflicting duplicate cannot be hidden by valid blocking entries'
    $state=Get-HostsRulesState ([Text.Encoding]::UTF8.GetBytes('# 0.0.0.0 insightjs.com'))
    Assert (-not $state.Complete -and $state.MissingLines.Count -eq 6) 'commented rules do not count as blocks'

    $script:launches=New-Object 'System.Collections.Generic.List[object]'
    function Test-HostsAdmin {
        $false
    }
    function Start-Process {
        param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru,$ErrorAction)
        $script:launches.Add([pscustomobject]@{
                FilePath=$FilePath;Verb=$Verb;Arguments=$ArgumentList;Wait=[bool]$Wait;PassThru=[bool]$PassThru
            })
        $process=[pscustomobject]@{
            ExitCode=0
            HasExited=$true
        }
        $process | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
        return $process
    }
    Assert ((Start-HostsBlockOperation ([guid]::NewGuid().ToString('N'))) -eq 0 -and $launches.Count -eq 1) 'administrator operation is dispatched through a mocked native process only'
    $launch=$launches[0]
    Assert ($launch.Verb -eq 'RunAs' -and $launch.Wait -and $launch.PassThru) 'UAC is requested only for the explicit operation and completion is awaited'
    $code=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($launch.Arguments[-1]))
    Assert ($code -match "GetFolderPath\('Windows'\)" -and $code -match 'System32\\drivers\\etc\\hosts') 'elevated payload uses the fixed Windows hosts path'
    Assert ($code -notmatch 'Invoke-TraceScan|Verification.ps1|LauncherPath|Remove-Item|Start-Mp' -and $launch.Arguments[-1].Length -lt 30000) 'elevated payload includes only the hosts operation, not a temporary script or the scanner'
    $tokens=$null
    $errors=$null
    [void][Management.Automation.Language.Parser]::ParseInput($code,[ref]$tokens,[ref]$errors)
    Assert ($errors.Count -eq 0) 'encoded elevated command parses in Windows PowerShell'
    function Get-HostsBlockPath {
        $path
    }
    function Test-HostsAdmin {
        $true
    }
    [IO.File]::WriteAllText($path,'127.0.0.1 localhost')
    Assert ((Start-HostsBlockOperation ([guid]::NewGuid().ToString('N'))) -eq 0 -and $launches.Count -eq 1 -and (Read-HostsBlockState $path).Complete) 'already-administrator branch writes only the fake target without requesting UAC again'
    [IO.File]::WriteAllText($path,'192.0.2.10 insightjs.com')
    Assert ((Start-HostsBlockOperation ([guid]::NewGuid().ToString('N'))) -eq 12) 'administrator branch returns a specific conflict failure'
    foreach($case in @(@([OperationCanceledException]::new('cancel'),1223),@([UnauthorizedAccessException]::new('denied'),11),@([IO.IOException]::new('locked'),10))) {
        try{
            throw $case[0]
        }catch{
            Assert ((Get-HostsFailureCode $_) -eq $case[1]) 'failure classifier distinguishes cancellation, access denial and IO failure'
        }
    }
    $script:answers=New-Object 'System.Collections.Generic.Queue[string]'
    $script:shown=New-Object 'System.Collections.Generic.List[string]'
    $script:previewAtConsent=''
    function Write-Host {
        param($Object,[ConsoleColor]$ForegroundColor='Gray')$script:shown.Add([string]$Object)
    }
    function Read-Host {
        $script:previewAtConsent=$script:shown -join "`n"
        $script:answers.Dequeue()
    }
    function Save-Report {}
    $script:ops=0
    function Start-HostsBlockOperation {
        param($Token) $script:ops++
        [void](Add-KnownHostsBlocks $path $Token)
        return 0
    }
    [IO.File]::WriteAllText($path,'127.0.0.1 localhost')
    $answers.Enqueue('n')
    Offer-HostsBlock
    Assert ($ops -eq 0 -and ($Report -join "`n") -match 'refusé : aucune modification') 'refusing the offer causes no elevation or write'
    foreach($domain in @('insightjs.com','analytics.insightjs.com','insightjs.org')) {
        Assert ($previewAtConsent.Contains("  - $domain") -and $previewAtConsent.Contains("0.0.0.0 $domain") -and $previewAtConsent.Contains("::1 $domain")) "domain and exact IPv4/IPv6 rules shown before consent: $domain"
    }
    Assert ($previewAtConsent.Contains("Fichier concerné : $path") -and $previewAtConsent -match 'seules les lignes manquantes' -and $previewAtConsent -match 'sauvegarde') 'hosts file, no-duplicate behavior and backup explained before confirmation'
    $answers.Enqueue('o')
    Offer-HostsBlock
    Assert ($ops -eq 1 -and ($Report -join "`n") -match 'DOMAINES SIGNALÉS BLOQUÉS.*relecture' -and (Read-HostsBlockState $path).Complete) 'acceptance reports success only after the actual fake contents are verified'
    Initialize-Report
    $backupsBefore=@(Get-ChildItem -LiteralPath $fixture -Filter 'hosts.NIKKE-backup-*').Count
    Offer-HostsBlock
    Assert ($ops -eq 1 -and ($Report -join "`n") -match 'DOMAINES DÉJÀ BLOQUÉS' -and $answers.Count -eq 0 -and @(Get-ChildItem -LiteralPath $fixture -Filter 'hosts.NIKKE-backup-*').Count -eq $backupsBefore) 'already blocked domains are verified with no prompt, write, backup or elevation'
    [IO.File]::WriteAllText($path,'127.0.0.1 localhost')
    Initialize-Report
    function Start-HostsBlockOperation {
        param($Token) throw [OperationCanceledException]::new('simulated UAC cancellation')
    }
    $answers.Enqueue('o')
    Offer-HostsBlock
    Assert (($Report -join "`n") -match 'administrateur a été annulée' -and ($Report -join "`n") -notmatch 'DOMAINES SIGNALÉS BLOQUÉS') 'cancelled elevation is clearly identified and never produces a success claim'
    Initialize-Report
    function Start-HostsBlockOperation {
        param($Token) return $null
    }
    $answers.Enqueue('o')
    Offer-HostsBlock
    Assert (($Report -join "`n") -notmatch 'DOMAINES SIGNALÉS BLOQUÉS') 'missing administrator result cannot be converted into successful zero exit status'
    Initialize-Report
    function Start-HostsBlockOperation {
        param($Token) return 0
    }
    $answers.Enqueue('o')
    Offer-HostsBlock
    Assert (($Report -join "`n") -notmatch 'DOMAINES SIGNALÉS BLOQUÉS') 'zero exit status without actual rules never produces a success claim'
    Initialize-Report
    function Start-HostsBlockOperation {
        param($Token) [void](Add-KnownHostsBlocks $path $Token)
        return $null
    }
    $answers.Enqueue('o')
    Offer-HostsBlock
    Assert (($Report -join "`n") -match 'DOMAINES SIGNALÉS BLOQUÉS.*relecture') 'verified contents confirm success even when the child exit status is unavailable'
    Initialize-Report
    [IO.File]::WriteAllText($path,'127.0.0.1 localhost')
    function Start-HostsBlockOperation {
        param($Token) [void](Add-KnownHostsBlocks $path $Token)
        throw [OperationCanceledException]::new('misleading status')
    }
    $answers.Enqueue('o')
    Offer-HostsBlock
    Assert (($Report -join "`n") -match 'DOMAINES SIGNALÉS BLOQUÉS.*relecture') 'verified contents take priority over a misleading operation status'
    Initialize-Report
    [IO.File]::WriteAllText($path,'127.0.0.1 localhost')
    function Start-HostsBlockOperation {
        param($Token) Remove-Item -LiteralPath $path
        return 0
    }
    $answers.Enqueue('o')
    Offer-HostsBlock
    Assert (($Report -join "`n") -match 'Impossible de relire hosts' -and ($Report -join "`n") -notmatch 'DOMAINES SIGNALÉS BLOQUÉS') 'a failed readback never produces a success claim'
    Initialize-Report
    [IO.File]::WriteAllText($path,'192.0.2.10 insightjs.com')
    function Start-HostsBlockOperation {
        throw 'Unexpected elevation'
    }
    Offer-HostsBlock
    Assert (($Report -join "`n") -match 'conflit' -and $answers.Count -eq 0 -and [IO.File]::ReadAllText($path) -ceq '192.0.2.10 insightjs.com') 'preflight conflict needs no consent or elevation and preserves existing entries'
    Initialize-Report
    [IO.File]::WriteAllBytes($path,[Text.Encoding]::Unicode.GetBytes('127.0.0.1 localhost'))
    Offer-HostsBlock
    Assert (($Report -join "`n") -match 'format du fichier hosts' -and $answers.Count -eq 0) 'unsupported file format is explained before consent or elevation'
    Initialize-Report
    [IO.File]::WriteAllText($path,'127.0.0.1 localhost')
    $lock=[IO.File]::Open($path,'Open','ReadWrite','None')
    try {
        Offer-HostsBlock
    }finally{
        $lock.Dispose()
    }
    Assert (($Report -join "`n") -match 'inaccessible ou utilisé' -and $answers.Count -eq 0) 'unreadable file is reported without claiming blocked domains or asking for UAC'
    $script:Language='en'
    Assert ((Convert-UiText 'Ce blocage ne supprime pas une infection et ne bloque pas les connexions directes vers les IP signalées.') -like 'This block does not remove an infection*') 'English description explains the precise limits of hosts blocking'
    Assert ((Convert-UiText 'DOMAINES DÉJÀ BLOQUÉS DANS HOSTS — aucune modification ni demande administrateur nécessaire.') -like 'DOMAINS ALREADY BLOCKED IN HOSTS*') 'new verification result is translated into English'
    Microsoft.PowerShell.Utility\Write-Host "SUCCESS: $checks hosts-option checks on fake files only; no UAC or system hosts modification."
} finally {
    if(Test-Path -LiteralPath $fixture){
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
