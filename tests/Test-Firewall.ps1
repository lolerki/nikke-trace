# Inert files and mocked firewall commands only. No firewall rule is read or changed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repository = Split-Path $PSScriptRoot -Parent
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('NikkeTrace-firewall-' + [guid]::NewGuid().ToString('N'))
$checks = 0
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:checks++
}
try {
    . (Join-Path $repository 'NikkeTrace.ps1') -NoPrompt -Language en
    Initialize-Report
    $NoPrompt = $false
    $install = Join-Path $fixture 'SyntheticNIKKE & accents é'
    $service = Join-Path $install 'Launcher\intl_service'
    [void][IO.Directory]::CreateDirectory($service)
    [IO.File]::WriteAllText((Join-Path $install 'Launcher\nikke_launcher.exe'), 'INERT')
    $program = Join-Path $service 'tbs_browser.exe'
    [IO.File]::WriteAllText($program, 'INERT')
    $script:rules = New-Object 'System.Collections.Generic.List[object]'
    $script:answers = New-Object 'System.Collections.Generic.Queue[string]'
    $script:shown = New-Object 'System.Collections.Generic.List[object]'
    $script:changes = 0
    $script:adminRequests = 0
    $script:active = $true
    $script:firewallEnabled = $true
    $script:allowLocal = $true
    $script:readFailure = $false
    $script:removeFailure = $false
    $script:elevated = $true
    function Write-Host { param($Object, [ConsoleColor]$ForegroundColor = 'Gray') $script:shown.Add([pscustomobject]@{ Text = Convert-UiText ([string]$Object); Color = [string]$ForegroundColor }) }
    function Read-Host { param($Prompt) if ($script:answers.Count -eq 0) { throw 'Unexpected question' }; $script:answers.Dequeue() }
    function Save-Report { }
    function Import-LauncherBrowserFirewallModule { }
    function Get-NikkeRemovalCandidates { $install }
    function Test-HostsAdmin { $script:elevated }
    function Get-NetFirewallRule {
        param($PolicyStore, $ErrorAction)
        if ($script:readFailure) { throw 'INERT READ FAILURE' }
        if ($PolicyStore -eq 'ActiveStore' -and -not $script:active) { return }
        $script:rules.ToArray()
    }
    function Get-NetFirewallApplicationFilter { param($AssociatedNetFirewallRule, $ErrorAction) [pscustomobject]@{ Program = $AssociatedNetFirewallRule.Program } }
    function Get-NetFirewallPortFilter { param($AssociatedNetFirewallRule, $ErrorAction) [pscustomobject]@{ Protocol = 'Any'; LocalPort = 'Any'; RemotePort = 'Any' } }
    function Get-NetFirewallAddressFilter { param($AssociatedNetFirewallRule, $ErrorAction) [pscustomobject]@{ LocalAddress = 'Any'; RemoteAddress = 'Any' } }
    function Get-NetFirewallProfile {
        param($PolicyStore, $ErrorAction)
        foreach ($name in @('Domain', 'Private', 'Public')) { [pscustomobject]@{ Name = $name; Enabled = $script:firewallEnabled; AllowLocalFirewallRules = $script:allowLocal } }
    }
    function New-NetFirewallRule {
        param($PolicyStore, $Name, $DisplayName, $Description, $Group, $Program, $Direction, $Action, $Profile, $Enabled, $Protocol, $LocalAddress, $RemoteAddress, $ErrorAction)
        if ($PolicyStore -ne 'PersistentStore' -or $Direction -ne 'Outbound' -or $Action -ne 'Block' -or $Profile -ne 'Any' -or $Protocol -ne 'Any' -or $LocalAddress -ne 'Any' -or $RemoteAddress -ne 'Any') { throw 'Unexpected firewall scope' }
        $script:rules.Add([pscustomobject]@{ Name = $Name; Description = $Description; Group = $Group; Program = $Program; Direction = $Direction; Action = $Action; Profile = $Profile; Enabled = $Enabled })
        $script:changes++
    }
    function Remove-NetFirewallRule {
        param($PolicyStore, $Name, $ErrorAction)
        if ($script:removeFailure) { throw 'INERT REMOVE FAILURE' }
        if ($PolicyStore -ne 'PersistentStore' -or $Name -notmatch '^NikkeTrace-LauncherBrowser-[A-F0-9]{64}$') { throw 'Unexpected removal target' }
        for ($i = $script:rules.Count - 1; $i -ge 0; $i--) { if ($script:rules[$i].Name -ceq $Name) { $script:rules.RemoveAt($i); $script:changes++ } }
    }
    Assert ((Get-LauncherBrowserProgram $install) -eq $program) 'only the verified launcher browser is discovered'
    $bad = $false
    try { Get-LauncherBrowserRuleName (Join-Path $service 'chrome.exe') } catch { $bad = $true }
    Assert $bad 'ordinary browsers cannot be firewall targets'
    $bad = $false
    try { Get-LauncherBrowserRuleName ('\\server\share\Launcher\intl_service\tbs_browser.exe') } catch { $bad = $true }
    Assert $bad 'network program paths are refused'
    $answers.Enqueue('n')
    Offer-LauncherBrowserFirewall 'Block'
    Assert ($changes -eq 0 -and $answers.Count -eq 0) 'declining changes nothing'
    $NoPrompt = $true
    Offer-LauncherBrowserFirewall 'Block'
    Assert ($changes -eq 0) 'noninteractive checks never modify the firewall'
    $NoPrompt = $false
    $answers.Enqueue('y')
    Offer-LauncherBrowserFirewall 'Block'
    Assert ($changes -eq 1 -and $rules.Count -eq 1 -and $rules[0].Program -eq $program) 'consent creates exactly one program-specific outbound block'
    Assert (@($shown | Where-Object { $_.Color -eq 'Green' -and $_.Text -like '*active Windows configuration*' }).Count -eq 1) 'success requires active configuration readback'
    $targetIndex = -1
    for ($i = 0; $i -lt $shown.Count; $i++) { if ($shown[$i].Text -eq $program) { $targetIndex = $i; break } }
    Assert ($targetIndex -ge 0 -and @($shown | Where-Object { $_.Text -like '*may prevent account sign-in*' }).Count -gt 0) 'target and sign-in warning are displayed before modification'
    $answers.Enqueue('y')
    Offer-LauncherBrowserFirewall 'Block'
    Assert ($changes -eq 1 -and $rules.Count -eq 1) 'running twice never duplicates rules'
    $shown.Clear()
    $script:active = $false
    $answers.Enqueue('y')
    Offer-LauncherBrowserFirewall 'Block'
    Assert (@($shown | Where-Object { $_.Color -eq 'Green' }).Count -eq 0 -and @($shown | Where-Object { $_.Text -like '*unconfirmed or partial*' }).Count -eq 1) 'a rule absent from active policy never produces a green result'
    $script:active = $true
    foreach ($field in @('firewallEnabled', 'allowLocal')) {
        Set-Variable -Scope Script -Name $field -Value $false
        $shown.Clear()
        $answers.Enqueue('y')
        Offer-LauncherBrowserFirewall 'Block'
        Assert (@($shown | Where-Object { $_.Color -eq 'Green' }).Count -eq 0) "disabled or restricted firewall is not reassuring: $field"
        Set-Variable -Scope Script -Name $field -Value $true
    }
    $shown.Clear()
    $script:readFailure = $true
    Offer-LauncherBrowserFirewall 'Block'
    Assert (@($shown | Where-Object { $_.Color -eq 'Green' }).Count -eq 0 -and $changes -eq 1) 'read failure neither changes rules nor reports success'
    $script:readFailure = $false
    $rules[0].Program = Join-Path $service 'chrome.exe'
    $bad = $false
    try { Set-LauncherBrowserFirewall $program 'Remove' } catch { $bad = $true }
    Assert ($bad -and $changes -eq 1) 'a conflicting rule is preserved instead of overwritten or removed'
    $rules[0].Program = $program
    $script:elevated = $false
    function Start-Process {
        param($FilePath, $Verb, $ArgumentList, $WindowStyle, [switch]$Wait, [switch]$PassThru, $ErrorAction)
        $script:adminRequests++
        $script:encoded = $ArgumentList[-1]
        if ($Verb -ne 'RunAs' -or $ArgumentList[-2] -ne '-EncodedCommand' -or $FilePath -ne (Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe')) { throw 'Unexpected elevation command' }
        throw 'INERT UAC CANCELLATION'
    }
    $shown.Clear()
    $rules.Clear()
    $answers.Enqueue('y')
    Offer-LauncherBrowserFirewall 'Block'
    Assert ($adminRequests -eq 1 -and @($shown | Where-Object { $_.Color -eq 'Green' }).Count -eq 0) 'cancelled elevation never reports a block'
    $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($script:encoded))
    $tokens = $null; $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseInput($decoded, [ref]$tokens, [ref]$parseErrors)
    Assert ($parseErrors.Count -eq 0 -and $script:encoded.Length -lt 30000 -and $decoded -notmatch '-File |Invoke-Expression') 'elevation uses bounded fixed code and encoded data, not an editable temporary script'
    $script:elevated = $true
    Set-LauncherBrowserFirewall $program 'Block'
    $unrelated = [pscustomobject]@{ Name = 'Other-tool-rule'; Description = ''; Group = ''; Program = 'Any'; Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'; Enabled = 'True' }
    $rules.Add($unrelated)
    [IO.Directory]::Delete($install, $true)
    $script:removeFailure = $true
    $shown.Clear()
    $answers.Enqueue('y')
    Offer-LauncherBrowserFirewall 'Remove'
    Assert ($rules.Count -eq 2 -and @($shown | Where-Object { $_.Color -eq 'Green' }).Count -eq 0) 'failed removal is reported without claiming rollback'
    $script:removeFailure = $false
    $answers.Enqueue('y')
    Offer-LauncherBrowserFirewall 'Remove'
    Assert ($rules.Count -eq 1 -and $rules[0].Name -eq 'Other-tool-rule') 'undo works after uninstall and preserves other firewall rules'
    $answers.Enqueue('6'); $answers.Enqueue('b'); $answers.Enqueue('b')
    Assert ((Show-AdvancedOptions) -eq 'Retour' -and $answers.Count -eq 0) 'advanced option 6 opens the browser firewall submenu and returns normally'
    Write-Output "SUCCESS: $checks firewall checks on inert fixtures and mocked commands only."
} finally {
    if ([IO.Directory]::Exists($fixture)) { [IO.Directory]::Delete($fixture, $true) }
}
