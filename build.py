from pathlib import Path
import hashlib
import re
import zipfile

root = Path(__file__).resolve().parent
source = root / 'NikkeTrace.ps1'
payload = source.read_text(encoding='utf-8-sig').replace('\r\n', '\n')
bootstrap = (
    "$ErrorActionPreference='Stop'; "
    "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
    "$code=1; $scratch=Join-Path $env:TEMP ('NIKKE-Assistant-'+[guid]::NewGuid().ToString('N')); "
    "try { [void][IO.Directory]::CreateDirectory($scratch); "
    "$lines=[IO.File]::ReadAllLines($env:NIKKE_LAUNCHER,[Text.Encoding]::UTF8); "
    "$i=[Array]::IndexOf($lines,':NIKKE_POWERSHELL_PAYLOAD'); "
    "if($i -lt 0){throw 'Incomplete file. Download it again.'}; "
    "$scriptFile=Join-Path $scratch 'Verification.ps1'; "
    "[IO.File]::WriteAllLines($scriptFile,$lines[($i+1)..($lines.Length-1)],[Text.UTF8Encoding]::new($true)); "
    "& (Join-Path $PSHOME 'powershell.exe') -NoLogo -NoProfile -ExecutionPolicy Bypass -File $scriptFile -LauncherPath $env:NIKKE_LAUNCHER; "
    "$code=$LASTEXITCODE "
    "} catch { Write-Host ('Unable to start: '+$_.Exception.Message) } "
    "finally { if([IO.Directory]::Exists($scratch)){try{[IO.Directory]::Delete($scratch,$true)}catch{Write-Host 'The temporary file could not be removed.'}} }; "
    "exit $code"
)
header = rf'''@echo off
setlocal DisableDelayedExpansion
title NikkeTrace - EN / FR
rem The readable PowerShell source is embedded below.
rem Execution policy is changed only for these processes, never permanently.
set "NIKKE_LAUNCHER=%~f0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "{bootstrap}"
set "NIKKE_EXIT=%ERRORLEVEL%"
if not "%NIKKE_EXIT%"=="0" (
  echo The action did not complete. No cleanup can be confirmed.
  echo Do not disable your antivirus to run this tool.
  pause
)
exit /b %NIKKE_EXIT%
:NIKKE_POWERSHELL_PAYLOAD
'''
artifact = root / 'NikkeTrace.cmd'
artifact.write_bytes((header + payload).replace('\n', '\r\n').encode('utf-8'))
version = re.search(r'VERSION (\d+\.\d+)', payload).group(1)
(root / 'dist').mkdir(exist_ok=True)
archive = root / 'dist' / f'nikke-trace-v{version}.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
    z.write(artifact, artifact.name)
with zipfile.ZipFile(archive) as z:
    assert z.namelist() == ['NikkeTrace.cmd']
    assert z.testzip() is None
extracted = artifact.read_text(encoding='utf-8').split(':NIKKE_POWERSHELL_PAYLOAD\n', 1)[1]
assert extracted == payload
(root / 'dist' / 'SHA256.txt').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '\n')
print(f'Player archive: {archive.name}, one file, {archive.stat().st_size} bytes')
