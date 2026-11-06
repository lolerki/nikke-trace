@echo off
setlocal DisableDelayedExpansion
title NikkeTrace - EN / FR
rem The readable PowerShell source is embedded below.
rem Execution policy is changed only for these processes, never permanently.
set "NIKKE_LAUNCHER=%~f0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; if($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage'){Write-Host 'Windows application control restricts this session. NikkeTrace cannot run; no check was performed.'; exit 1}; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $code=1; $scratch=Join-Path $env:TEMP ('NIKKE-Assistant-'+[guid]::NewGuid().ToString('N')); try { [void][IO.Directory]::CreateDirectory($scratch); $lines=[IO.File]::ReadAllLines($env:NIKKE_LAUNCHER,[Text.Encoding]::UTF8); $i=[Array]::IndexOf($lines,':NIKKE_POWERSHELL_PAYLOAD'); if($i -lt 0){throw 'Incomplete file. Download it again.'}; $scriptFile=Join-Path $scratch 'Verification.ps1'; [IO.File]::WriteAllLines($scriptFile,$lines[($i+1)..($lines.Length-1)],[Text.UTF8Encoding]::new($true)); & (Join-Path $PSHOME 'powershell.exe') -NoLogo -NoProfile -ExecutionPolicy Bypass -File $scriptFile -LauncherPath $env:NIKKE_LAUNCHER; $code=$LASTEXITCODE } catch { Write-Host ('Unable to start: '+$_.Exception.Message) } finally { if([IO.Directory]::Exists($scratch)){try{[IO.Directory]::Delete($scratch,$true)}catch{Write-Host 'The temporary file could not be removed.'}} }; exit $code"
set "NIKKE_EXIT=%ERRORLEVEL%"
if not "%NIKKE_EXIT%"=="0" (
  echo The action did not complete. No cleanup can be confirmed.
  echo Do not disable your antivirus to run this tool.
  echo Running as administrator does not override Smart App Control.
  pause
)
exit /b %NIKKE_EXIT%
:NIKKE_POWERSHELL_PAYLOAD
#requires -Version 5.1
<#
MIT License

Copyright (c) 2026 lolerki

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

NikkeTrace: local checks and optional targeted cleanup for known NIKKE incident traces.
Requires Windows PowerShell 5.1.
#>
[CmdletBinding()]
param(
    [string[]]$NikkePath = @(),
    [ValidateSet('en', 'fr')][string]$Language = 'en',
    [switch]$NoPrompt,
    [ValidateSet('Verifier', 'SansJeu', 'Navigateurs')][string]$Mode = 'Verifier',
    [ValidateSet('Tous', 'Chrome', 'Edge', 'Firefox', 'Brave', 'Opera', 'Vivaldi')][string]$Navigateur = 'Tous',
    [string]$LauncherPath = $PSCommandPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Microsoft.PowerShell.Utility\Write-Host 'Windows application control restricts this session. NikkeTrace cannot run; no check was performed.' -ForegroundColor Yellow
    Microsoft.PowerShell.Utility\Write-Host 'Keep Windows security enabled. Running as administrator does not override application control.'
    exit 1
}
$script:SessionExposure = $false
$script:ExtraNikkePath = @()
$script:NextBrowser = $null
$script:ScanFeedback = $null
$script:CustomBrowserRoots = New-Object 'System.Collections.Generic.List[object]'


# BEGIN LANGUAGE SUPPORT
$script:Language = $Language
$script:TranslationCache = @{}
$script:UiCatalog = @'
[
    {
        "French": "Un ancien journal peut manquer après désinstallation ; les autres contrôles restent utiles. Ne réinstallez pas le jeu pour récupérer ce journal.",
        "Pattern": "^Un\\ ancien\\ journal\\ peut\\ manquer\\ après\\ désinstallation\\ ;\\ les\\ autres\\ contrôles\\ restent\\ utiles\\.\\ Ne\\ réinstallez\\ pas\\ le\\ jeu\\ pour\\ récupérer\\ ce\\ journal\\.$",
        "English": "An old log may be missing after uninstalling; the other checks remain useful. Do not reinstall the game to recover this log.",
        "Count": 0,
        "Weight": 144
    },
    {
        "French": "Avant de commencer : déconnectez ce PC d Internet, fermez NIKKE, son lanceur et les navigateurs. Vérifiez aussi les icônes près de l horloge.",
        "Pattern": "^Avant\\ de\\ commencer\\ :\\ déconnectez\\ ce\\ PC\\ d\\ Internet,\\ fermez\\ NIKKE,\\ son\\ lanceur\\ et\\ les\\ navigateurs\\.\\ Vérifiez\\ aussi\\ les\\ icônes\\ près\\ de\\ l\\ horloge\\.$",
        "English": "Before starting: disconnect this PC from the Internet and close NIKKE, its launcher and browsers. Also check the icons near the clock.",
        "Count": 0,
        "Weight": 141
    },
    {
        "French": "Sécurisez vos comptes depuis un appareil sain : mots de passe enregistrés ou utilisés sur ce PC, sessions ouvertes et clés ou jetons exposés.",
        "Pattern": "^Sécurisez\\ vos\\ comptes\\ depuis\\ un\\ appareil\\ sain\\ :\\ mots\\ de\\ passe\\ enregistrés\\ ou\\ utilisés\\ sur\\ ce\\ PC,\\ sessions\\ ouvertes\\ et\\ clés\\ ou\\ jetons\\ exposés\\.$",
        "English": "Secure your accounts from a clean device: passwords saved or used on this PC, open sessions and exposed keys or tokens.",
        "Count": 0,
        "Weight": 141
    },
    {
        "French": "Cette vérification ne teste pas les connexions réelles. Une mise à jour qui change le chemin du programme peut nécessiter un nouveau blocage.",
        "Pattern": "^Cette\\ vérification\\ ne\\ teste\\ pas\\ les\\ connexions\\ réelles\\.\\ Une\\ mise\\ à\\ jour\\ qui\\ change\\ le\\ chemin\\ du\\ programme\\ peut\\ nécessiter\\ un\\ nouveau\\ blocage\\.$",
        "English": "This check does not test actual connections. An update that changes the program path may require a new block.",
        "Count": 0,
        "Weight": 141
    },
    {
        "French": "Restez hors ligne, gardez le lanceur fermé et suivez le nettoyage guidé. Effectuez ensuite une analyse antivirus complète et hors connexion.",
        "Pattern": "^Restez\\ hors\\ ligne,\\ gardez\\ le\\ lanceur\\ fermé\\ et\\ suivez\\ le\\ nettoyage\\ guidé\\.\\ Effectuez\\ ensuite\\ une\\ analyse\\ antivirus\\ complète\\ et\\ hors\\ connexion\\.$",
        "English": "Stay offline, keep the launcher closed and follow guided cleanup. Then run a full antivirus scan and an offline scan.",
        "Count": 0,
        "Weight": 140
    },
    {
        "French": "Journaux : profondeur 8 niveaux ; navigateurs : 65 niveaux ; limite de 12000 dossiers par racine, caches exclus et liens/jonctions ignorés.",
        "Pattern": "^Journaux\\ :\\ profondeur\\ 8\\ niveaux\\ ;\\ navigateurs\\ :\\ 65\\ niveaux\\ ;\\ limite\\ de\\ 12000\\ dossiers\\ par\\ racine,\\ caches\\ exclus\\ et\\ liens/jonctions\\ ignorés\\.$",
        "English": "Logs: depth 8; browsers: depth 65; limit of 12000 folders per root, excluding caches and skipping links/junctions.",
        "Count": 0,
        "Weight": 139
    },
    {
        "French": "Par précaution, depuis un appareil sain : changez vos mots de passe enregistrés ou utilisés sur ce PC, ainsi que ceux réutilisés ailleurs.",
        "Pattern": "^Par\\ précaution,\\ depuis\\ un\\ appareil\\ sain\\ :\\ changez\\ vos\\ mots\\ de\\ passe\\ enregistrés\\ ou\\ utilisés\\ sur\\ ce\\ PC,\\ ainsi\\ que\\ ceux\\ réutilisés\\ ailleurs\\.$",
        "English": "As a precaution, use a clean device to change passwords saved or used on this PC, and passwords reused elsewhere.",
        "Count": 0,
        "Weight": 138
    },
    {
        "French": "Fermez les navigateurs et réessayez. Consultez le rapport si un contrôle reste incomplet ; cela ne signifie pas à lui seul une infection.",
        "Pattern": "^Fermez\\ les\\ navigateurs\\ et\\ réessayez\\.\\ Consultez\\ le\\ rapport\\ si\\ un\\ contrôle\\ reste\\ incomplet\\ ;\\ cela\\ ne\\ signifie\\ pas\\ à\\ lui\\ seul\\ une\\ infection\\.$",
        "English": "Close browsers and try again. Consult the report if a check remains incomplete; this alone does not indicate infection.",
        "Count": 0,
        "Weight": 137
    },
    {
        "French": "Activez la double authentification. Si un coffre de mots de passe était déverrouillé, remplacez aussi les mots de passe qu il contenait.",
        "Pattern": "^Activez\\ la\\ double\\ authentification\\.\\ Si\\ un\\ coffre\\ de\\ mots\\ de\\ passe\\ était\\ déverrouillé,\\ remplacez\\ aussi\\ les\\ mots\\ de\\ passe\\ qu\\ il\\ contenait\\.$",
        "English": "Enable two-factor authentication. If a password vault was unlocked, also replace the passwords it contained.",
        "Count": 0,
        "Weight": 136
    },
    {
        "French": "Fermez les navigateurs et le lanceur puis réessayez. Si un fichier reste verrouillé, redémarrez Windows avant de relancer le contrôle.",
        "Pattern": "^Fermez\\ les\\ navigateurs\\ et\\ le\\ lanceur\\ puis\\ réessayez\\.\\ Si\\ un\\ fichier\\ reste\\ verrouillé,\\ redémarrez\\ Windows\\ avant\\ de\\ relancer\\ le\\ contrôle\\.$",
        "English": "Close browsers and the launcher, then try again. If a file stays locked, restart Windows before rechecking.",
        "Count": 0,
        "Weight": 134
    },
    {
        "French": "Le blocage des sites signalés est proposé ensuite, avec une confirmation séparée. Il reste aussi accessible dans les options avancées.",
        "Pattern": "^Le\\ blocage\\ des\\ sites\\ signalés\\ est\\ proposé\\ ensuite,\\ avec\\ une\\ confirmation\\ séparée\\.\\ Il\\ reste\\ aussi\\ accessible\\ dans\\ les\\ options\\ avancées\\.$",
        "English": "Reported website blocking is offered afterwards, with separate confirmation. It also remains available in advanced options.",
        "Count": 0,
        "Weight": 134
    },
    {
        "French": "Les fichiers suspects et le cache du lanceur seront traités après ce redémarrage. Ne relancez pas le jeu ni son lanceur entre-temps.",
        "Pattern": "^Les\\ fichiers\\ suspects\\ et\\ le\\ cache\\ du\\ lanceur\\ seront\\ traités\\ après\\ ce\\ redémarrage\\.\\ Ne\\ relancez\\ pas\\ le\\ jeu\\ ni\\ son\\ lanceur\\ entre\\-temps\\.$",
        "English": "Suspicious files and the launcher cache will be handled after the restart. Do not reopen the game or its launcher in the meantime.",
        "Count": 0,
        "Weight": 132
    },
    {
        "French": "  Conseil : fermez les applications concernées et relancez le contrôle. Si la limite persiste, demandez de l aide avec ce rapport.",
        "Pattern": "^\\ \\ Conseil\\ :\\ fermez\\ les\\ applications\\ concernées\\ et\\ relancez\\ le\\ contrôle\\.\\ Si\\ la\\ limite\\ persiste,\\ demandez\\ de\\ l\\ aide\\ avec\\ ce\\ rapport\\.$",
        "English": "  Advice: close the affected applications and retry. If the limitation persists, seek help with this report.",
        "Count": 0,
        "Weight": 130
    },
    {
        "French": "  Disparu signifie absent au contrôle. Seules les actions marquées CONFIRMÉES attestent ce que cet outil a effectivement traité.",
        "Pattern": "^\\ \\ Disparu\\ signifie\\ absent\\ au\\ contrôle\\.\\ Seules\\ les\\ actions\\ marquées\\ CONFIRMÉES\\ attestent\\ ce\\ que\\ cet\\ outil\\ a\\ effectivement\\ traité\\.$",
        "English": "  Missing means absent during the check. Only actions marked CONFIRMED establish what this tool actually handled.",
        "Count": 0,
        "Weight": 128
    },
    {
        "French": "Jeu déjà supprimé ? Le mode dédié vérifie encore les navigateurs, le registre, les temporaires et les journaux résiduels connus.",
        "Pattern": "^Jeu\\ déjà\\ supprimé\\ \\?\\ Le\\ mode\\ dédié\\ vérifie\\ encore\\ les\\ navigateurs,\\ le\\ registre,\\ les\\ temporaires\\ et\\ les\\ journaux\\ résiduels\\ connus\\.$",
        "English": "Game already removed? The dedicated mode still checks browsers, registry, temporary files and known residual logs.",
        "Count": 0,
        "Weight": 128
    },
    {
        "French": "Disparu signifie absent au contrôle. Seules les actions marquées CONFIRMÉES attestent ce que cet outil a effectivement traité.",
        "Pattern": "^Disparu\\ signifie\\ absent\\ au\\ contrôle\\.\\ Seules\\ les\\ actions\\ marquées\\ CONFIRMÉES\\ attestent\\ ce\\ que\\ cet\\ outil\\ a\\ effectivement\\ traité\\.$",
        "English": "Missing means absent during the check. Only actions marked CONFIRMED establish what this tool actually handled.",
        "Count": 0,
        "Weight": 126
    },
    {
        "French": "Les entrées de registre seront revérifiées et sauvegardées avant toute modification. Les éléments incertains restent en place.",
        "Pattern": "^Les\\ entrées\\ de\\ registre\\ seront\\ revérifiées\\ et\\ sauvegardées\\ avant\\ toute\\ modification\\.\\ Les\\ éléments\\ incertains\\ restent\\ en\\ place\\.$",
        "English": "Registry entries will be rechecked and backed up before changes. Uncertain items remain untouched.",
        "Count": 0,
        "Weight": 126
    },
    {
        "French": "  Changez vos mots de passe enregistrés ou utilisés sur ce PC, déconnectez les sessions et activez la double authentification.",
        "Pattern": "^\\ \\ Changez\\ vos\\ mots\\ de\\ passe\\ enregistrés\\ ou\\ utilisés\\ sur\\ ce\\ PC,\\ déconnectez\\ les\\ sessions\\ et\\ activez\\ la\\ double\\ authentification\\.$",
        "English": "  Change passwords saved or used on this PC, sign out sessions and enable two-factor authentication.",
        "Count": 0,
        "Weight": 126
    },
    {
        "French": "  3. Si un coffre était déverrouillé, son contenu peut être exposé : changer seulement son mot de passe maître ne suffit pas.",
        "Pattern": "^\\ \\ 3\\.\\ Si\\ un\\ coffre\\ était\\ déverrouillé,\\ son\\ contenu\\ peut\\ être\\ exposé\\ :\\ changer\\ seulement\\ son\\ mot\\ de\\ passe\\ maître\\ ne\\ suffit\\ pas\\.$",
        "English": "  3. An unlocked password vault may have been exposed: changing only its master password is not enough.",
        "Count": 0,
        "Weight": 125
    },
    {
        "French": "Avant toute reprise du jeu : attendre les consignes officielles et réinitialiser le cache du lanceur avec aide si nécessaire.",
        "Pattern": "^Avant\\ toute\\ reprise\\ du\\ jeu\\ :\\ attendre\\ les\\ consignes\\ officielles\\ et\\ réinitialiser\\ le\\ cache\\ du\\ lanceur\\ avec\\ aide\\ si\\ nécessaire\\.$",
        "English": "Before playing again: wait for official guidance and reset the launcher cache with help if needed.",
        "Count": 0,
        "Weight": 125
    },
    {
        "French": "Aucune trace actuelle trouvée dans les éléments vérifiés. Cela ne prouve pas qu aucun programme malveillant ne s est exécuté.",
        "Pattern": "^Aucune\\ trace\\ actuelle\\ trouvée\\ dans\\ les\\ éléments\\ vérifiés\\.\\ Cela\\ ne\\ prouve\\ pas\\ qu\\ aucun\\ programme\\ malveillant\\ ne\\ s\\ est\\ exécuté\\.$",
        "English": "No current trace was found in the checked items. This does not prove that malicious software never ran.",
        "Count": 0,
        "Weight": 125
    },
    {
        "French": "À faire : consultez les raisons dans [R] Rapport avant de relancer la vérification. Une limite ne signifie pas une infection.",
        "Pattern": "^À\\ faire\\ :\\ consultez\\ les\\ raisons\\ dans\\ \\[R\\]\\ Rapport\\ avant\\ de\\ relancer\\ la\\ vérification\\.\\ Une\\ limite\\ ne\\ signifie\\ pas\\ une\\ infection\\.$",
        "English": "Next: read the reasons in [R] Report before checking again. A limitation does not mean an infection.",
        "Count": 0,
        "Weight": 125
    },
    {
        "French": "Étape 1 : retirer l élément de démarrage suspect. Étape 2 : redémarrer Windows avant le traitement des fichiers et du cache.",
        "Pattern": "^Étape\\ 1\\ :\\ retirer\\ l\\ élément\\ de\\ démarrage\\ suspect\\.\\ Étape\\ 2\\ :\\ redémarrer\\ Windows\\ avant\\ le\\ traitement\\ des\\ fichiers\\ et\\ du\\ cache\\.$",
        "English": "Step 1: remove the suspicious startup entry. Step 2: restart Windows before handling files and cache.",
        "Count": 0,
        "Weight": 124
    },
    {
        "French": "Une exposition passée a été relevée pendant cette session ; un nettoyage ne peut pas annuler un éventuel vol d identifiants.",
        "Pattern": "^Une\\ exposition\\ passée\\ a\\ été\\ relevée\\ pendant\\ cette\\ session\\ ;\\ un\\ nettoyage\\ ne\\ peut\\ pas\\ annuler\\ un\\ éventuel\\ vol\\ d\\ identifiants\\.$",
        "English": "Past exposure was observed during this session; cleanup cannot undo possible credential theft.",
        "Count": 0,
        "Weight": 124
    },
    {
        "French": "3. Si un coffre était déverrouillé, son contenu peut être exposé : changer seulement son mot de passe maître ne suffit pas.",
        "Pattern": "^3\\.\\ Si\\ un\\ coffre\\ était\\ déverrouillé,\\ son\\ contenu\\ peut\\ être\\ exposé\\ :\\ changer\\ seulement\\ son\\ mot\\ de\\ passe\\ maître\\ ne\\ suffit\\ pas\\.$",
        "English": "3. An unlocked password vault may have been exposed: changing only its master password is not enough.",
        "Count": 0,
        "Weight": 123
    },
    {
        "French": "Par précaution, depuis un appareil sain : changez les mots de passe enregistrés/utilisés sur le PC potentiellement exposé.",
        "Pattern": "^Par\\ précaution,\\ depuis\\ un\\ appareil\\ sain\\ :\\ changez\\ les\\ mots\\ de\\ passe\\ enregistrés/utilisés\\ sur\\ le\\ PC\\ potentiellement\\ exposé\\.$",
        "English": "As a precaution, use a clean device to change passwords stored or used on the potentially exposed PC.",
        "Count": 0,
        "Weight": 122
    },
    {
        "French": "Les connexions déjà ouvertes peuvent continuer. Fermez puis rouvrez vos navigateurs ; ne relancez pas un launcher suspect.",
        "Pattern": "^Les\\ connexions\\ déjà\\ ouvertes\\ peuvent\\ continuer\\.\\ Fermez\\ puis\\ rouvrez\\ vos\\ navigateurs\\ ;\\ ne\\ relancez\\ pas\\ un\\ launcher\\ suspect\\.$",
        "English": "Existing connections may continue. Close and reopen your browsers; do not restart a suspicious launcher.",
        "Count": 0,
        "Weight": 122
    },
    {
        "French": "Le nettoyage ne peut pas annuler un éventuel vol d identifiants : sécurisez vos comptes même après le retrait des traces.",
        "Pattern": "^Le\\ nettoyage\\ ne\\ peut\\ pas\\ annuler\\ un\\ éventuel\\ vol\\ d\\ identifiants\\ :\\ sécurisez\\ vos\\ comptes\\ même\\ après\\ le\\ retrait\\ des\\ traces\\.$",
        "English": "Cleanup cannot undo possible credential theft: secure your accounts even after traces are removed.",
        "Count": 0,
        "Weight": 121
    },
    {
        "French": "La désinstallation se fait dans les paramètres de Windows. Aucun dossier du jeu ne sera renommé ou effacé par NikkeTrace.",
        "Pattern": "^La\\ désinstallation\\ se\\ fait\\ dans\\ les\\ paramètres\\ de\\ Windows\\.\\ Aucun\\ dossier\\ du\\ jeu\\ ne\\ sera\\ renommé\\ ou\\ effacé\\ par\\ NikkeTrace\\.$",
        "English": "Uninstall through Windows Settings. NikkeTrace will not rename or delete any game folder.",
        "Count": 0,
        "Weight": 121
    },
    {
        "French": "Les journaux signalent une activité passée ; les fichiers/entrées de registre indiquent des traces actuelles à examiner.",
        "Pattern": "^Les\\ journaux\\ signalent\\ une\\ activité\\ passée\\ ;\\ les\\ fichiers/entrées\\ de\\ registre\\ indiquent\\ des\\ traces\\ actuelles\\ à\\ examiner\\.$",
        "English": "Logs indicate past activity; files and registry entries indicate current items to investigate.",
        "Count": 0,
        "Weight": 120
    },
    {
        "French": "  2. Déconnectez toutes les sessions, retirez les appareils et accès suspects, puis activez la double authentification.",
        "Pattern": "^\\ \\ 2\\.\\ Déconnectez\\ toutes\\ les\\ sessions,\\ retirez\\ les\\ appareils\\ et\\ accès\\ suspects,\\ puis\\ activez\\ la\\ double\\ authentification\\.$",
        "English": "  2. Sign out all sessions, remove unknown devices and suspicious app access, then enable two-factor authentication.",
        "Count": 0,
        "Weight": 119
    },
    {
        "French": "Un seul fichier sert à vérifier le jeu, les navigateurs et le registre, puis à proposer un nettoyage ciblé avec accord.",
        "Pattern": "^Un\\ seul\\ fichier\\ sert\\ à\\ vérifier\\ le\\ jeu,\\ les\\ navigateurs\\ et\\ le\\ registre,\\ puis\\ à\\ proposer\\ un\\ nettoyage\\ ciblé\\ avec\\ accord\\.$",
        "English": "One file checks the game, browsers and registry, then offers targeted cleanup with consent.",
        "Count": 0,
        "Weight": 119
    },
    {
        "French": "Si une DLL reste verrouillée, faites vérifier le retrait de sa persistance, redémarrez Windows puis relancez cet outil.",
        "Pattern": "^Si\\ une\\ DLL\\ reste\\ verrouillée,\\ faites\\ vérifier\\ le\\ retrait\\ de\\ sa\\ persistance,\\ redémarrez\\ Windows\\ puis\\ relancez\\ cet\\ outil\\.$",
        "English": "If a DLL remains locked, have its startup persistence removal checked, restart Windows, then run this tool again.",
        "Count": 0,
        "Weight": 119
    },
    {
        "French": "  Conseil : un journal supprimé ne peut pas être relu. Ne réinstallez pas le jeu ; les autres contrôles restent utiles.",
        "Pattern": "^\\ \\ Conseil\\ :\\ un\\ journal\\ supprimé\\ ne\\ peut\\ pas\\ être\\ relu\\.\\ Ne\\ réinstallez\\ pas\\ le\\ jeu\\ ;\\ les\\ autres\\ contrôles\\ restent\\ utiles\\.$",
        "English": "  Advice: a deleted log cannot be read again. Do not reinstall the game; the other checks remain useful.",
        "Count": 0,
        "Weight": 119
    },
    {
        "French": "Il ne supprime aucune infection et ne garantit ni une protection future ni une baisse de la consommation de ressources.",
        "Pattern": "^Il\\ ne\\ supprime\\ aucune\\ infection\\ et\\ ne\\ garantit\\ ni\\ une\\ protection\\ future\\ ni\\ une\\ baisse\\ de\\ la\\ consommation\\ de\\ ressources\\.$",
        "English": "This does not remove infections or guarantee future protection or lower resource use.",
        "Count": 0,
        "Weight": 119
    },
    {
        "French": "Causes possibles : droits Windows, programme protégé, architecture différente ou programme arrêté pendant le contrôle.",
        "Pattern": "^Causes\\ possibles\\ :\\ droits\\ Windows,\\ programme\\ protégé,\\ architecture\\ différente\\ ou\\ programme\\ arrêté\\ pendant\\ le\\ contrôle\\.$",
        "English": "Possible causes: Windows permissions, a protected program, a different architecture or a program exiting during the check.",
        "Count": 0,
        "Weight": 118
    },
    {
        "French": "Une sauvegarde sera créée à côté de hosts. Les autres entrées seront conservées ; un conflit annulera la modification.",
        "Pattern": "^Une\\ sauvegarde\\ sera\\ créée\\ à\\ côté\\ de\\ hosts\\.\\ Les\\ autres\\ entrées\\ seront\\ conservées\\ ;\\ un\\ conflit\\ annulera\\ la\\ modification\\.$",
        "English": "A backup will be created next to hosts. Other entries will be preserved; a conflict cancels the change.",
        "Count": 0,
        "Weight": 118
    },
    {
        "French": "Le fichier hosts ou sa sauvegarde est inaccessible ou utilisé par un autre programme. Le blocage n a pas été confirmé.",
        "Pattern": "^Le\\ fichier\\ hosts\\ ou\\ sa\\ sauvegarde\\ est\\ inaccessible\\ ou\\ utilisé\\ par\\ un\\ autre\\ programme\\.\\ Le\\ blocage\\ n\\ a\\ pas\\ été\\ confirmé\\.$",
        "English": "The hosts file or its backup is unavailable or in use by another program. Blocking has not been confirmed.",
        "Count": 0,
        "Weight": 118
    },
    {
        "French": "Seuls les blocages manquants seront ajoutés. Une sauvegarde sera conservée et les autres réglages resteront inchangés.",
        "Pattern": "^Seuls\\ les\\ blocages\\ manquants\\ seront\\ ajoutés\\.\\ Une\\ sauvegarde\\ sera\\ conservée\\ et\\ les\\ autres\\ réglages\\ resteront\\ inchangés\\.$",
        "English": "Only missing blocks will be added. A backup will be kept and other settings will remain unchanged.",
        "Count": 0,
        "Weight": 118
    },
    {
        "French": "2. Déconnectez toutes les sessions, retirez les appareils et accès suspects, puis activez la double authentification.",
        "Pattern": "^2\\.\\ Déconnectez\\ toutes\\ les\\ sessions,\\ retirez\\ les\\ appareils\\ et\\ accès\\ suspects,\\ puis\\ activez\\ la\\ double\\ authentification\\.$",
        "English": "2. Sign out all sessions, remove unknown devices and suspicious app access, then enable two-factor authentication.",
        "Count": 0,
        "Weight": 117
    },
    {
        "French": "Après un nettoyage, la revérification est automatique. Après un redémarrage hors connexion, relancez ce même fichier.",
        "Pattern": "^Après\\ un\\ nettoyage,\\ la\\ revérification\\ est\\ automatique\\.\\ Après\\ un\\ redémarrage\\ hors\\ connexion,\\ relancez\\ ce\\ même\\ fichier\\.$",
        "English": "Rechecking is automatic after cleanup. After an offline scan restart, run this same file again.",
        "Count": 0,
        "Weight": 117
    },
    {
        "French": "Consultez les prérequis Microsoft (Defender principal, WinRE ; Windows ARM non pris en charge) ou demandez de l aide.",
        "Pattern": "^Consultez\\ les\\ prérequis\\ Microsoft\\ \\(Defender\\ principal,\\ WinRE\\ ;\\ Windows\\ ARM\\ non\\ pris\\ en\\ charge\\)\\ ou\\ demandez\\ de\\ l\\ aide\\.$",
        "English": "Review Microsoft requirements (Defender primary, WinRE; Windows ARM unsupported) or seek help.",
        "Count": 0,
        "Weight": 117
    },
    {
        "French": "Information : une référence locale à un site signalé a été trouvée. Une consultation du site peut suffire à la créer.",
        "Pattern": "^Information\\ :\\ une\\ référence\\ locale\\ à\\ un\\ site\\ signalé\\ a\\ été\\ trouvée\\.\\ Une\\ consultation\\ du\\ site\\ peut\\ suffire\\ à\\ la\\ créer\\.$",
        "English": "Information: a local reference to a reported website was found. Visiting the site can be enough to create it.",
        "Count": 0,
        "Weight": 117
    },
    {
        "French": "Recherche des traces connues. Le blocage des sites est une option séparée ; aucun changement pendant la vérification.",
        "Pattern": "^Recherche\\ des\\ traces\\ connues\\.\\ Le\\ blocage\\ des\\ sites\\ est\\ une\\ option\\ séparée\\ ;\\ aucun\\ changement\\ pendant\\ la\\ vérification\\.$",
        "English": "Checking known traces. Website blocking is a separate option; nothing is changed during the check.",
        "Count": 0,
        "Weight": 117
    },
    {
        "French": "Pour une installation Google Play Games, retirez uniquement NIKKE depuis sa bibliothèque ; conservez les autres jeux.",
        "Pattern": "^Pour\\ une\\ installation\\ Google\\ Play\\ Games,\\ retirez\\ uniquement\\ NIKKE\\ depuis\\ sa\\ bibliothèque\\ ;\\ conservez\\ les\\ autres\\ jeux\\.$",
        "English": "For Google Play Games, remove only NIKKE from its library; keep your other games.",
        "Count": 0,
        "Weight": 117
    },
    {
        "French": "     Remplacez aussi les jetons API et clés SSH concernés. Ne communiquez jamais vos secrets à un dépanneur Discord.",
        "Pattern": "^\\ \\ \\ \\ \\ Remplacez\\ aussi\\ les\\ jetons\\ API\\ et\\ clés\\ SSH\\ concernés\\.\\ Ne\\ communiquez\\ jamais\\ vos\\ secrets\\ à\\ un\\ dépanneur\\ Discord\\.$",
        "English": "     Also replace affected API tokens and SSH keys. Never share secrets with someone offering Discord support.",
        "Count": 0,
        "Weight": 116
    },
    {
        "French": "Relevez le chemin du profil (dossier racine pour Firefox). Ne lancez pas un navigateur suspect uniquement pour cela.",
        "Pattern": "^Relevez\\ le\\ chemin\\ du\\ profil\\ \\(dossier\\ racine\\ pour\\ Firefox\\)\\.\\ Ne\\ lancez\\ pas\\ un\\ navigateur\\ suspect\\ uniquement\\ pour\\ cela\\.$",
        "English": "Copy the profile path (root directory for Firefox). Do not launch a suspicious browser just to find it.",
        "Count": 0,
        "Weight": 116
    },
    {
        "French": "Sans journaux conservés, une exécution passée reste indéterminée. Ne réinstallez pas le jeu pour cette vérification.",
        "Pattern": "^Sans\\ journaux\\ conservés,\\ une\\ exécution\\ passée\\ reste\\ indéterminée\\.\\ Ne\\ réinstallez\\ pas\\ le\\ jeu\\ pour\\ cette\\ vérification\\.$",
        "English": "Without retained logs, past execution remains unknown. Do not reinstall the game just to check.",
        "Count": 0,
        "Weight": 116
    },
    {
        "French": "  Contrôle ciblé des traces connues et accessibles de cet incident ; ce résultat ne certifie pas que le PC est sain.",
        "Pattern": "^\\ \\ Contrôle\\ ciblé\\ des\\ traces\\ connues\\ et\\ accessibles\\ de\\ cet\\ incident\\ ;\\ ce\\ résultat\\ ne\\ certifie\\ pas\\ que\\ le\\ PC\\ est\\ sain\\.$",
        "English": "  Targeted check of known, accessible traces of this incident; this result does not certify a clean PC.",
        "Count": 0,
        "Weight": 116
    },
    {
        "French": "Recherche des traces connues. Aucun changement pendant la vérification ; chaque intervention nécessite votre accord.",
        "Pattern": "^Recherche\\ des\\ traces\\ connues\\.\\ Aucun\\ changement\\ pendant\\ la\\ vérification\\ ;\\ chaque\\ intervention\\ nécessite\\ votre\\ accord\\.$",
        "English": "Checking known traces. Nothing is changed during the check; each intervention requires your consent.",
        "Count": 0,
        "Weight": 116
    },
    {
        "French": "Après le retour dans Windows : consulter Historique de protection et relancer cet outil pour revérifier les traces.",
        "Pattern": "^Après\\ le\\ retour\\ dans\\ Windows\\ :\\ consulter\\ Historique\\ de\\ protection\\ et\\ relancer\\ cet\\ outil\\ pour\\ revérifier\\ les\\ traces\\.$",
        "English": "After returning to Windows: review Protection history and run this tool again to recheck indicators.",
        "Count": 0,
        "Weight": 115
    },
    {
        "French": "Une trace historique renseigne sur une exposition passée ; elle ne démontre pas à elle seule une activité actuelle.",
        "Pattern": "^Une\\ trace\\ historique\\ renseigne\\ sur\\ une\\ exposition\\ passée\\ ;\\ elle\\ ne\\ démontre\\ pas\\ à\\ elle\\ seule\\ une\\ activité\\ actuelle\\.$",
        "English": "A historical trace indicates possible past exposure; it does not by itself establish current activity.",
        "Count": 0,
        "Weight": 115
    },
    {
        "French": "Par précaution, changez vos mots de passe depuis un appareil sain et déconnectez les sessions ouvertes. Aide : [S].",
        "Pattern": "^Par\\ précaution,\\ changez\\ vos\\ mots\\ de\\ passe\\ depuis\\ un\\ appareil\\ sain\\ et\\ déconnectez\\ les\\ sessions\\ ouvertes\\.\\ Aide\\ :\\ \\[S\\]\\.$",
        "English": "As a precaution, change passwords from a clean device and sign out existing sessions. Help: [S].",
        "Count": 0,
        "Weight": 115
    },
    {
        "French": "Aide hors connexion proposée. Aucun lancement antivirus, redémarrage ou changement réseau déclenché par cet outil.",
        "Pattern": "^Aide\\ hors\\ connexion\\ proposée\\.\\ Aucun\\ lancement\\ antivirus,\\ redémarrage\\ ou\\ changement\\ réseau\\ déclenché\\ par\\ cet\\ outil\\.$",
        "English": "Offline scan help offered. This tool started no antivirus scan, restart or network change.",
        "Count": 0,
        "Weight": 114
    },
    {
        "French": "Sans preuve conservée, une exécution passée reste indéterminée. Ne réinstallez pas le jeu pour cette vérification.",
        "Pattern": "^Sans\\ preuve\\ conservée,\\ une\\ exécution\\ passée\\ reste\\ indéterminée\\.\\ Ne\\ réinstallez\\ pas\\ le\\ jeu\\ pour\\ cette\\ vérification\\.$",
        "English": "Without retained evidence, past execution remains unknown. Do not reinstall the game just to check.",
        "Count": 0,
        "Weight": 114
    },
    {
        "French": "  1. Changez les mots de passe enregistrés/utilisés sur le PC potentiellement exposé et ceux réutilisés ailleurs.",
        "Pattern": "^\\ \\ 1\\.\\ Changez\\ les\\ mots\\ de\\ passe\\ enregistrés/utilisés\\ sur\\ le\\ PC\\ potentiellement\\ exposé\\ et\\ ceux\\ réutilisés\\ ailleurs\\.$",
        "English": "  1. Change passwords stored or used on the potentially exposed PC, and passwords reused elsewhere.",
        "Count": 0,
        "Weight": 113
    },
    {
        "French": "Microsoft recommande de suspendre la protection BitLocker avant cette analyse : demandez de l aide si nécessaire.",
        "Pattern": "^Microsoft\\ recommande\\ de\\ suspendre\\ la\\ protection\\ BitLocker\\ avant\\ cette\\ analyse\\ :\\ demandez\\ de\\ l\\ aide\\ si\\ nécessaire\\.$",
        "English": "Microsoft recommends suspending BitLocker protection before this scan: seek help if needed.",
        "Count": 0,
        "Weight": 113
    },
    {
        "French": "Si une compromission est probable, privilégiez une réinstallation propre de Windows avec une personne compétente.",
        "Pattern": "^Si\\ une\\ compromission\\ est\\ probable,\\ privilégiez\\ une\\ réinstallation\\ propre\\ de\\ Windows\\ avec\\ une\\ personne\\ compétente\\.$",
        "English": "If compromise is likely, favour a clean Windows reinstall with qualified assistance.",
        "Count": 0,
        "Weight": 113
    },
    {
        "French": "Enregistrez vos travaux, redémarrez Windows puis relancez ce même fichier et choisissez la vérification complète.",
        "Pattern": "^Enregistrez\\ vos\\ travaux,\\ redémarrez\\ Windows\\ puis\\ relancez\\ ce\\ même\\ fichier\\ et\\ choisissez\\ la\\ vérification\\ complète\\.$",
        "English": "Save your work, restart Windows, then run this same file and choose the full check.",
        "Count": 0,
        "Weight": 113
    },
    {
        "French": "     Commencez par la messagerie et le gestionnaire de mots de passe, puis comptes importants, Discord et NIKKE.",
        "Pattern": "^\\ \\ \\ \\ \\ Commencez\\ par\\ la\\ messagerie\\ et\\ le\\ gestionnaire\\ de\\ mots\\ de\\ passe,\\ puis\\ comptes\\ importants,\\ Discord\\ et\\ NIKKE\\.$",
        "English": "     Start with email and your password manager, then important accounts, Discord and NIKKE.",
        "Count": 0,
        "Weight": 112
    },
    {
        "French": "Ouvrez Protection contre les virus et menaces > Options d analyse > Microsoft Defender (analyse hors connexion).",
        "Pattern": "^Ouvrez\\ Protection\\ contre\\ les\\ virus\\ et\\ menaces\\ >\\ Options\\ d\\ analyse\\ >\\ Microsoft\\ Defender\\ \\(analyse\\ hors\\ connexion\\)\\.$",
        "English": "Open Virus & threat protection > Scan options > Microsoft Defender Antivirus (offline scan).",
        "Count": 0,
        "Weight": 112
    },
    {
        "French": "Les données légitimes de vos navigateurs, les autres applications et les éléments non reconnus seront conservés.",
        "Pattern": "^Les\\ données\\ légitimes\\ de\\ vos\\ navigateurs,\\ les\\ autres\\ applications\\ et\\ les\\ éléments\\ non\\ reconnus\\ seront\\ conservés\\.$",
        "English": "Legitimate browser data, other applications and unrecognized items will be preserved.",
        "Count": 0,
        "Weight": 112
    },
    {
        "French": "Remplacez aussi les jetons API et clés SSH concernés. Ne communiquez jamais vos secrets à un dépanneur Discord.",
        "Pattern": "^Remplacez\\ aussi\\ les\\ jetons\\ API\\ et\\ clés\\ SSH\\ concernés\\.\\ Ne\\ communiquez\\ jamais\\ vos\\ secrets\\ à\\ un\\ dépanneur\\ Discord\\.$",
        "English": "Also replace affected API tokens and SSH keys. Never share secrets with someone offering Discord support.",
        "Count": 0,
        "Weight": 111
    },
    {
        "French": "1. Changez les mots de passe enregistrés/utilisés sur le PC potentiellement exposé et ceux réutilisés ailleurs.",
        "Pattern": "^1\\.\\ Changez\\ les\\ mots\\ de\\ passe\\ enregistrés/utilisés\\ sur\\ le\\ PC\\ potentiellement\\ exposé\\ et\\ ceux\\ réutilisés\\ ailleurs\\.$",
        "English": "1. Change passwords stored or used on the potentially exposed PC, and passwords reused elsewhere.",
        "Count": 0,
        "Weight": 111
    },
    {
        "French": "En cas de doute sérieux : couper Ethernet/Wi-Fi, ne pas relancer le jeu et ne plus saisir de secrets sur ce PC.",
        "Pattern": "^En\\ cas\\ de\\ doute\\ sérieux\\ :\\ couper\\ Ethernet/Wi\\-Fi,\\ ne\\ pas\\ relancer\\ le\\ jeu\\ et\\ ne\\ plus\\ saisir\\ de\\ secrets\\ sur\\ ce\\ PC\\.$",
        "English": "If you have serious doubts: disconnect Ethernet/Wi-Fi, do not launch the game or enter secrets on this PC.",
        "Count": 0,
        "Weight": 111
    },
    {
        "French": "Suppression définitive du cache : vous pourrez être déconnecté et les réglages du lanceur seront réinitialisés.",
        "Pattern": "^Suppression\\ définitive\\ du\\ cache\\ :\\ vous\\ pourrez\\ être\\ déconnecté\\ et\\ les\\ réglages\\ du\\ lanceur\\ seront\\ réinitialisés\\.$",
        "English": "Cache deletion is permanent: you may be signed out and launcher settings will be reset.",
        "Count": 0,
        "Weight": 111
    },
    {
        "French": "Des anciennes copies créées par NikkeTrace restent présentes. Leur présence ne prouve pas une infection active.",
        "Pattern": "^Des\\ anciennes\\ copies\\ créées\\ par\\ NikkeTrace\\ restent\\ présentes\\.\\ Leur\\ présence\\ ne\\ prouve\\ pas\\ une\\ infection\\ active\\.$",
        "English": "Old copies created by NikkeTrace are still present. Their presence does not prove an active infection.",
        "Count": 0,
        "Weight": 111
    },
    {
        "French": "Opération non confirmée ou partielle. Consultez le rapport ; aucun résultat de protection ne peut être garanti.",
        "Pattern": "^Opération\\ non\\ confirmée\\ ou\\ partielle\\.\\ Consultez\\ le\\ rapport\\ ;\\ aucun\\ résultat\\ de\\ protection\\ ne\\ peut\\ être\\ garanti\\.$",
        "English": "Operation unconfirmed or partial. Read the report; no protection can be guaranteed.",
        "Count": 0,
        "Weight": 111
    },
    {
        "French": "Révoquez aussi les sessions et accès suspects : retirer les fichiers ne sécurise pas les comptes déjà exposés.",
        "Pattern": "^Révoquez\\ aussi\\ les\\ sessions\\ et\\ accès\\ suspects\\ :\\ retirer\\ les\\ fichiers\\ ne\\ sécurise\\ pas\\ les\\ comptes\\ déjà\\ exposés\\.$",
        "English": "Also revoke suspicious sessions and access: removing files does not secure accounts that were already exposed.",
        "Count": 0,
        "Weight": 110
    },
    {
        "French": "La première étape ne peut pas être terminée. Aucun traitement des fichiers suspects ou du cache ne sera tenté.",
        "Pattern": "^La\\ première\\ étape\\ ne\\ peut\\ pas\\ être\\ terminée\\.\\ Aucun\\ traitement\\ des\\ fichiers\\ suspects\\ ou\\ du\\ cache\\ ne\\ sera\\ tenté\\.$",
        "English": "The first step could not be completed. Suspicious files and cache will be left untouched.",
        "Count": 0,
        "Weight": 110
    },
    {
        "French": "Modules : session Windows courante seulement ; processus protégés ou disparus signalés comme non vérifiables.",
        "Pattern": "^Modules\\ :\\ session\\ Windows\\ courante\\ seulement\\ ;\\ processus\\ protégés\\ ou\\ disparus\\ signalés\\ comme\\ non\\ vérifiables\\.$",
        "English": "Modules: current Windows session only; protected or exited processes are reported as unverifiable.",
        "Count": 0,
        "Weight": 109
    },
    {
        "French": "Les fichiers ciblés seront supprimés définitivement, sans copie conservée. Leur liste figure dans le rapport.",
        "Pattern": "^Les\\ fichiers\\ ciblés\\ seront\\ supprimés\\ définitivement,\\ sans\\ copie\\ conservée\\.\\ Leur\\ liste\\ figure\\ dans\\ le\\ rapport\\.$",
        "English": "Targeted files will be deleted permanently, without keeping copies. The report lists them.",
        "Count": 0,
        "Weight": 109
    },
    {
        "French": "Cela retire le jeu de son chemin habituel mais ne libère pas l espace disque et ne nettoie pas tout Windows.",
        "Pattern": "^Cela\\ retire\\ le\\ jeu\\ de\\ son\\ chemin\\ habituel\\ mais\\ ne\\ libère\\ pas\\ l\\ espace\\ disque\\ et\\ ne\\ nettoie\\ pas\\ tout\\ Windows\\.$",
        "English": "This removes the game from its original path but does not free disk space or clean all of Windows.",
        "Count": 0,
        "Weight": 108
    },
    {
        "French": "Fermez NIKKE et les navigateurs après avoir enregistré vos travaux. Aucun processus ne sera arrêté de force.",
        "Pattern": "^Fermez\\ NIKKE\\ et\\ les\\ navigateurs\\ après\\ avoir\\ enregistré\\ vos\\ travaux\\.\\ Aucun\\ processus\\ ne\\ sera\\ arrêté\\ de\\ force\\.$",
        "English": "Close NIKKE and browsers after saving your work. No process will be forcibly stopped.",
        "Count": 0,
        "Weight": 108
    },
    {
        "French": "Les caches NIKKE et le profil CEF sont vérifiés même sans le jeu : stockage local, scripts et traces réseau.",
        "Pattern": "^Les\\ caches\\ NIKKE\\ et\\ le\\ profil\\ CEF\\ sont\\ vérifiés\\ même\\ sans\\ le\\ jeu\\ :\\ stockage\\ local,\\ scripts\\ et\\ traces\\ réseau\\.$",
        "English": "NIKKE launcher caches and the CEF profile are checked even without the game: local storage, scripts and network traces.",
        "Count": 0,
        "Weight": 108
    },
    {
        "French": "Le programme reste installé. NikkeTrace ne le ferme pas et ne modifie pas les réglages généraux du pare-feu.",
        "Pattern": "^Le\\ programme\\ reste\\ installé\\.\\ NikkeTrace\\ ne\\ le\\ ferme\\ pas\\ et\\ ne\\ modifie\\ pas\\ les\\ réglages\\ généraux\\ du\\ pare\\-feu\\.$",
        "English": "The program stays installed. NikkeTrace does not close it or change general firewall settings.",
        "Count": 0,
        "Weight": 108
    },
    {
        "French": "Commencez par la messagerie et le gestionnaire de mots de passe, puis comptes importants, Discord et NIKKE.",
        "Pattern": "^Commencez\\ par\\ la\\ messagerie\\ et\\ le\\ gestionnaire\\ de\\ mots\\ de\\ passe,\\ puis\\ comptes\\ importants,\\ Discord\\ et\\ NIKKE\\.$",
        "English": "Start with email and your password manager, then important accounts, Discord and NIKKE.",
        "Count": 0,
        "Weight": 107
    },
    {
        "French": "Les autres comptes Windows, profils personnalisés non indiqués et variantes inconnues ne sont pas couverts.",
        "Pattern": "^Les\\ autres\\ comptes\\ Windows,\\ profils\\ personnalisés\\ non\\ indiqués\\ et\\ variantes\\ inconnues\\ ne\\ sont\\ pas\\ couverts\\.$",
        "English": "Other Windows accounts, unspecified custom profiles and unknown variants are outside the checked scope.",
        "Count": 0,
        "Weight": 107
    },
    {
        "French": "Le cache du lanceur concerné sera renommé sur place. Ses réglages et connexions peuvent être réinitialisés.",
        "Pattern": "^Le\\ cache\\ du\\ lanceur\\ concerné\\ sera\\ renommé\\ sur\\ place\\.\\ Ses\\ réglages\\ et\\ connexions\\ peuvent\\ être\\ réinitialisés\\.$",
        "English": "The affected launcher cache will be renamed in place. Its settings and sign-ins may be reset.",
        "Count": 0,
        "Weight": 107
    },
    {
        "French": "Seule la DLL Chrome dans un sous-dossier de 64 caractères hexadécimaux est admise au nettoyage automatique.",
        "Pattern": "^Seule\\ la\\ DLL\\ Chrome\\ dans\\ un\\ sous\\-dossier\\ de\\ 64\\ caractères\\ hexadécimaux\\ est\\ admise\\ au\\ nettoyage\\ automatique\\.$",
        "English": "Only the Chrome DLL in a subfolder named with 64 hexadecimal characters qualifies for automatic cleanup.",
        "Count": 0,
        "Weight": 107
    },
    {
        "French": "Programmes en cours : {0} programme(s) non inspecté(s). Cette limite ne signifie pas qu un virus a été trouvé.",
        "Pattern": "^Programmes\\ en\\ cours\\ :\\ (?<v0>.*?)\\ programme\\(s\\)\\ non\\ inspecté\\(s\\)\\.\\ Cette\\ limite\\ ne\\ signifie\\ pas\\ qu\\ un\\ virus\\ a\\ été\\ trouvé\\.$",
        "English": "Running programs: {0} program(s) could not be inspected. This limitation does not mean a virus was found.",
        "Count": 1,
        "Weight": 107
    },
    {
        "French": "Le contrôle reste possible si le jeu a déjà été désinstallé. Ne le réinstallez pas pour cette vérification.",
        "Pattern": "^Le\\ contrôle\\ reste\\ possible\\ si\\ le\\ jeu\\ a\\ déjà\\ été\\ désinstallé\\.\\ Ne\\ le\\ réinstallez\\ pas\\ pour\\ cette\\ vérification\\.$",
        "English": "Checks still work if the game has been uninstalled. Do not reinstall it for this check.",
        "Count": 0,
        "Weight": 107
    },
    {
        "French": "Aucun journal du jeu trouvé. Les navigateurs, le registre et les temporaires ont quand même été contrôlés.",
        "Pattern": "^Aucun\\ journal\\ du\\ jeu\\ trouvé\\.\\ Les\\ navigateurs,\\ le\\ registre\\ et\\ les\\ temporaires\\ ont\\ quand\\ même\\ été\\ contrôlés\\.$",
        "English": "No game log found. Browsers, registry and temporary files were still checked.",
        "Count": 0,
        "Weight": 106
    },
    {
        "French": "Fichiers renommés, variantes inconnues, profils personnalisés non indiqués et autres comptes non couverts.",
        "Pattern": "^Fichiers\\ renommés,\\ variantes\\ inconnues,\\ profils\\ personnalisés\\ non\\ indiqués\\ et\\ autres\\ comptes\\ non\\ couverts\\.$",
        "English": "Renamed files, unknown variants, unspecified custom profiles and other accounts are outside the checked scope.",
        "Count": 0,
        "Weight": 106
    },
    {
        "French": "Si le navigateur est déjà ouvert : Chrome chrome://version ; Edge edge://version ; Firefox about:profiles.",
        "Pattern": "^Si\\ le\\ navigateur\\ est\\ déjà\\ ouvert\\ :\\ Chrome\\ chrome://version\\ ;\\ Edge\\ edge://version\\ ;\\ Firefox\\ about:profiles\\.$",
        "English": "If already open: Chrome chrome://version ; Edge edge://version ; Firefox about:profiles.",
        "Count": 0,
        "Weight": 106
    },
    {
        "French": "Blocage non confirmé ou demande administrateur annulée. Aucun résultat de protection ne peut être garanti.",
        "Pattern": "^Blocage\\ non\\ confirmé\\ ou\\ demande\\ administrateur\\ annulée\\.\\ Aucun\\ résultat\\ de\\ protection\\ ne\\ peut\\ être\\ garanti\\.$",
        "English": "Block not confirmed or administrator prompt cancelled. No protection result can be guaranteed.",
        "Count": 0,
        "Weight": 106
    },
    {
        "French": "Aucune trace actuelle à retirer automatiquement. La réinitialisation du cache est proposée par précaution.",
        "Pattern": "^Aucune\\ trace\\ actuelle\\ à\\ retirer\\ automatiquement\\.\\ La\\ réinitialisation\\ du\\ cache\\ est\\ proposée\\ par\\ précaution\\.$",
        "English": "No current trace can be removed automatically. Resetting the cache is offered as a precaution.",
        "Count": 0,
        "Weight": 106
    },
    {
        "French": "  Conseil : cette zone reste non vérifiée. Si la limite persiste, demandez une assistance avec ce rapport.",
        "Pattern": "^\\ \\ Conseil\\ :\\ cette\\ zone\\ reste\\ non\\ vérifiée\\.\\ Si\\ la\\ limite\\ persiste,\\ demandez\\ une\\ assistance\\ avec\\ ce\\ rapport\\.$",
        "English": "  Advice: this area remains unchecked. If the limitation persists, ask for help with this report.",
        "Count": 0,
        "Weight": 106
    },
    {
        "French": "Enregistrez vos travaux : elle redémarrera le PC. Si le disque est chiffré, préparez votre clé BitLocker.",
        "Pattern": "^Enregistrez\\ vos\\ travaux\\ :\\ elle\\ redémarrera\\ le\\ PC\\.\\ Si\\ le\\ disque\\ est\\ chiffré,\\ préparez\\ votre\\ clé\\ BitLocker\\.$",
        "English": "Save your work: it will restart the PC. If the drive is encrypted, prepare your BitLocker recovery key.",
        "Count": 0,
        "Weight": 105
    },
    {
        "French": "Une empreinte DLL différente ne suffit pas à exclure cette attaque : la DLL peut varier selon la victime.",
        "Pattern": "^Une\\ empreinte\\ DLL\\ différente\\ ne\\ suffit\\ pas\\ à\\ exclure\\ cette\\ attaque\\ :\\ la\\ DLL\\ peut\\ varier\\ selon\\ la\\ victime\\.$",
        "English": "A different DLL fingerprint does not rule out this attack: the DLL may vary by victim.",
        "Count": 0,
        "Weight": 105
    },
    {
        "French": "En cas de traces : coupez Ethernet/Wi-Fi, ne relancez pas le jeu, ne saisissez pas de secrets sur ce PC.",
        "Pattern": "^En\\ cas\\ de\\ traces\\ :\\ coupez\\ Ethernet/Wi\\-Fi,\\ ne\\ relancez\\ pas\\ le\\ jeu,\\ ne\\ saisissez\\ pas\\ de\\ secrets\\ sur\\ ce\\ PC\\.$",
        "English": "If indicators are found: disconnect Ethernet/Wi-Fi, do not launch the game or enter secrets on this PC.",
        "Count": 0,
        "Weight": 104
    },
    {
        "French": "Contrôles TCP/DNS via les API Windows ; aucun accès aux domaines signalés, aucune modification de hosts.",
        "Pattern": "^Contrôles\\ TCP/DNS\\ via\\ les\\ API\\ Windows\\ ;\\ aucun\\ accès\\ aux\\ domaines\\ signalés,\\ aucune\\ modification\\ de\\ hosts\\.$",
        "English": "TCP/DNS checks use Windows APIs; reported domains are not contacted and hosts is not modified.",
        "Count": 0,
        "Weight": 104
    },
    {
        "French": "Ce blocage ne supprime pas une infection et ne bloque pas les connexions directes vers les IP signalées.",
        "Pattern": "^Ce\\ blocage\\ ne\\ supprime\\ pas\\ une\\ infection\\ et\\ ne\\ bloque\\ pas\\ les\\ connexions\\ directes\\ vers\\ les\\ IP\\ signalées\\.$",
        "English": "This block does not remove an infection or block direct connections to the reported IPs.",
        "Count": 0,
        "Weight": 104
    },
    {
        "French": "Ces règles bloquent localement les noms indiqués, pour IPv4 et IPv6. Aucun autre domaine ne sera ajouté.",
        "Pattern": "^Ces\\ règles\\ bloquent\\ localement\\ les\\ noms\\ indiqués,\\ pour\\ IPv4\\ et\\ IPv6\\.\\ Aucun\\ autre\\ domaine\\ ne\\ sera\\ ajouté\\.$",
        "English": "These rules locally block the listed names for IPv4 and IPv6. No other domain will be added.",
        "Count": 0,
        "Weight": 104
    },
    {
        "French": "Une règle existante entre en conflit avec un domaine signalé. Aucune entrée existante ne sera remplacée.",
        "Pattern": "^Une\\ règle\\ existante\\ entre\\ en\\ conflit\\ avec\\ un\\ domaine\\ signalé\\.\\ Aucune\\ entrée\\ existante\\ ne\\ sera\\ remplacée\\.$",
        "English": "An existing rule conflicts with a reported domain. No existing entry will be replaced.",
        "Count": 0,
        "Weight": 104
    },
    {
        "French": "Sécurité Windows > Protection contre les virus et menaces > Options d analyse > analyse hors connexion.",
        "Pattern": "^Sécurité\\ Windows\\ >\\ Protection\\ contre\\ les\\ virus\\ et\\ menaces\\ >\\ Options\\ d\\ analyse\\ >\\ analyse\\ hors\\ connexion\\.$",
        "English": "Windows Security > Virus & threat protection > Scan options > Offline scan.",
        "Count": 0,
        "Weight": 103
    },
    {
        "French": "Un correctif côté serveur ne nettoie pas un PC déjà exposé ; le cache peut conserver un ancien fichier.",
        "Pattern": "^Un\\ correctif\\ côté\\ serveur\\ ne\\ nettoie\\ pas\\ un\\ PC\\ déjà\\ exposé\\ ;\\ le\\ cache\\ peut\\ conserver\\ un\\ ancien\\ fichier\\.$",
        "English": "A server-side fix does not clean an exposed PC; the cache may retain an old file.",
        "Count": 0,
        "Weight": 103
    },
    {
        "French": "Enregistrez vos travaux et formulaires avant d accepter ; les téléchargements peuvent être interrompus.",
        "Pattern": "^Enregistrez\\ vos\\ travaux\\ et\\ formulaires\\ avant\\ d\\ accepter\\ ;\\ les\\ téléchargements\\ peuvent\\ être\\ interrompus\\.$",
        "English": "Save your work and forms before accepting; downloads may be interrupted.",
        "Count": 0,
        "Weight": 103
    },
    {
        "French": "Les règles attendues n ont pas été confirmées dans hosts. Le rapport contient le détail de l opération.",
        "Pattern": "^Les\\ règles\\ attendues\\ n\\ ont\\ pas\\ été\\ confirmées\\ dans\\ hosts\\.\\ Le\\ rapport\\ contient\\ le\\ détail\\ de\\ l\\ opération\\.$",
        "English": "The expected rules have not been confirmed in hosts. Operation details are available in the report.",
        "Count": 0,
        "Weight": 103
    },
    {
        "French": "Le choix 1 recherche les traces connues, affiche un bilan puis propose un nettoyage après confirmation.",
        "Pattern": "^Le\\ choix\\ 1\\ recherche\\ les\\ traces\\ connues,\\ affiche\\ un\\ bilan\\ puis\\ propose\\ un\\ nettoyage\\ après\\ confirmation\\.$",
        "English": "Option 1 checks known traces, shows a summary, then offers cleanup after confirmation.",
        "Count": 0,
        "Weight": 103
    },
    {
        "French": "Demande de fermeture envoyée. La vérification continue ; validez toute confirmation dans le navigateur.",
        "Pattern": "^Demande\\ de\\ fermeture\\ envoyée\\.\\ La\\ vérification\\ continue\\ ;\\ validez\\ toute\\ confirmation\\ dans\\ le\\ navigateur\\.$",
        "English": "Close request sent. Checking continues; respond to any confirmation in your browser.",
        "Count": 0,
        "Weight": 103
    },
    {
        "French": "  Changez les mots de passe concernés, déconnectez les sessions et activez la double authentification.",
        "Pattern": "^\\ \\ Changez\\ les\\ mots\\ de\\ passe\\ concernés,\\ déconnectez\\ les\\ sessions\\ et\\ activez\\ la\\ double\\ authentification\\.$",
        "English": "  Change affected passwords, sign out sessions and enable two-factor authentication.",
        "Count": 0,
        "Weight": 102
    },
    {
        "French": "Signatures non validées ici sur un échantillon réel. Aucun accès aux mots de passe, cookies ou jetons.",
        "Pattern": "^Signatures\\ non\\ validées\\ ici\\ sur\\ un\\ échantillon\\ réel\\.\\ Aucun\\ accès\\ aux\\ mots\\ de\\ passe,\\ cookies\\ ou\\ jetons\\.$",
        "English": "Signatures were not validated here against a real sample. No passwords, cookies or tokens are accessed.",
        "Count": 0,
        "Weight": 102
    },
    {
        "French": "  Réseau, DNS et hosts : un indice seul ne prouve pas une infection ; aucune connexion externe lancée.",
        "Pattern": "^\\ \\ Réseau,\\ DNS\\ et\\ hosts\\ :\\ un\\ indice\\ seul\\ ne\\ prouve\\ pas\\ une\\ infection\\ ;\\ aucune\\ connexion\\ externe\\ lancée\\.$",
        "English": "  Network, DNS and hosts: an indicator alone does not establish infection; no external connection initiated.",
        "Count": 0,
        "Weight": 102
    },
    {
        "French": "  Une exposition passée a été relevée précédemment : le changement des mots de passe reste nécessaire.",
        "Pattern": "^\\ \\ Une\\ exposition\\ passée\\ a\\ été\\ relevée\\ précédemment\\ :\\ le\\ changement\\ des\\ mots\\ de\\ passe\\ reste\\ nécessaire\\.$",
        "English": "  Past exposure was found earlier: changing affected passwords remains necessary.",
        "Count": 0,
        "Weight": 102
    },
    {
        "French": "Suppression définitive : vous pourrez être déconnecté du lanceur et ses réglages seront réinitialisés.",
        "Pattern": "^Suppression\\ définitive\\ :\\ vous\\ pourrez\\ être\\ déconnecté\\ du\\ lanceur\\ et\\ ses\\ réglages\\ seront\\ réinitialisés\\.$",
        "English": "Permanent deletion: you may be signed out of the launcher and its settings will be reset.",
        "Count": 0,
        "Weight": 102
    },
    {
        "French": "Ce résultat concerne les traces connues et le périmètre vérifié, sans certification de sécurité du PC.",
        "Pattern": "^Ce\\ résultat\\ concerne\\ les\\ traces\\ connues\\ et\\ le\\ périmètre\\ vérifié,\\ sans\\ certification\\ de\\ sécurité\\ du\\ PC\\.$",
        "English": "This result covers known traces within the checked scope; it does not certify that the PC is secure.",
        "Count": 0,
        "Weight": 102
    },
    {
        "French": "À faire : restez hors ligne et examinez le nettoyage proposé. Une analyse antivirus reste recommandée.",
        "Pattern": "^À\\ faire\\ :\\ restez\\ hors\\ ligne\\ et\\ examinez\\ le\\ nettoyage\\ proposé\\.\\ Une\\ analyse\\ antivirus\\ reste\\ recommandée\\.$",
        "English": "Next: stay offline and review the proposed cleanup. An antivirus scan is still recommended.",
        "Count": 0,
        "Weight": 102
    },
    {
        "French": "Le cache NIKKE est aussi vérifié sans le jeu : marqueur k2f.agent.state, sans extraction des secrets.",
        "Pattern": "^Le\\ cache\\ NIKKE\\ est\\ aussi\\ vérifié\\ sans\\ le\\ jeu\\ :\\ marqueur\\ k2f\\.agent\\.state,\\ sans\\ extraction\\ des\\ secrets\\.$",
        "English": "The NIKKE cache is checked even without the game: k2f.agent.state marker only, without extracting secret values.",
        "Count": 0,
        "Weight": 101
    },
    {
        "French": "Le format du fichier hosts n est pas pris en charge. Aucune réécriture automatique ne sera effectuée.",
        "Pattern": "^Le\\ format\\ du\\ fichier\\ hosts\\ n\\ est\\ pas\\ pris\\ en\\ charge\\.\\ Aucune\\ réécriture\\ automatique\\ ne\\ sera\\ effectuée\\.$",
        "English": "The hosts file format is not supported. The file will not be rewritten automatically.",
        "Count": 0,
        "Weight": 101
    },
    {
        "French": "[C] Nettoyage guidé   [V] Revérifier   [R] Rapport   [D] Détails   [A] Options avancées   [Q] Quitter",
        "Pattern": "^\\[C\\]\\ Nettoyage\\ guidé\\ \\ \\ \\[V\\]\\ Revérifier\\ \\ \\ \\[R\\]\\ Rapport\\ \\ \\ \\[D\\]\\ Détails\\ \\ \\ \\[A\\]\\ Options\\ avancées\\ \\ \\ \\[Q\\]\\ Quitter$",
        "English": "[C] Guided cleanup   [V] Recheck   [R] Report   [D] Details   [A] Advanced options   [Q] Quit",
        "Count": 0,
        "Weight": 101
    },
    {
        "French": "  Attente prolongée. Ctrl+C permet d interrompre ; un contrôle interrompu ne confirme aucun résultat.",
        "Pattern": "^\\ \\ Attente\\ prolongée\\.\\ Ctrl\\+C\\ permet\\ d\\ interrompre\\ ;\\ un\\ contrôle\\ interrompu\\ ne\\ confirme\\ aucun\\ résultat\\.$",
        "English": "  This is taking longer. Press Ctrl+C to interrupt; an interrupted check has no confirmed result.",
        "Count": 0,
        "Weight": 101
    },
    {
        "French": "Changez les mots de passe concernés, déconnectez les sessions et activez la double authentification.",
        "Pattern": "^Changez\\ les\\ mots\\ de\\ passe\\ concernés,\\ déconnectez\\ les\\ sessions\\ et\\ activez\\ la\\ double\\ authentification\\.$",
        "English": "Change affected passwords, sign out sessions and enable two-factor authentication.",
        "Count": 0,
        "Weight": 100
    },
    {
        "French": "Aucun profil habituel trouvé pour les navigateurs sélectionnés ; profils personnalisés non couverts.",
        "Pattern": "^Aucun\\ profil\\ habituel\\ trouvé\\ pour\\ les\\ navigateurs\\ sélectionnés\\ ;\\ profils\\ personnalisés\\ non\\ couverts\\.$",
        "English": "No standard profile found for the selected browsers; custom profiles may be outside the checked locations.",
        "Count": 0,
        "Weight": 100
    },
    {
        "French": "Consultez le rapport si un contrôle reste incomplet ; cela ne signifie pas à lui seul une infection.",
        "Pattern": "^Consultez\\ le\\ rapport\\ si\\ un\\ contrôle\\ reste\\ incomplet\\ ;\\ cela\\ ne\\ signifie\\ pas\\ à\\ lui\\ seul\\ une\\ infection\\.$",
        "English": "Consult the report if a check remains incomplete; this alone does not indicate infection.",
        "Count": 0,
        "Weight": 100
    },
    {
        "French": "Des règles peuvent déjà être présentes. Vous pouvez demander leur retrait dans les options avancées.",
        "Pattern": "^Des\\ règles\\ peuvent\\ déjà\\ être\\ présentes\\.\\ Vous\\ pouvez\\ demander\\ leur\\ retrait\\ dans\\ les\\ options\\ avancées\\.$",
        "English": "Some rules may already be present. You can request their removal in Advanced options.",
        "Count": 0,
        "Weight": 100
    },
    {
        "French": "1 Tous les navigateurs (recommandé) | 2 Chrome | 3 Edge | 4 Firefox | 5 Brave | 6 Opera | 7 Vivaldi",
        "Pattern": "^1\\ Tous\\ les\\ navigateurs\\ \\(recommandé\\)\\ \\|\\ 2\\ Chrome\\ \\|\\ 3\\ Edge\\ \\|\\ 4\\ Firefox\\ \\|\\ 5\\ Brave\\ \\|\\ 6\\ Opera\\ \\|\\ 7\\ Vivaldi$",
        "English": "1 All browsers (recommended) | 2 Chrome | 3 Edge | 4 Firefox | 5 Brave | 6 Opera | 7 Vivaldi",
        "Count": 0,
        "Weight": 99
    },
    {
        "French": "Fermez NIKKE et ses processus avant de continuer. Ne lancez aucun exécutable de la copie conservée.",
        "Pattern": "^Fermez\\ NIKKE\\ et\\ ses\\ processus\\ avant\\ de\\ continuer\\.\\ Ne\\ lancez\\ aucun\\ exécutable\\ de\\ la\\ copie\\ conservée\\.$",
        "English": "Close NIKKE and its processes before continuing. Do not run executables from the retained copy.",
        "Count": 0,
        "Weight": 99
    },
    {
        "French": "Pour compléter : faites ensuite une analyse antivirus, notamment Microsoft Defender hors connexion.",
        "Pattern": "^Pour\\ compléter\\ :\\ faites\\ ensuite\\ une\\ analyse\\ antivirus,\\ notamment\\ Microsoft\\ Defender\\ hors\\ connexion\\.$",
        "English": "For an additional check, run an antivirus scan such as Microsoft Defender Offline yourself.",
        "Count": 0,
        "Weight": 99
    },
    {
        "French": "Les données des autres applications, les navigateurs et les éléments non reconnus seront conservés.",
        "Pattern": "^Les\\ données\\ des\\ autres\\ applications,\\ les\\ navigateurs\\ et\\ les\\ éléments\\ non\\ reconnus\\ seront\\ conservés\\.$",
        "English": "Other applications' data, browsers and unrecognized items will be preserved.",
        "Count": 0,
        "Weight": 99
    },
    {
        "French": "Il ne bloque pas les sites. Ce blocage facultatif est proposé séparément dans les options avancées.",
        "Pattern": "^Il\\ ne\\ bloque\\ pas\\ les\\ sites\\.\\ Ce\\ blocage\\ facultatif\\ est\\ proposé\\ séparément\\ dans\\ les\\ options\\ avancées\\.$",
        "English": "It does not block websites. Optional blocking is offered separately in advanced options.",
        "Count": 0,
        "Weight": 99
    },
    {
        "French": "Le retrait du jeu et du lanceur sera proposé séparément. Il ne sera jamais fait sans votre accord.",
        "Pattern": "^Le\\ retrait\\ du\\ jeu\\ et\\ du\\ lanceur\\ sera\\ proposé\\ séparément\\.\\ Il\\ ne\\ sera\\ jamais\\ fait\\ sans\\ votre\\ accord\\.$",
        "English": "Removing the game and launcher will be offered separately. It will never happen without your consent.",
        "Count": 0,
        "Weight": 98
    },
    {
        "French": "Une vérification incomplète ne permet pas de conclure à l absence de trace dans la zone concernée.",
        "Pattern": "^Une\\ vérification\\ incomplète\\ ne\\ permet\\ pas\\ de\\ conclure\\ à\\ l\\ absence\\ de\\ trace\\ dans\\ la\\ zone\\ concernée\\.$",
        "English": "An incomplete check cannot establish that the affected area contains no traces.",
        "Count": 0,
        "Weight": 98
    },
    {
        "French": "Ancienne copie du dossier NIKKE à examiner manuellement ; elle ne sera pas effacée automatiquement",
        "Pattern": "^Ancienne\\ copie\\ du\\ dossier\\ NIKKE\\ à\\ examiner\\ manuellement\\ ;\\ elle\\ ne\\ sera\\ pas\\ effacée\\ automatiquement$",
        "English": "Old NIKKE folder copy needs manual review; it will not be deleted automatically",
        "Count": 0,
        "Weight": 98
    },
    {
        "French": "  Aucun fichier ou élément de registre suspect à comparer ; les journaux sont traités séparément.",
        "Pattern": "^\\ \\ Aucun\\ fichier\\ ou\\ élément\\ de\\ registre\\ suspect\\ à\\ comparer\\ ;\\ les\\ journaux\\ sont\\ traités\\ séparément\\.$",
        "English": "  No suspicious file or registry item to compare; logs are handled separately.",
        "Count": 0,
        "Weight": 97
    },
    {
        "French": "  ÉCHEC de la revérification : aucun nettoyage ne peut être confirmé. Consulter Sécurité Windows.",
        "Pattern": "^\\ \\ ÉCHEC\\ de\\ la\\ revérification\\ :\\ aucun\\ nettoyage\\ ne\\ peut\\ être\\ confirmé\\.\\ Consulter\\ Sécurité\\ Windows\\.$",
        "English": "  RECHECK FAILED: cleanup cannot be confirmed. Check Windows Security.",
        "Count": 0,
        "Weight": 97
    },
    {
        "French": "Defender doit être principal et actif, et WinRE disponible. Windows ARM n est pas pris en charge.",
        "Pattern": "^Defender\\ doit\\ être\\ principal\\ et\\ actif,\\ et\\ WinRE\\ disponible\\.\\ Windows\\ ARM\\ n\\ est\\ pas\\ pris\\ en\\ charge\\.$",
        "English": "Defender must be the active primary antivirus, and WinRE available. Windows ARM is not supported.",
        "Count": 0,
        "Weight": 97
    },
    {
        "French": "Effectuez ces changements sur les sites officiels, depuis un téléphone ou un autre appareil sain.",
        "Pattern": "^Effectuez\\ ces\\ changements\\ sur\\ les\\ sites\\ officiels,\\ depuis\\ un\\ téléphone\\ ou\\ un\\ autre\\ appareil\\ sain\\.$",
        "English": "Make these changes on official websites, using a phone or another clean device.",
        "Count": 0,
        "Weight": 97
    },
    {
        "French": "  Un précédent contrôle a relevé un marqueur NIKKE : le risque pour les comptes reste à traiter.",
        "Pattern": "^\\ \\ Un\\ précédent\\ contrôle\\ a\\ relevé\\ un\\ marqueur\\ NIKKE\\ :\\ le\\ risque\\ pour\\ les\\ comptes\\ reste\\ à\\ traiter\\.$",
        "English": "  An earlier check found a NIKKE indicator: possible account exposure still needs attention.",
        "Count": 0,
        "Weight": 96
    },
    {
        "French": "Commencez par votre messagerie, puis Google/Microsoft, Discord, NIKKE et vos comptes importants.",
        "Pattern": "^Commencez\\ par\\ votre\\ messagerie,\\ puis\\ Google/Microsoft,\\ Discord,\\ NIKKE\\ et\\ vos\\ comptes\\ importants\\.$",
        "English": "Start with your email, then Google/Microsoft, Discord, NIKKE and your important accounts.",
        "Count": 0,
        "Weight": 96
    },
    {
        "French": "Ancien journal absent : l historique ne peut plus être vérifié, notamment après désinstallation.",
        "Pattern": "^Ancien\\ journal\\ absent\\ :\\ l\\ historique\\ ne\\ peut\\ plus\\ être\\ vérifié,\\ notamment\\ après\\ désinstallation\\.$",
        "English": "Old log missing: past activity can no longer be checked, including after an uninstall.",
        "Count": 0,
        "Weight": 96
    },
    {
        "French": "Des traces anciennes ont été trouvées. Elles ne prouvent pas une activité malveillante actuelle.",
        "Pattern": "^Des\\ traces\\ anciennes\\ ont\\ été\\ trouvées\\.\\ Elles\\ ne\\ prouvent\\ pas\\ une\\ activité\\ malveillante\\ actuelle\\.$",
        "English": "Old traces were found. They do not prove current malicious activity.",
        "Count": 0,
        "Weight": 96
    },
    {
        "French": "Seules les règles créées par cette option seront retirées. Les autres blocages seront conservés.",
        "Pattern": "^Seules\\ les\\ règles\\ créées\\ par\\ cette\\ option\\ seront\\ retirées\\.\\ Les\\ autres\\ blocages\\ seront\\ conservés\\.$",
        "English": "Only rules created by this option will be removed. Other blocks will be preserved.",
        "Count": 0,
        "Weight": 96
    },
    {
        "French": "Aucun fichier ou élément de registre suspect à comparer ; les journaux sont traités séparément.",
        "Pattern": "^Aucun\\ fichier\\ ou\\ élément\\ de\\ registre\\ suspect\\ à\\ comparer\\ ;\\ les\\ journaux\\ sont\\ traités\\ séparément\\.$",
        "English": "No suspicious file or registry item to compare; logs are handled separately.",
        "Count": 0,
        "Weight": 95
    },
    {
        "French": "ÉCHEC de la revérification : aucun nettoyage ne peut être confirmé. Consulter Sécurité Windows.",
        "Pattern": "^ÉCHEC\\ de\\ la\\ revérification\\ :\\ aucun\\ nettoyage\\ ne\\ peut\\ être\\ confirmé\\.\\ Consulter\\ Sécurité\\ Windows\\.$",
        "English": "RECHECK FAILED: cleanup cannot be confirmed. Check Windows Security.",
        "Count": 0,
        "Weight": 95
    },
    {
        "French": "Compte courant, profils usuels et registre HKCU/HKLM 32/64 ; CLSID Windows HKLM légitime exclu.",
        "Pattern": "^Compte\\ courant,\\ profils\\ usuels\\ et\\ registre\\ HKCU/HKLM\\ 32/64\\ ;\\ CLSID\\ Windows\\ HKLM\\ légitime\\ exclu\\.$",
        "English": "Current account, standard profiles and HKCU/HKLM registry in 32/64-bit views; the legitimate Windows HKLM CLSID is excluded.",
        "Count": 0,
        "Weight": 95
    },
    {
        "French": "Consultez le rapport pour le détail ; aucun retrait non confirmé ne sera annoncé comme réussi.",
        "Pattern": "^Consultez\\ le\\ rapport\\ pour\\ le\\ détail\\ ;\\ aucun\\ retrait\\ non\\ confirmé\\ ne\\ sera\\ annoncé\\ comme\\ réussi\\.$",
        "English": "See the report for details; an unconfirmed removal will never be reported as successful.",
        "Count": 0,
        "Weight": 94
    },
    {
        "French": "Un précédent contrôle a relevé un marqueur NIKKE : le risque pour les comptes reste à traiter.",
        "Pattern": "^Un\\ précédent\\ contrôle\\ a\\ relevé\\ un\\ marqueur\\ NIKKE\\ :\\ le\\ risque\\ pour\\ les\\ comptes\\ reste\\ à\\ traiter\\.$",
        "English": "An earlier check found a NIKKE indicator: possible account exposure still needs attention.",
        "Count": 0,
        "Weight": 94
    },
    {
        "French": "La recherche peut continuer avec un navigateur ouvert. Aucun programme ne sera fermé de force.",
        "Pattern": "^La\\ recherche\\ peut\\ continuer\\ avec\\ un\\ navigateur\\ ouvert\\.\\ Aucun\\ programme\\ ne\\ sera\\ fermé\\ de\\ force\\.$",
        "English": "The check can continue with a browser open. No program will be forcibly closed.",
        "Count": 0,
        "Weight": 94
    },
    {
        "French": "Windows a refusé l accès au fichier hosts ou à sa sauvegarde. Le blocage n a pas été confirmé.",
        "Pattern": "^Windows\\ a\\ refusé\\ l\\ accès\\ au\\ fichier\\ hosts\\ ou\\ à\\ sa\\ sauvegarde\\.\\ Le\\ blocage\\ n\\ a\\ pas\\ été\\ confirmé\\.$",
        "English": "Windows denied access to the hosts file or its backup. Blocking has not been confirmed.",
        "Count": 0,
        "Weight": 94
    },
    {
        "French": "  - vous ne pourrez pas utiliser Windows ou Internet pendant l analyse (environ 15 minutes) ;",
        "Pattern": "^\\ \\ \\-\\ vous\\ ne\\ pourrez\\ pas\\ utiliser\\ Windows\\ ou\\ Internet\\ pendant\\ l\\ analyse\\ \\(environ\\ 15\\ minutes\\)\\ ;$",
        "English": "  - you cannot use Windows or browse the Internet during the scan (about 15 minutes);",
        "Count": 0,
        "Weight": 93
    },
    {
        "French": "AUCUNE TRACE CONNUE DETECTEE DANS LE PERIMETRE VERIFIE - aucune garantie que le PC soit sain.",
        "Pattern": "^AUCUNE\\ TRACE\\ CONNUE\\ DETECTEE\\ DANS\\ LE\\ PERIMETRE\\ VERIFIE\\ \\-\\ aucune\\ garantie\\ que\\ le\\ PC\\ soit\\ sain\\.$",
        "English": "NO KNOWN INDICATOR DETECTED IN THE CHECKED SCOPE — no guarantee that the PC is clean.",
        "Count": 0,
        "Weight": 93
    },
    {
        "French": "  État k2f.agent.state détecté : exposition passée possible, activité actuelle non démontrée.",
        "Pattern": "^\\ \\ État\\ k2f\\.agent\\.state\\ détecté\\ :\\ exposition\\ passée\\ possible,\\ activité\\ actuelle\\ non\\ démontrée\\.$",
        "English": "  k2f.agent.state detected: possible past exposure; current activity not established.",
        "Count": 0,
        "Weight": 93
    },
    {
        "French": "  Aucun marqueur brut connu dans le cache disponible ; cache absent ou compressé non probant.",
        "Pattern": "^\\ \\ Aucun\\ marqueur\\ brut\\ connu\\ dans\\ le\\ cache\\ disponible\\ ;\\ cache\\ absent\\ ou\\ compressé\\ non\\ probant\\.$",
        "English": "  No known raw marker in the available cache; absent or compressed cache is inconclusive.",
        "Count": 0,
        "Weight": 93
    },
    {
        "French": "vérification partielle ; cette limite seule ne signale pas un virus — détails dans le rapport",
        "Pattern": "^vérification\\ partielle\\ ;\\ cette\\ limite\\ seule\\ ne\\ signale\\ pas\\ un\\ virus\\ —\\ détails\\ dans\\ le\\ rapport$",
        "English": "partial check; this limitation alone does not indicate a virus — details in the report",
        "Count": 0,
        "Weight": 93
    },
    {
        "French": "Consultez le détail des traces et effectuez une analyse antivirus complète et hors connexion.",
        "Pattern": "^Consultez\\ le\\ détail\\ des\\ traces\\ et\\ effectuez\\ une\\ analyse\\ antivirus\\ complète\\ et\\ hors\\ connexion\\.$",
        "English": "Review the trace details, then run a full antivirus scan and an offline scan.",
        "Count": 0,
        "Weight": 93
    },
    {
        "French": "  Aucun élément suspect à comparer ; les anciennes traces restent détaillées dans le rapport.",
        "Pattern": "^\\ \\ Aucun\\ élément\\ suspect\\ à\\ comparer\\ ;\\ les\\ anciennes\\ traces\\ restent\\ détaillées\\ dans\\ le\\ rapport\\.$",
        "English": "  No suspicious item to compare; historical traces remain detailed in the report.",
        "Count": 0,
        "Weight": 93
    },
    {
        "French": "Aucun nettoyage ne peut être confirmé. Utilisez Sécurité Windows ou demandez une assistance.",
        "Pattern": "^Aucun\\ nettoyage\\ ne\\ peut\\ être\\ confirmé\\.\\ Utilisez\\ Sécurité\\ Windows\\ ou\\ demandez\\ une\\ assistance\\.$",
        "English": "Cleanup cannot be confirmed. Use Windows Security or seek assistance.",
        "Count": 0,
        "Weight": 92
    },
    {
        "French": "Cet outil communautaire recherche des traces connues ; il n est ni officiel ni un antivirus.",
        "Pattern": "^Cet\\ outil\\ communautaire\\ recherche\\ des\\ traces\\ connues\\ ;\\ il\\ n\\ est\\ ni\\ officiel\\ ni\\ un\\ antivirus\\.$",
        "English": "This community tool checks known indicators; it is neither official nor an antivirus.",
        "Count": 0,
        "Weight": 92
    },
    {
        "French": "Ne restaurez pas ou ne relancez pas cette copie avant les consignes de sécurité officielles.",
        "Pattern": "^Ne\\ restaurez\\ pas\\ ou\\ ne\\ relancez\\ pas\\ cette\\ copie\\ avant\\ les\\ consignes\\ de\\ sécurité\\ officielles\\.$",
        "English": "Do not restore or launch this copy before official security guidance is available.",
        "Count": 0,
        "Weight": 92
    },
    {
        "French": "DOMAINES DÉJÀ BLOQUÉS DANS HOSTS — aucune modification ni demande administrateur nécessaire.",
        "Pattern": "^DOMAINES\\ DÉJÀ\\ BLOQUÉS\\ DANS\\ HOSTS\\ —\\ aucune\\ modification\\ ni\\ demande\\ administrateur\\ nécessaire\\.$",
        "English": "DOMAINS ALREADY BLOCKED IN HOSTS — no change or administrator request needed.",
        "Count": 0,
        "Weight": 92
    },
    {
        "French": "Le retrait d un élément de démarrage suspect n a pas pu être confirmé. Consultez le rapport.",
        "Pattern": "^Le\\ retrait\\ d\\ un\\ élément\\ de\\ démarrage\\ suspect\\ n\\ a\\ pas\\ pu\\ être\\ confirmé\\.\\ Consultez\\ le\\ rapport\\.$",
        "English": "Removing a suspicious startup entry could not be confirmed. See the report.",
        "Count": 0,
        "Weight": 92
    },
    {
        "French": "Dans la liste des applications, cherchez NIKKE et son lanceur, puis choisissez Désinstaller.",
        "Pattern": "^Dans\\ la\\ liste\\ des\\ applications,\\ cherchez\\ NIKKE\\ et\\ son\\ lanceur,\\ puis\\ choisissez\\ Désinstaller\\.$",
        "English": "Find NIKKE and its launcher in the app list, then choose Uninstall.",
        "Count": 0,
        "Weight": 92
    },
    {
        "French": "Cela concerne uniquement tbs_browser.exe dans le lanceur NIKKE, pas Chrome, Edge ou Firefox.",
        "Pattern": "^Cela\\ concerne\\ uniquement\\ tbs_browser\\.exe\\ dans\\ le\\ lanceur\\ NIKKE,\\ pas\\ Chrome,\\ Edge\\ ou\\ Firefox\\.$",
        "English": "This only affects tbs_browser.exe in the NIKKE launcher, not Chrome, Edge or Firefox.",
        "Count": 0,
        "Weight": 92
    },
    {
        "French": "Blocage NikkeTrace retiré ; absence des règles confirmée. Les autres règles sont conservées.",
        "Pattern": "^Blocage\\ NikkeTrace\\ retiré\\ ;\\ absence\\ des\\ règles\\ confirmée\\.\\ Les\\ autres\\ règles\\ sont\\ conservées\\.$",
        "English": "NikkeTrace block removed; absence of its rules confirmed. Other rules are preserved.",
        "Count": 0,
        "Weight": 92
    },
    {
        "French": "- vous ne pourrez pas utiliser Windows ou Internet pendant l analyse (environ 15 minutes) ;",
        "Pattern": "^\\-\\ vous\\ ne\\ pourrez\\ pas\\ utiliser\\ Windows\\ ou\\ Internet\\ pendant\\ l\\ analyse\\ \\(environ\\ 15\\ minutes\\)\\ ;$",
        "English": "- you cannot use Windows or browse the Internet during the scan (about 15 minutes);",
        "Count": 0,
        "Weight": 91
    },
    {
        "French": "PlatformExperienceHelper seul et onominan.tmp ne sont pas des indicateurs de cette attaque.",
        "Pattern": "^PlatformExperienceHelper\\ seul\\ et\\ onominan\\.tmp\\ ne\\ sont\\ pas\\ des\\ indicateurs\\ de\\ cette\\ attaque\\.$",
        "English": "PlatformExperienceHelper alone and onominan.tmp are not indicators of this attack.",
        "Count": 0,
        "Weight": 91
    },
    {
        "French": "Contrôles TCP/DNS locaux ; blocage des domaines dans hosts uniquement sur accord explicite.",
        "Pattern": "^Contrôles\\ TCP/DNS\\ locaux\\ ;\\ blocage\\ des\\ domaines\\ dans\\ hosts\\ uniquement\\ sur\\ accord\\ explicite\\.$",
        "English": "Local TCP/DNS checks; domain blocking in hosts only with explicit consent.",
        "Count": 0,
        "Weight": 91
    },
    {
        "French": "Le dossier de récupération ne peut pas être préparé. Aucun fichier suspect ne sera déplacé.",
        "Pattern": "^Le\\ dossier\\ de\\ récupération\\ ne\\ peut\\ pas\\ être\\ préparé\\.\\ Aucun\\ fichier\\ suspect\\ ne\\ sera\\ déplacé\\.$",
        "English": "The recovery folder could not be prepared. No suspicious files will be moved.",
        "Count": 0,
        "Weight": 91
    },
    {
        "French": "Fichier correspondant aux critères du guide officiel ; empreinte malveillante non confirmée",
        "Pattern": "^Fichier\\ correspondant\\ aux\\ critères\\ du\\ guide\\ officiel\\ ;\\ empreinte\\ malveillante\\ non\\ confirmée$",
        "English": "File matches the official guide criteria; malicious hash not confirmed",
        "Count": 0,
        "Weight": 91
    },
    {
        "French": "Windows bloquera les connexions sortantes de ces programmes, pour tous les profils réseau :",
        "Pattern": "^Windows\\ bloquera\\ les\\ connexions\\ sortantes\\ de\\ ces\\ programmes,\\ pour\\ tous\\ les\\ profils\\ réseau\\ :$",
        "English": "Windows will block outbound connections from these programs on all network profiles:",
        "Count": 0,
        "Weight": 91
    },
    {
        "French": "  Cela signale une exposition possible ; cela ne décrit pas l état actuel des navigateurs.",
        "Pattern": "^\\ \\ Cela\\ signale\\ une\\ exposition\\ possible\\ ;\\ cela\\ ne\\ décrit\\ pas\\ l\\ état\\ actuel\\ des\\ navigateurs\\.$",
        "English": "  This suggests possible past exposure; it does not describe the current browser state.",
        "Count": 0,
        "Weight": 90
    },
    {
        "French": "Enregistrez vos travaux et fermez les navigateurs si possible, surtout avant un nettoyage.",
        "Pattern": "^Enregistrez\\ vos\\ travaux\\ et\\ fermez\\ les\\ navigateurs\\ si\\ possible,\\ surtout\\ avant\\ un\\ nettoyage\\.$",
        "English": "Save your work and close browsers if possible, especially before cleanup.",
        "Count": 0,
        "Weight": 90
    },
    {
        "French": "La proposition de fermeture des navigateurs n était pas disponible. La recherche continue.",
        "Pattern": "^La\\ proposition\\ de\\ fermeture\\ des\\ navigateurs\\ n\\ était\\ pas\\ disponible\\.\\ La\\ recherche\\ continue\\.$",
        "English": "The browser closing offer was unavailable. The check continues.",
        "Count": 0,
        "Weight": 90
    },
    {
        "French": "Anciennes sauvegardes de journaux conservées par NikkeTrace ; à examiner avant suppression",
        "Pattern": "^Anciennes\\ sauvegardes\\ de\\ journaux\\ conservées\\ par\\ NikkeTrace\\ ;\\ à\\ examiner\\ avant\\ suppression$",
        "English": "Old log backups retained by NikkeTrace; review before deleting",
        "Count": 0,
        "Weight": 90
    },
    {
        "French": "Aucun journal NIKKE lisible : exposition passée indéterminée, même après désinstallation.",
        "Pattern": "^Aucun\\ journal\\ NIKKE\\ lisible\\ :\\ exposition\\ passée\\ indéterminée,\\ même\\ après\\ désinstallation\\.$",
        "English": "No readable NIKKE log: past exposure remains unknown, even after uninstalling.",
        "Count": 0,
        "Weight": 89
    },
    {
        "French": "Par précaution : changez vos mots de passe depuis un appareil sain (conseils : option 5).",
        "Pattern": "^Par\\ précaution\\ :\\ changez\\ vos\\ mots\\ de\\ passe\\ depuis\\ un\\ appareil\\ sain\\ \\(conseils\\ :\\ option\\ 5\\)\\.$",
        "English": "As a precaution: change your passwords using a clean device (guidance: option 5).",
        "Count": 0,
        "Weight": 89
    },
    {
        "French": "Un cache ne peut pas être traité automatiquement. Les autres actions restent disponibles.",
        "Pattern": "^Un\\ cache\\ ne\\ peut\\ pas\\ être\\ traité\\ automatiquement\\.\\ Les\\ autres\\ actions\\ restent\\ disponibles\\.$",
        "English": "A cache cannot be handled automatically. Other actions remain available.",
        "Count": 0,
        "Weight": 89
    },
    {
        "French": "Nettoyage interrompu : aucun résultat global ne peut être confirmé. Consultez le rapport.",
        "Pattern": "^Nettoyage\\ interrompu\\ :\\ aucun\\ résultat\\ global\\ ne\\ peut\\ être\\ confirmé\\.\\ Consultez\\ le\\ rapport\\.$",
        "English": "Cleanup interrupted: an overall result cannot be confirmed. See the report.",
        "Count": 0,
        "Weight": 89
    },
    {
        "French": "Cette rubrique affiche des conseils ; NikkeTrace ne modifie aucun compte ni mot de passe.",
        "Pattern": "^Cette\\ rubrique\\ affiche\\ des\\ conseils\\ ;\\ NikkeTrace\\ ne\\ modifie\\ aucun\\ compte\\ ni\\ mot\\ de\\ passe\\.$",
        "English": "This section provides advice; NikkeTrace does not change any account or password.",
        "Count": 0,
        "Weight": 89
    },
    {
        "French": "Navigateur du lanceur non trouvé automatiquement. Vous pouvez indiquer le dossier du jeu.",
        "Pattern": "^Navigateur\\ du\\ lanceur\\ non\\ trouvé\\ automatiquement\\.\\ Vous\\ pouvez\\ indiquer\\ le\\ dossier\\ du\\ jeu\\.$",
        "English": "Launcher browser was not found automatically. You can enter the game folder.",
        "Count": 0,
        "Weight": 89
    },
    {
        "French": "Pour revenir en arrière : Options avancées > Accès Internet du navigateur du lanceur > Retirer le blocage.",
        "Pattern": "^Pour\\ revenir\\ en\\ arrière\\ :\\ Options\\ avancées\\ >\\ Retirer\\ le\\ blocage\\ du\\ navigateur\\ du\\ lanceur\\.$",
        "English": "To undo: Advanced options > Launcher browser Internet access > Remove the launcher browser block.",
        "Count": 0,
        "Weight": 89
    },
    {
        "French": "Cela signale une exposition possible ; cela ne décrit pas l état actuel des navigateurs.",
        "Pattern": "^Cela\\ signale\\ une\\ exposition\\ possible\\ ;\\ cela\\ ne\\ décrit\\ pas\\ l\\ état\\ actuel\\ des\\ navigateurs\\.$",
        "English": "This suggests possible past exposure; it does not describe the current browser state.",
        "Count": 0,
        "Weight": 88
    },
    {
        "French": "  - Windows redémarrera ensuite ; cela ne désactive pas définitivement votre connexion.",
        "Pattern": "^\\ \\ \\-\\ Windows\\ redémarrera\\ ensuite\\ ;\\ cela\\ ne\\ désactive\\ pas\\ définitivement\\ votre\\ connexion\\.$",
        "English": "  - Windows will start again afterwards; your connection is not permanently disabled.",
        "Count": 0,
        "Weight": 87
    },
    {
        "French": "Vous pouvez demander leur fermeture normale pour faciliter le contrôle et le nettoyage.",
        "Pattern": "^Vous\\ pouvez\\ demander\\ leur\\ fermeture\\ normale\\ pour\\ faciliter\\ le\\ contrôle\\ et\\ le\\ nettoyage\\.$",
        "English": "You can request a normal close to help with the check and cleanup.",
        "Count": 0,
        "Weight": 87
    },
    {
        "French": "[R] Rapport technique   [S] Conseils pour vos comptes   [H] Aide   [A] Options avancées",
        "Pattern": "^\\[R\\]\\ Rapport\\ technique\\ \\ \\ \\[S\\]\\ Conseils\\ pour\\ vos\\ comptes\\ \\ \\ \\[H\\]\\ Aide\\ \\ \\ \\[A\\]\\ Options\\ avancées$",
        "English": "[R] Technical report   [S] Account security advice   [H] Help   [A] Advanced options",
        "Count": 0,
        "Weight": 87
    },
    {
        "French": "Historique NIKKE : {0} ; les journaux absents ne permettent pas de reconstituer le passé.",
        "Pattern": "^Historique\\ NIKKE\\ :\\ (?<v0>.*?)\\ ;\\ les\\ journaux\\ absents\\ ne\\ permettent\\ pas\\ de\\ reconstituer\\ le\\ passé\\.$",
        "English": "NIKKE history: {0}; missing logs cannot reconstruct past activity.",
        "Count": 1,
        "Weight": 86
    },
    {
        "French": "Les détails techniques et les limites de lecture sont conservés dans le rapport privé.",
        "Pattern": "^Les\\ détails\\ techniques\\ et\\ les\\ limites\\ de\\ lecture\\ sont\\ conservés\\ dans\\ le\\ rapport\\ privé\\.$",
        "English": "Technical details and reading limitations are retained in the private report.",
        "Count": 0,
        "Weight": 86
    },
    {
        "French": "Le retrait d un élément de démarrage suspect n a pas pu être confirmé. Consultez le rapport.",
        "Pattern": "^Le\\ retrait\\ d\\ une\\ référence\\ du\\ registre\\ n\\ a\\ pas\\ pu\\ être\\ confirmé\\.\\ Consultez\\ le\\ rapport\\.$",
        "English": "Removing a startup entry could not be confirmed. See the report.",
        "Count": 0,
        "Weight": 86
    },
    {
        "French": "Le blocage peut empêcher la connexion au compte et le chargement des pages du lanceur.",
        "Pattern": "^Le\\ blocage\\ peut\\ empêcher\\ la\\ connexion\\ au\\ compte\\ et\\ le\\ chargement\\ des\\ pages\\ du\\ lanceur\\.$",
        "English": "Blocking may prevent account sign-in and launcher pages from loading.",
        "Count": 0,
        "Weight": 86
    },
    {
        "French": "- Windows redémarrera ensuite ; cela ne désactive pas définitivement votre connexion.",
        "Pattern": "^\\-\\ Windows\\ redémarrera\\ ensuite\\ ;\\ cela\\ ne\\ désactive\\ pas\\ définitivement\\ votre\\ connexion\\.$",
        "English": "- Windows will start again afterwards; your connection is not permanently disabled.",
        "Count": 0,
        "Weight": 85
    },
    {
        "French": "Ne publiez pas le rapport brut : il peut contenir votre nom Windows dans les chemins.",
        "Pattern": "^Ne\\ publiez\\ pas\\ le\\ rapport\\ brut\\ :\\ il\\ peut\\ contenir\\ votre\\ nom\\ Windows\\ dans\\ les\\ chemins\\.$",
        "English": "Do not post the raw report: paths may contain your Windows username.",
        "Count": 0,
        "Weight": 85
    },
    {
        "French": "Une analyse négative et la disparition des traces ne prouvent pas que le PC est sain.",
        "Pattern": "^Une\\ analyse\\ négative\\ et\\ la\\ disparition\\ des\\ traces\\ ne\\ prouvent\\ pas\\ que\\ le\\ PC\\ est\\ sain\\.$",
        "English": "A negative scan and missing indicators do not prove that the PC is clean.",
        "Count": 0,
        "Weight": 85
    },
    {
        "French": "DOMAINES SIGNALÉS BLOQUÉS DANS HOSTS — ce blocage ne certifie pas que le PC est sain.",
        "Pattern": "^DOMAINES\\ SIGNALÉS\\ BLOQUÉS\\ DANS\\ HOSTS\\ —\\ ce\\ blocage\\ ne\\ certifie\\ pas\\ que\\ le\\ PC\\ est\\ sain\\.$",
        "English": "REPORTED DOMAINS BLOCKED IN HOSTS — this block does not certify a clean PC.",
        "Count": 0,
        "Weight": 85
    },
    {
        "French": "Avant de partager ce rapport, masquez les informations personnelles dans les chemins.",
        "Pattern": "^Avant\\ de\\ partager\\ ce\\ rapport,\\ masquez\\ les\\ informations\\ personnelles\\ dans\\ les\\ chemins\\.$",
        "English": "Before sharing this report, redact personal information from its paths.",
        "Count": 0,
        "Weight": 85
    },
    {
        "French": "Terminez la désinstallation dans Windows, puis choisissez Revérifier dans NikkeTrace.",
        "Pattern": "^Terminez\\ la\\ désinstallation\\ dans\\ Windows,\\ puis\\ choisissez\\ Revérifier\\ dans\\ NikkeTrace\\.$",
        "English": "Finish uninstalling in Windows, then choose Check again in NikkeTrace.",
        "Count": 0,
        "Weight": 85
    },
    {
        "French": "  - le PC redémarrera et les applications seront fermées ; enregistrez vos travaux ;",
        "Pattern": "^\\ \\ \\-\\ le\\ PC\\ redémarrera\\ et\\ les\\ applications\\ seront\\ fermées\\ ;\\ enregistrez\\ vos\\ travaux\\ ;$",
        "English": "  - the PC will restart and applications will close; save your work;",
        "Count": 0,
        "Weight": 84
    },
    {
        "French": "  Une analyse antivirus hors connexion reste conseillée ; cet outil ne la lance pas.",
        "Pattern": "^\\ \\ Une\\ analyse\\ antivirus\\ hors\\ connexion\\ reste\\ conseillée\\ ;\\ cet\\ outil\\ ne\\ la\\ lance\\ pas\\.$",
        "English": "  An offline antivirus scan is still recommended; this tool does not start it.",
        "Count": 0,
        "Weight": 84
    },
    {
        "French": "Aucune lecture des mots de passe, cookies ou jetons. Les rapports restent sur le PC.",
        "Pattern": "^Aucune\\ lecture\\ des\\ mots\\ de\\ passe,\\ cookies\\ ou\\ jetons\\.\\ Les\\ rapports\\ restent\\ sur\\ le\\ PC\\.$",
        "English": "No passwords, cookies or tokens are read. Reports remain on this PC.",
        "Count": 0,
        "Weight": 84
    },
    {
        "French": "  Référence ou téléchargement seulement : aucune exécution confirmée par ces lignes.",
        "Pattern": "^\\ \\ Référence\\ ou\\ téléchargement\\ seulement\\ :\\ aucune\\ exécution\\ confirmée\\ par\\ ces\\ lignes\\.$",
        "English": "  Reference or download only: these lines do not confirm execution.",
        "Count": 0,
        "Weight": 84
    },
    {
        "French": "Entrée de démarrage Chrome Helper : nom seul non retenu comme trace de cet incident.",
        "Pattern": "^Entrée\\ de\\ démarrage\\ Chrome\\ Helper\\ :\\ nom\\ seul\\ non\\ retenu\\ comme\\ trace\\ de\\ cet\\ incident\\.$",
        "English": "Chrome Helper startup entry: its name alone is not treated as a trace of this incident.",
        "Count": 0,
        "Weight": 84
    },
    {
        "French": "Fermez NIKKE et son lanceur, puis réessayez. Aucun programme ne sera fermé de force.",
        "Pattern": "^Fermez\\ NIKKE\\ et\\ son\\ lanceur,\\ puis\\ réessayez\\.\\ Aucun\\ programme\\ ne\\ sera\\ fermé\\ de\\ force\\.$",
        "English": "Close NIKKE and its launcher, then try again. No program will be forcibly closed.",
        "Count": 0,
        "Weight": 84
    },
    {
        "French": "À faire : redémarrez Windows, puis relancez ce fichier pour poursuivre le nettoyage.",
        "Pattern": "^À\\ faire\\ :\\ redémarrez\\ Windows,\\ puis\\ relancez\\ ce\\ fichier\\ pour\\ poursuivre\\ le\\ nettoyage\\.$",
        "English": "Next: restart Windows, then run this file again to continue cleanup.",
        "Count": 0,
        "Weight": 84
    },
    {
        "French": "Les règles ont été relues dans le fichier. Cela ne certifie pas que le PC est sain.",
        "Pattern": "^Les\\ règles\\ ont\\ été\\ relues\\ dans\\ le\\ fichier\\.\\ Cela\\ ne\\ certifie\\ pas\\ que\\ le\\ PC\\ est\\ sain\\.$",
        "English": "The rules were verified by reading the file. This does not certify that the PC is clean.",
        "Count": 0,
        "Weight": 83
    },
    {
        "French": "Impossible de relire hosts après l opération. Le blocage ne peut pas être confirmé.",
        "Pattern": "^Impossible\\ de\\ relire\\ hosts\\ après\\ l\\ opération\\.\\ Le\\ blocage\\ ne\\ peut\\ pas\\ être\\ confirmé\\.$",
        "English": "Could not read hosts after the operation. Blocking cannot be confirmed.",
        "Count": 0,
        "Weight": 83
    },
    {
        "French": "Vérification des traces connues de cet incident, sans diagnostic antivirus complet.",
        "Pattern": "^Vérification\\ des\\ traces\\ connues\\ de\\ cet\\ incident,\\ sans\\ diagnostic\\ antivirus\\ complet\\.$",
        "English": "Checks for known traces of this incident; this is not a full antivirus assessment.",
        "Count": 0,
        "Weight": 83
    },
    {
        "French": "Ouverture impossible. Utilisez Paramètres > Applications > Applications installées.",
        "Pattern": "^Ouverture\\ impossible\\.\\ Utilisez\\ Paramètres\\ >\\ Applications\\ >\\ Applications\\ installées\\.$",
        "English": "Could not open Settings. Use Settings > Apps > Installed apps.",
        "Count": 0,
        "Weight": 83
    },
    {
        "French": "- le PC redémarrera et les applications seront fermées ; enregistrez vos travaux ;",
        "Pattern": "^\\-\\ le\\ PC\\ redémarrera\\ et\\ les\\ applications\\ seront\\ fermées\\ ;\\ enregistrez\\ vos\\ travaux\\ ;$",
        "English": "- the PC will restart and applications will close; save your work;",
        "Count": 0,
        "Weight": 82
    },
    {
        "French": "Une analyse antivirus hors connexion reste conseillée ; cet outil ne la lance pas.",
        "Pattern": "^Une\\ analyse\\ antivirus\\ hors\\ connexion\\ reste\\ conseillée\\ ;\\ cet\\ outil\\ ne\\ la\\ lance\\ pas\\.$",
        "English": "An offline antivirus scan is still recommended; this tool does not start it.",
        "Count": 0,
        "Weight": 82
    },
    {
        "French": "Les journaux connus seront sauvegardés dans un dossier privé avant le déplacement.",
        "Pattern": "^Les\\ journaux\\ connus\\ seront\\ sauvegardés\\ dans\\ un\\ dossier\\ privé\\ avant\\ le\\ déplacement\\.$",
        "English": "Known logs will be backed up privately before the move.",
        "Count": 0,
        "Weight": 82
    },
    {
        "French": "Sauvegarde si modification : hosts.NIKKE-backup-* à côté du fichier hosts Windows.",
        "Pattern": "^Sauvegarde\\ si\\ modification\\ :\\ hosts\\.NIKKE\\-backup\\-\\*\\ à\\ côté\\ du\\ fichier\\ hosts\\ Windows\\.$",
        "English": "Backup if changed: hosts.NIKKE-backup-* next to the Windows hosts file.",
        "Count": 0,
        "Weight": 82
    },
    {
        "French": "À faire : consultez [D] Détails. En cas de doute, effectuez une analyse antivirus.",
        "Pattern": "^À\\ faire\\ :\\ consultez\\ \\[D\\]\\ Détails\\.\\ En\\ cas\\ de\\ doute,\\ effectuez\\ une\\ analyse\\ antivirus\\.$",
        "English": "Next: read [D] Details. If in doubt, run an antivirus scan.",
        "Count": 0,
        "Weight": 82
    },
    {
        "French": "Aucun élément ne répond aux critères stricts du nettoyage. Rien ne sera supprimé.",
        "Pattern": "^Aucun\\ élément\\ ne\\ répond\\ aux\\ critères\\ stricts\\ du\\ nettoyage\\.\\ Rien\\ ne\\ sera\\ supprimé\\.$",
        "English": "No item meets the strict cleanup criteria. Nothing will be removed.",
        "Count": 0,
        "Weight": 81
    },
    {
        "French": "Vérification du cache incomplète : aucun nettoyage global ne peut être confirmé.",
        "Pattern": "^Vérification\\ du\\ cache\\ incomplète\\ :\\ aucun\\ nettoyage\\ global\\ ne\\ peut\\ être\\ confirmé\\.$",
        "English": "Cache check incomplete: overall cleanup cannot be confirmed.",
        "Count": 0,
        "Weight": 80
    },
    {
        "French": "NikkeTrace ne redémarre pas le PC et ne lance rien automatiquement au démarrage.",
        "Pattern": "^NikkeTrace\\ ne\\ redémarre\\ pas\\ le\\ PC\\ et\\ ne\\ lance\\ rien\\ automatiquement\\ au\\ démarrage\\.$",
        "English": "NikkeTrace does not restart the PC or run anything automatically at startup.",
        "Count": 0,
        "Weight": 80
    },
    {
        "French": "La reprise du nettoyage ne peut pas être vérifiée. Aucun fichier ne sera retiré.",
        "Pattern": "^La\\ reprise\\ du\\ nettoyage\\ ne\\ peut\\ pas\\ être\\ vérifiée\\.\\ Aucun\\ fichier\\ ne\\ sera\\ retiré\\.$",
        "English": "Cleanup recovery could not be verified. No files will be removed.",
        "Count": 0,
        "Weight": 80
    },
    {
        "French": "Depuis un téléphone ou autre appareil sain, sans attendre la fin des analyses :",
        "Pattern": "^Depuis\\ un\\ téléphone\\ ou\\ autre\\ appareil\\ sain,\\ sans\\ attendre\\ la\\ fin\\ des\\ analyses\\ :$",
        "English": "From a phone or another clean device, without waiting for scans to finish:",
        "Count": 0,
        "Weight": 79
    },
    {
        "French": "Règles de blocage installées et relues dans la configuration active de Windows.",
        "Pattern": "^Règles\\ de\\ blocage\\ installées\\ et\\ relues\\ dans\\ la\\ configuration\\ active\\ de\\ Windows\\.$",
        "English": "Block rules installed and read back in the active Windows configuration.",
        "Count": 0,
        "Weight": 79
    },
    {
        "French": "Recherche de l installation incomplète : les contrôles hors du jeu continuent.",
        "Pattern": "^Recherche\\ de\\ l\\ installation\\ incomplète\\ :\\ les\\ contrôles\\ hors\\ du\\ jeu\\ continuent\\.$",
        "English": "Installation search incomplete: checks outside the game will continue.",
        "Count": 0,
        "Weight": 78
    },
    {
        "French": "Windows demandera les droits administrateur si nécessaire, après votre accord.",
        "Pattern": "^Windows\\ demandera\\ les\\ droits\\ administrateur\\ si\\ nécessaire,\\ après\\ votre\\ accord\\.$",
        "English": "Windows will request administrator rights if needed, after you agree.",
        "Count": 0,
        "Weight": 78
    },
    {
        "French": "Le rapport conserve les traces détectées, pas une copie des fichiers du cache.",
        "Pattern": "^Le\\ rapport\\ conserve\\ les\\ traces\\ détectées,\\ pas\\ une\\ copie\\ des\\ fichiers\\ du\\ cache\\.$",
        "English": "The report preserves the detected indicators, not a copy of the cache files.",
        "Count": 0,
        "Weight": 78
    },
    {
        "French": "Cliquez sur Analyser maintenant uniquement quand vous êtes prêt à redémarrer.",
        "Pattern": "^Cliquez\\ sur\\ Analyser\\ maintenant\\ uniquement\\ quand\\ vous\\ êtes\\ prêt\\ à\\ redémarrer\\.$",
        "English": "Click Scan now only when you are ready to restart.",
        "Count": 0,
        "Weight": 77
    },
    {
        "French": "La clé contient des éléments supplémentaires non reconnus : laissée en place.",
        "Pattern": "^La\\ clé\\ contient\\ des\\ éléments\\ supplémentaires\\ non\\ reconnus\\ :\\ laissée\\ en\\ place\\.$",
        "English": "The key contains additional unrecognised items: left unchanged.",
        "Count": 0,
        "Weight": 77
    },
    {
        "French": "Fermeture facultative : une fenêtre de navigateur n a pas pu être identifiée.",
        "Pattern": "^Fermeture\\ facultative\\ :\\ une\\ fenêtre\\ de\\ navigateur\\ n\\ a\\ pas\\ pu\\ être\\ identifiée\\.$",
        "English": "Optional closing: a browser window could not be identified.",
        "Count": 0,
        "Weight": 77
    },
    {
        "French": "Le navigateur peut demander confirmation. Aucun arrêt forcé ne sera effectué.",
        "Pattern": "^Le\\ navigateur\\ peut\\ demander\\ confirmation\\.\\ Aucun\\ arrêt\\ forcé\\ ne\\ sera\\ effectué\\.$",
        "English": "The browser may ask for confirmation. No process will be forcibly stopped.",
        "Count": 0,
        "Weight": 77
    },
    {
        "French": "Une trace ancienne reste à examiner ; son emplacement figure dans le rapport.",
        "Pattern": "^Une\\ trace\\ ancienne\\ reste\\ à\\ examiner\\ ;\\ son\\ emplacement\\ figure\\ dans\\ le\\ rapport\\.$",
        "English": "A historical trace still needs review; its location is in the report.",
        "Count": 0,
        "Weight": 77
    },
    {
        "French": "     Changer le mot de passe ne révoque pas toujours une session déjà volée.",
        "Pattern": "^\\ \\ \\ \\ \\ Changer\\ le\\ mot\\ de\\ passe\\ ne\\ révoque\\ pas\\ toujours\\ une\\ session\\ déjà\\ volée\\.$",
        "English": "     Changing a password does not always revoke a stolen session.",
        "Count": 0,
        "Weight": 76
    },
    {
        "French": "Aucun programme ciblé par cet incident n était ouvert au moment du contrôle.",
        "Pattern": "^Aucun\\ programme\\ ciblé\\ par\\ cet\\ incident\\ n\\ était\\ ouvert\\ au\\ moment\\ du\\ contrôle\\.$",
        "English": "No program targeted by this incident was open at the time of the check.",
        "Count": 0,
        "Weight": 76
    },
    {
        "French": "Le chemin hosts est redirigé. L outil refuse de le modifier automatiquement.",
        "Pattern": "^Le\\ chemin\\ hosts\\ est\\ redirigé\\.\\ L\\ outil\\ refuse\\ de\\ le\\ modifier\\ automatiquement\\.$",
        "English": "The hosts path is redirected. The tool will not modify it automatically.",
        "Count": 0,
        "Weight": 76
    },
    {
        "French": "Redémarrez Windows puis relancez le même fichier pour terminer le nettoyage.",
        "Pattern": "^Redémarrez\\ Windows\\ puis\\ relancez\\ le\\ même\\ fichier\\ pour\\ terminer\\ le\\ nettoyage\\.$",
        "English": "Restart Windows, then run the same file to finish cleanup.",
        "Count": 0,
        "Weight": 76
    },
    {
        "French": "Ce blocage est limité aux noms ci-dessus ; il ne supprime pas une infection.",
        "Pattern": "^Ce\\ blocage\\ est\\ limité\\ aux\\ noms\\ ci\\-dessus\\ ;\\ il\\ ne\\ supprime\\ pas\\ une\\ infection\\.$",
        "English": "This block covers only the names above; it does not remove an infection.",
        "Count": 0,
        "Weight": 76
    },
    {
        "French": "Aide hors connexion refusée : aucune ouverture, analyse ou relance Windows.",
        "Pattern": "^Aide\\ hors\\ connexion\\ refusée\\ :\\ aucune\\ ouverture,\\ analyse\\ ou\\ relance\\ Windows\\.$",
        "English": "Offline scan help declined: nothing opened, scanned or restarted.",
        "Count": 0,
        "Weight": 75
    },
    {
        "French": "Installation NIKKE non confirmée : aucun retrait automatique de ce dossier.",
        "Pattern": "^Installation\\ NIKKE\\ non\\ confirmée\\ :\\ aucun\\ retrait\\ automatique\\ de\\ ce\\ dossier\\.$",
        "English": "NIKKE installation not confirmed: this folder will not be removed automatically.",
        "Count": 0,
        "Weight": 75
    },
    {
        "French": "Jeu déclaré déjà supprimé : poursuite du contrôle sans installation du jeu.",
        "Pattern": "^Jeu\\ déclaré\\ déjà\\ supprimé\\ :\\ poursuite\\ du\\ contrôle\\ sans\\ installation\\ du\\ jeu\\.$",
        "English": "Game reported as already removed: continuing checks without its installation.",
        "Count": 0,
        "Weight": 75
    },
    {
        "French": "Si le disque est chiffré, préparez votre clé BitLocker avant toute analyse.",
        "Pattern": "^Si\\ le\\ disque\\ est\\ chiffré,\\ préparez\\ votre\\ clé\\ BitLocker\\ avant\\ toute\\ analyse\\.$",
        "English": "If the drive is encrypted, prepare your BitLocker recovery key before any scan.",
        "Count": 0,
        "Weight": 75
    },
    {
        "French": "CACHE NIKKE ISOLÉ : dossier retiré de son chemin habituel, copie conservée.",
        "Pattern": "^CACHE\\ NIKKE\\ ISOLÉ\\ :\\ dossier\\ retiré\\ de\\ son\\ chemin\\ habituel,\\ copie\\ conservée\\.$",
        "English": "NIKKE CACHE ISOLATED: folder moved from its usual path, copy retained.",
        "Count": 0,
        "Weight": 75
    },
    {
        "French": "Le dossier Chrome légitime et les profils des navigateurs seront conservés.",
        "Pattern": "^Le\\ dossier\\ Chrome\\ légitime\\ et\\ les\\ profils\\ des\\ navigateurs\\ seront\\ conservés\\.$",
        "English": "The legitimate Chrome folder and browser profiles will be preserved.",
        "Count": 0,
        "Weight": 75
    },
    {
        "French": "Windows demandera les droits administrateur pour cette opération seulement.",
        "Pattern": "^Windows\\ demandera\\ les\\ droits\\ administrateur\\ pour\\ cette\\ opération\\ seulement\\.$",
        "English": "Windows will request administrator rights for this operation only.",
        "Count": 0,
        "Weight": 75
    },
    {
        "French": "Élément de démarrage suspect retiré. Redémarrage nécessaire pour continuer.",
        "Pattern": "^Élément\\ de\\ démarrage\\ suspect\\ retiré\\.\\ Redémarrage\\ nécessaire\\ pour\\ continuer\\.$",
        "English": "Suspicious startup entry removed. A restart is needed to continue.",
        "Count": 0,
        "Weight": 75
    },
    {
        "French": "Bilan non enregistré : gardez cette fenêtre ouverte pour lire le résultat.",
        "Pattern": "^Bilan\\ non\\ enregistré\\ :\\ gardez\\ cette\\ fenêtre\\ ouverte\\ pour\\ lire\\ le\\ résultat\\.$",
        "English": "Report could not be saved: keep this window open to read the result.",
        "Count": 0,
        "Weight": 74
    },
    {
        "French": "ELEMENTS A EXAMINER - presence insuffisante pour conclure a une infection.",
        "Pattern": "^ELEMENTS\\ A\\ EXAMINER\\ \\-\\ presence\\ insuffisante\\ pour\\ conclure\\ a\\ une\\ infection\\.$",
        "English": "ITEMS TO INVESTIGATE — insufficient evidence to confirm infection.",
        "Count": 0,
        "Weight": 74
    },
    {
        "French": "Indiquez un dossier de données, pas chrome.exe, msedge.exe ou firefox.exe.",
        "Pattern": "^Indiquez\\ un\\ dossier\\ de\\ données,\\ pas\\ chrome\\.exe,\\ msedge\\.exe\\ ou\\ firefox\\.exe\\.$",
        "English": "Enter a data folder, not chrome.exe, msedge.exe or firefox.exe.",
        "Count": 0,
        "Weight": 74
    },
    {
        "French": "TRACES SIGNALEES TROUVEES - traiter le PC comme potentiellement compromis.",
        "Pattern": "^TRACES\\ SIGNALEES\\ TROUVEES\\ \\-\\ traiter\\ le\\ PC\\ comme\\ potentiellement\\ compromis\\.$",
        "English": "REPORTED INDICATORS FOUND — treat the PC as potentially compromised.",
        "Count": 0,
        "Weight": 74
    },
    {
        "French": "DLL homonyme chargée dans un processus : vérifier le chemin et l empreinte",
        "Pattern": "^DLL\\ homonyme\\ chargée\\ dans\\ un\\ processus\\ :\\ vérifier\\ le\\ chemin\\ et\\ l\\ empreinte$",
        "English": "Same-name DLL loaded in a process: check the path and fingerprint",
        "Count": 0,
        "Weight": 74
    },
    {
        "French": "Domaine signalé bloqué dans hosts : ce blocage ne prouve pas une infection",
        "Pattern": "^Domaine\\ signalé\\ bloqué\\ dans\\ hosts\\ :\\ ce\\ blocage\\ ne\\ prouve\\ pas\\ une\\ infection$",
        "English": "Reported domain blocked in hosts: the block does not establish infection",
        "Count": 0,
        "Weight": 74
    },
    {
        "French": "Aucun élément connu ne peut être nettoyé automatiquement pour ce résultat.",
        "Pattern": "^Aucun\\ élément\\ connu\\ ne\\ peut\\ être\\ nettoyé\\ automatiquement\\ pour\\ ce\\ résultat\\.$",
        "English": "No known item can be cleaned automatically for this result.",
        "Count": 0,
        "Weight": 74
    },
    {
        "French": "Ce choix ouvre une aide et Sécurité Windows. Il ne lance pas une analyse.",
        "Pattern": "^Ce\\ choix\\ ouvre\\ une\\ aide\\ et\\ Sécurité\\ Windows\\.\\ Il\\ ne\\ lance\\ pas\\ une\\ analyse\\.$",
        "English": "This option opens help and Windows Security. It does not start a scan.",
        "Count": 0,
        "Weight": 73
    },
    {
        "French": "Référence DNS locale : une consultation ou un blocage peut aussi la créer",
        "Pattern": "^Référence\\ DNS\\ locale\\ :\\ une\\ consultation\\ ou\\ un\\ blocage\\ peut\\ aussi\\ la\\ créer$",
        "English": "Local DNS reference: a lookup or blocking tool can also create it",
        "Count": 0,
        "Weight": 73
    },
    {
        "French": "Navigateurs laissés ouverts à votre demande. La recherche peut continuer.",
        "Pattern": "^Navigateurs\\ laissés\\ ouverts\\ à\\ votre\\ demande\\.\\ La\\ recherche\\ peut\\ continuer\\.$",
        "English": "Browsers left open at your request. The check can continue.",
        "Count": 0,
        "Weight": 73
    },
    {
        "French": "La demande administrateur a été annulée. Le blocage n a pas été confirmé.",
        "Pattern": "^La\\ demande\\ administrateur\\ a\\ été\\ annulée\\.\\ Le\\ blocage\\ n\\ a\\ pas\\ été\\ confirmé\\.$",
        "English": "The administrator request was cancelled. Blocking has not been confirmed.",
        "Count": 0,
        "Weight": 73
    },
    {
        "French": "DOMAINES SIGNALÉS BLOQUÉS DANS HOSTS — confirmé par relecture du fichier.",
        "Pattern": "^DOMAINES\\ SIGNALÉS\\ BLOQUÉS\\ DANS\\ HOSTS\\ —\\ confirmé\\ par\\ relecture\\ du\\ fichier\\.$",
        "English": "REPORTED DOMAINS BLOCKED IN HOSTS — confirmed by reading the file back.",
        "Count": 0,
        "Weight": 73
    },
    {
        "French": "Emplacements habituels à ouvrir dans l Explorateur ou avec Windows + R :",
        "Pattern": "^Emplacements\\ habituels\\ à\\ ouvrir\\ dans\\ l\\ Explorateur\\ ou\\ avec\\ Windows\\ \\+\\ R\\ :$",
        "English": "Standard locations to open in File Explorer or with Windows + R:",
        "Count": 0,
        "Weight": 72
    },
    {
        "French": "EXPOSITION PASSÉE POSSIBLE — protéger les comptes même sans DLL présente",
        "Pattern": "^EXPOSITION\\ PASSÉE\\ POSSIBLE\\ —\\ protéger\\ les\\ comptes\\ même\\ sans\\ DLL\\ présente$",
        "English": "POSSIBLE PAST EXPOSURE — protect accounts even if no DLL is present",
        "Count": 0,
        "Weight": 72
    },
    {
        "French": "La demande de fermeture n a pas été confirmée. La vérification continue.",
        "Pattern": "^La\\ demande\\ de\\ fermeture\\ n\\ a\\ pas\\ été\\ confirmée\\.\\ La\\ vérification\\ continue\\.$",
        "English": "The close request could not be confirmed. Checking continues.",
        "Count": 0,
        "Weight": 72
    },
    {
        "French": "Changer le mot de passe ne révoque pas toujours une session déjà volée.",
        "Pattern": "^Changer\\ le\\ mot\\ de\\ passe\\ ne\\ révoque\\ pas\\ toujours\\ une\\ session\\ déjà\\ volée\\.$",
        "English": "Changing a password does not always revoke a stolen session.",
        "Count": 0,
        "Weight": 71
    },
    {
        "French": "Ouverture impossible : cherchez Sécurité Windows dans le menu Démarrer.",
        "Pattern": "^Ouverture\\ impossible\\ :\\ cherchez\\ Sécurité\\ Windows\\ dans\\ le\\ menu\\ Démarrer\\.$",
        "English": "Could not open Windows Security: find it in the Start menu.",
        "Count": 0,
        "Weight": 71
    },
    {
        "French": "Empreinte DLL différente du signalement : une variante reste possible.",
        "Pattern": "^Empreinte\\ DLL\\ différente\\ du\\ signalement\\ :\\ une\\ variante\\ reste\\ possible\\.$",
        "English": "DLL fingerprint differs from the report: a variant remains possible.",
        "Count": 0,
        "Weight": 70
    },
    {
        "French": "RÉFÉRENCES À L INCIDENT TROUVÉES — à examiner, infection non confirmée",
        "Pattern": "^RÉFÉRENCES\\ À\\ L\\ INCIDENT\\ TROUVÉES\\ —\\ à\\ examiner,\\ infection\\ non\\ confirmée$",
        "English": "REFERENCES TO THE INCIDENT FOUND — investigate; infection not confirmed",
        "Count": 0,
        "Weight": 70
    },
    {
        "French": "Le profil CEF partagé et les profils des navigateurs seront conservés.",
        "Pattern": "^Le\\ profil\\ CEF\\ partagé\\ et\\ les\\ profils\\ des\\ navigateurs\\ seront\\ conservés\\.$",
        "English": "The shared CEF profile and browser profiles will be preserved.",
        "Count": 0,
        "Weight": 70
    },
    {
        "French": "Cet outil ne lance aucun antivirus et ne déclenche aucun redémarrage.",
        "Pattern": "^Cet\\ outil\\ ne\\ lance\\ aucun\\ antivirus\\ et\\ ne\\ déclenche\\ aucun\\ redémarrage\\.$",
        "English": "This tool starts no antivirus scan and triggers no restart.",
        "Count": 0,
        "Weight": 69
    },
    {
        "French": "7  Supprimer le cache NIKKE (facultatif, après sauvegarde du rapport)",
        "Pattern": "^7\\ \\ Supprimer\\ le\\ cache\\ NIKKE\\ \\(facultatif,\\ après\\ sauvegarde\\ du\\ rapport\\)$",
        "English": "7  Delete NIKKE launcher cache (optional, after saving the report)",
        "Count": 0,
        "Weight": 69
    },
    {
        "French": "Traces actuelles : {0} ; historiques : {1} ; autres éléments à examiner : {2}.",
        "Pattern": "^Traces\\ actuelles\\ :\\ (?<v0>.*?)\\ ;\\ historiques\\ :\\ (?<v1>.*?)\\ ;\\ autres\\ éléments\\ à\\ examiner\\ :\\ (?<v2>.*?)\\.$",
        "English": "Current traces: {0}; historical: {1}; other items needing review: {2}.",
        "Count": 3,
        "Weight": 69
    },
    {
        "French": "Fichier téléchargé à examiner : taille signalée, contenu non confirmé",
        "Pattern": "^Fichier\\ téléchargé\\ à\\ examiner\\ :\\ taille\\ signalée,\\ contenu\\ non\\ confirmé$",
        "English": "Downloaded file needs review: reported size, content unconfirmed",
        "Count": 0,
        "Weight": 69
    },
    {
        "French": "Le rappel périodique est indisponible ; les étapes restent affichées.",
        "Pattern": "^Le\\ rappel\\ périodique\\ est\\ indisponible\\ ;\\ les\\ étapes\\ restent\\ affichées\\.$",
        "English": "Periodic reminders are unavailable; check stages will still be displayed.",
        "Count": 0,
        "Weight": 69
    },
    {
        "French": "  Journaux NIKKE : aucun marqueur connu dans $($Snapshot.LogsRead) journal/journaux lu(s)",
        "Pattern": "^\\ \\ Journaux\\ NIKKE\\ :\\ aucun\\ marqueur\\ connu\\ dans\\ (?<v0>.*?)\\ journal/journaux\\ lu\\(s\\)$",
        "English": "  NIKKE logs: no known indicator in {0} readable log(s)",
        "Count": 1,
        "Weight": 68
    },
    {
        "French": "Journaux NIKKE : non consultés dans le contrôle ciblé du navigateur.",
        "Pattern": "^Journaux\\ NIKKE\\ :\\ non\\ consultés\\ dans\\ le\\ contrôle\\ ciblé\\ du\\ navigateur\\.$",
        "English": "NIKKE logs: not checked in the browser-only check.",
        "Count": 0,
        "Weight": 68
    },
    {
        "French": "Le nom du dossier ne permet pas de confirmer une installation NIKKE.",
        "Pattern": "^Le\\ nom\\ du\\ dossier\\ ne\\ permet\\ pas\\ de\\ confirmer\\ une\\ installation\\ NIKKE\\.$",
        "English": "The folder name does not confirm a NIKKE installation.",
        "Count": 0,
        "Weight": 68
    },
    {
        "French": "  Le menu propose aussi un blocage facultatif des domaines signalés.",
        "Pattern": "^\\ \\ Le\\ menu\\ propose\\ aussi\\ un\\ blocage\\ facultatif\\ des\\ domaines\\ signalés\\.$",
        "English": "  The menu also offers optional blocking of the reported domains.",
        "Count": 0,
        "Weight": 68
    },
    {
        "French": "  Contrôle terminé avec une limite ({0} s) ; détail dans le rapport.",
        "Pattern": "^\\ \\ Contrôle\\ terminé\\ avec\\ une\\ limite\\ \\((?<v0>.*?)\\ s\\)\\ ;\\ détail\\ dans\\ le\\ rapport\\.$",
        "English": "  Check finished with a limitation ({0} s); see the report for details.",
        "Count": 1,
        "Weight": 68
    },
    {
        "French": "Fichier ciblé à supprimer définitivement, sans copie de récupération",
        "Pattern": "^Fichier\\ ciblé\\ à\\ supprimer\\ définitivement,\\ sans\\ copie\\ de\\ récupération$",
        "English": "Targeted file to delete permanently, without a recovery copy",
        "Count": 0,
        "Weight": 68
    },
    {
        "French": "  Le dossier User Data ou le profil de votre installation portable.",
        "Pattern": "^\\ \\ Le\\ dossier\\ User\\ Data\\ ou\\ le\\ profil\\ de\\ votre\\ installation\\ portable\\.$",
        "English": "  The User Data folder or profile folder for your portable installation.",
        "Count": 0,
        "Weight": 67
    },
    {
        "French": "Les autres indices restent à examiner avec une personne compétente.",
        "Pattern": "^Les\\ autres\\ indices\\ restent\\ à\\ examiner\\ avec\\ une\\ personne\\ compétente\\.$",
        "English": "Other indicators still need investigation with qualified assistance.",
        "Count": 0,
        "Weight": 67
    },
    {
        "French": "VÉRIFICATION PARTIELLE — AUCUNE TRACE TROUVÉE DANS LES ÉLÉMENTS LUS",
        "Pattern": "^VÉRIFICATION\\ PARTIELLE\\ —\\ AUCUNE\\ TRACE\\ TROUVÉE\\ DANS\\ LES\\ ÉLÉMENTS\\ LUS$",
        "English": "PARTIAL CHECK — NO TRACES FOUND IN THE ITEMS READ",
        "Count": 0,
        "Weight": 67
    },
    {
        "French": "Ce chemin est un dossier ; aucune suppression récursive autorisée.",
        "Pattern": "^Ce\\ chemin\\ est\\ un\\ dossier\\ ;\\ aucune\\ suppression\\ récursive\\ autorisée\\.$",
        "English": "This path is a folder; recursive deletion is not allowed.",
        "Count": 0,
        "Weight": 66
    },
    {
        "French": "Cette référence de registre ne fait pas partie du nettoyage ciblé.",
        "Pattern": "^Cette\\ référence\\ de\\ registre\\ ne\\ fait\\ pas\\ partie\\ du\\ nettoyage\\ ciblé\\.$",
        "English": "This registry reference is outside the targeted cleanup scope.",
        "Count": 0,
        "Weight": 66
    },
    {
        "French": "Choisissez le dossier du profil, pas le fichier EXE du navigateur.",
        "Pattern": "^Choisissez\\ le\\ dossier\\ du\\ profil,\\ pas\\ le\\ fichier\\ EXE\\ du\\ navigateur\\.$",
        "English": "Select the profile folder, not the browser EXE file.",
        "Count": 0,
        "Weight": 66
    },
    {
        "French": "Valeur modifiée ou chemin non documenté : entrée laissée en place.",
        "Pattern": "^Valeur\\ modifiée\\ ou\\ chemin\\ non\\ documenté\\ :\\ entrée\\ laissée\\ en\\ place\\.$",
        "English": "Value changed or undocumented path: entry left unchanged.",
        "Count": 0,
        "Weight": 66
    },
    {
        "French": "Fermeture facultative non confirmée ; la recherche peut continuer.",
        "Pattern": "^Fermeture\\ facultative\\ non\\ confirmée\\ ;\\ la\\ recherche\\ peut\\ continuer\\.$",
        "English": "Optional close not confirmed; the check can continue.",
        "Count": 0,
        "Weight": 66
    },
    {
        "French": "Résultat technique hosts : code {0} ; lignes manquantes {1} ; conflits {2}.",
        "Pattern": "^Résultat\\ technique\\ hosts\\ :\\ code\\ (?<v0>.*?)\\ ;\\ lignes\\ manquantes\\ (?<v1>.*?)\\ ;\\ conflits\\ (?<v2>.*?)\\.$",
        "English": "Hosts technical result: code {0}; missing lines {1}; conflicts {2}.",
        "Count": 3,
        "Weight": 66
    },
    {
        "French": "Des indices ont été trouvés ; ils ne confirment pas une infection.",
        "Pattern": "^Des\\ indices\\ ont\\ été\\ trouvés\\ ;\\ ils\\ ne\\ confirment\\ pas\\ une\\ infection\\.$",
        "English": "Indicators were found; they do not confirm an infection.",
        "Count": 0,
        "Weight": 66
    },
    {
        "French": "À vérifier : {0} — contrôle incomplet, raison dans le rapport [R].",
        "Pattern": "^À\\ vérifier\\ :\\ (?<v0>.*?)\\ —\\ contrôle\\ incomplet,\\ raison\\ dans\\ le\\ rapport\\ \\[R\\]\\.$",
        "English": "Needs review: {0} — incomplete check, see the reason in the report [R].",
        "Count": 1,
        "Weight": 66
    },
    {
        "French": "Les éléments trouvés sont décrits dans [D] Détails et [R] Rapport.",
        "Pattern": "^Les\\ éléments\\ trouvés\\ sont\\ décrits\\ dans\\ \\[D\\]\\ Détails\\ et\\ \\[R\\]\\ Rapport\\.$",
        "English": "Findings are described in [D] Details and [R] Report.",
        "Count": 0,
        "Weight": 66
    },
    {
        "French": "2  Retirer le blocage du navigateur du lanceur créé par NikkeTrace",
        "Pattern": "^2\\ \\ Retirer\\ le\\ blocage\\ du\\ navigateur\\ du\\ lanceur\\ créé\\ par\\ NikkeTrace$",
        "English": "2  Remove the launcher browser block created by NikkeTrace",
        "Count": 0,
        "Weight": 66
    },
    {
        "French": "Le dossier User Data ou le profil de votre installation portable.",
        "Pattern": "^Le\\ dossier\\ User\\ Data\\ ou\\ le\\ profil\\ de\\ votre\\ installation\\ portable\\.$",
        "English": "The User Data folder or profile folder for your portable installation.",
        "Count": 0,
        "Weight": 65
    },
    {
        "French": "Contrôle des anciens dossiers conservés par NikkeTrace incomplet.",
        "Pattern": "^Contrôle\\ des\\ anciens\\ dossiers\\ conservés\\ par\\ NikkeTrace\\ incomplet\\.$",
        "English": "Check of old folders retained by NikkeTrace is incomplete.",
        "Count": 0,
        "Weight": 65
    },
    {
        "French": "EXPOSITION PASSÉE INDÉTERMINÉE : journaux absents ou illisibles.",
        "Pattern": "^EXPOSITION\\ PASSÉE\\ INDÉTERMINÉE\\ :\\ journaux\\ absents\\ ou\\ illisibles\\.$",
        "English": "PAST EXPOSURE UNKNOWN: logs missing or unreadable.",
        "Count": 0,
        "Weight": 64
    },
    {
        "French": "Indiquez un dossier local absolu, par exemple D:\\Profils\\Chrome.",
        "Pattern": "^Indiquez\\ un\\ dossier\\ local\\ absolu,\\ par\\ exemple\\ D:\\\\Profils\\\\Chrome\\.$",
        "English": "Enter an absolute local folder, such as D:\\Profiles\\Chrome.",
        "Count": 0,
        "Weight": 64
    },
    {
        "French": "TRACES CONNUES ACTUELLES TROUVÉES — voir les éléments ci-dessous",
        "Pattern": "^TRACES\\ CONNUES\\ ACTUELLES\\ TROUVÉES\\ —\\ voir\\ les\\ éléments\\ ci\\-dessous$",
        "English": "CURRENT KNOWN TRACES FOUND — see the items below",
        "Count": 0,
        "Weight": 64
    },
    {
        "French": "Contrôle ciblé de cet incident, pas une analyse antivirus du PC.",
        "Pattern": "^Contrôle\\ ciblé\\ de\\ cet\\ incident,\\ pas\\ une\\ analyse\\ antivirus\\ du\\ PC\\.$",
        "English": "Targeted check of this incident, not an antivirus scan of the PC.",
        "Count": 0,
        "Weight": 64
    },
    {
        "French": "Un fichier suspect n a pas pu être retiré. Consultez le rapport.",
        "Pattern": "^Un\\ fichier\\ suspect\\ n\\ a\\ pas\\ pu\\ être\\ retiré\\.\\ Consultez\\ le\\ rapport\\.$",
        "English": "A suspicious file could not be removed. See the report.",
        "Count": 0,
        "Weight": 64
    },
    {
        "French": "  Résumé : $removed disparu(s), $remaining encore à examiner, $unknown non vérifiable(s).",
        "Pattern": "^\\ \\ Résumé\\ :\\ (?<v0>.*?)\\ disparu\\(s\\),\\ (?<v1>.*?)\\ encore\\ à\\ examiner,\\ (?<v2>.*?)\\ non\\ vérifiable\\(s\\)\\.$",
        "English": "  Summary: {0} missing, {1} still to investigate, {2} unverifiable.",
        "Count": 3,
        "Weight": 63
    },
    {
        "French": "AUCUN INDICE CONNU TROUVÉ — pas de garantie que le PC soit sain",
        "Pattern": "^AUCUN\\ INDICE\\ CONNU\\ TROUVÉ\\ —\\ pas\\ de\\ garantie\\ que\\ le\\ PC\\ soit\\ sain$",
        "English": "NO KNOWN INDICATOR FOUND — no guarantee that the PC is clean",
        "Count": 0,
        "Weight": 63
    },
    {
        "French": "EXPOSITION PASSÉE INDÉTERMINÉE — journaux absents ou illisibles",
        "Pattern": "^EXPOSITION\\ PASSÉE\\ INDÉTERMINÉE\\ —\\ journaux\\ absents\\ ou\\ illisibles$",
        "English": "PAST EXPOSURE UNKNOWN — logs missing or unreadable",
        "Count": 0,
        "Weight": 63
    },
    {
        "French": "VÉRIFICATION NON RÉALISÉE — aucun contrôle utile n a pu aboutir",
        "Pattern": "^VÉRIFICATION\\ NON\\ RÉALISÉE\\ —\\ aucun\\ contrôle\\ utile\\ n\\ a\\ pu\\ aboutir$",
        "English": "CHECK NOT PERFORMED — no useful check could be completed",
        "Count": 0,
        "Weight": 63
    },
    {
        "French": "6  Bloquer les domaines signalés dans hosts (facultatif, admin)",
        "Pattern": "^6\\ \\ Bloquer\\ les\\ domaines\\ signalés\\ dans\\ hosts\\ \\(facultatif,\\ admin\\)$",
        "English": "6  Block reported domains in hosts (optional, admin)",
        "Count": 0,
        "Weight": 63
    },
    {
        "French": "Règles prévues (seules les lignes manquantes seront ajoutées) :",
        "Pattern": "^Règles\\ prévues\\ \\(seules\\ les\\ lignes\\ manquantes\\ seront\\ ajoutées\\)\\ :$",
        "English": "Planned rules (only missing lines will be added):",
        "Count": 0,
        "Weight": 63
    },
    {
        "French": "Cache non supprimé : son emplacement ne peut pas être confirmé.",
        "Pattern": "^Cache\\ non\\ supprimé\\ :\\ son\\ emplacement\\ ne\\ peut\\ pas\\ être\\ confirmé\\.$",
        "English": "Cache not deleted: its location could not be confirmed.",
        "Count": 0,
        "Weight": 63
    },
    {
        "French": "6  Accès Internet du navigateur du lanceur (blocage facultatif)",
        "Pattern": "^6\\ \\ Accès\\ Internet\\ du\\ navigateur\\ du\\ lanceur\\ \\(blocage\\ facultatif\\)$",
        "English": "6  Launcher browser Internet access (optional blocking)",
        "Count": 0,
        "Weight": 63
    },
    {
        "French": "  Journaux NIKKE : lecture incomplète — impossible de conclure",
        "Pattern": "^\\ \\ Journaux\\ NIKKE\\ :\\ lecture\\ incomplète\\ —\\ impossible\\ de\\ conclure$",
        "English": "  NIKKE logs: incomplete read — unable to conclude",
        "Count": 0,
        "Weight": 62
    },
    {
        "French": "Si vous cliquez ensuite sur Analyser maintenant dans Windows :",
        "Pattern": "^Si\\ vous\\ cliquez\\ ensuite\\ sur\\ Analyser\\ maintenant\\ dans\\ Windows\\ :$",
        "English": "If you then click Scan now in Windows:",
        "Count": 0,
        "Weight": 62
    },
    {
        "French": "Connexion TCP vers l IP signalée : ne prouve pas une infection",
        "Pattern": "^Connexion\\ TCP\\ vers\\ l\\ IP\\ signalée\\ :\\ ne\\ prouve\\ pas\\ une\\ infection$",
        "English": "TCP connection to the reported IP: does not establish infection",
        "Count": 0,
        "Weight": 62
    },
    {
        "French": "TRACES D UNE EXPOSITION PASSÉE TROUVÉES — protéger les comptes",
        "Pattern": "^TRACES\\ D\\ UNE\\ EXPOSITION\\ PASSÉE\\ TROUVÉES\\ —\\ protéger\\ les\\ comptes$",
        "English": "TRACES OF PAST EXPOSURE FOUND — secure your accounts",
        "Count": 0,
        "Weight": 62
    },
    {
        "French": "Retrait de l installation non confirmé : consultez le rapport.",
        "Pattern": "^Retrait\\ de\\ l\\ installation\\ non\\ confirmé\\ :\\ consultez\\ le\\ rapport\\.$",
        "English": "Installation removal unconfirmed: see the report.",
        "Count": 0,
        "Weight": 62
    },
    {
        "French": "Vous pouvez ajouter un blocage local pour les sites suivants :",
        "Pattern": "^Vous\\ pouvez\\ ajouter\\ un\\ blocage\\ local\\ pour\\ les\\ sites\\ suivants\\ :$",
        "English": "You can add a local block for the following websites:",
        "Count": 0,
        "Weight": 62
    },
    {
        "French": "  Journaux NIKKE : $($historical.Count) journal/journaux avec un marqueur signalé",
        "Pattern": "^\\ \\ Journaux\\ NIKKE\\ :\\ (?<v0>.*?)\\ journal/journaux\\ avec\\ un\\ marqueur\\ signalé$",
        "English": "  NIKKE logs: {0} log(s) with a reported indicator",
        "Count": 1,
        "Weight": 61
    },
    {
        "French": "$label : AUCUN MARQUEUR ACTUEL CONNU — historique NIKKE non vérifié",
        "Pattern": "^(?<v0>.*?)\\ :\\ AUCUN\\ MARQUEUR\\ ACTUEL\\ CONNU\\ —\\ historique\\ NIKKE\\ non\\ vérifié$",
        "English": "{0}: NO KNOWN CURRENT INDICATOR — NIKKE history not checked",
        "Count": 1,
        "Weight": 61
    },
    {
        "French": "Dossier NIKKE ou Launcher [Entrée = annuler si déjà supprimé]",
        "Pattern": "^Dossier\\ NIKKE\\ ou\\ Launcher\\ \\[Entrée\\ =\\ annuler\\ si\\ déjà\\ supprimé\\]$",
        "English": "NIKKE or Launcher folder [Enter = cancel if already removed]",
        "Count": 0,
        "Weight": 61
    },
    {
        "French": "La valeur a changé pendant la sauvegarde : opération annulée.",
        "Pattern": "^La\\ valeur\\ a\\ changé\\ pendant\\ la\\ sauvegarde\\ :\\ opération\\ annulée\\.$",
        "English": "The value changed during backup: action cancelled.",
        "Count": 0,
        "Weight": 61
    },
    {
        "French": "Le fichier a changé depuis la vérification ; laissé en place.",
        "Pattern": "^Le\\ fichier\\ a\\ changé\\ depuis\\ la\\ vérification\\ ;\\ laissé\\ en\\ place\\.$",
        "English": "The file changed since the check; it was left in place.",
        "Count": 0,
        "Weight": 61
    },
    {
        "French": "Nettoyage refusé : aucun fichier déplacé ni registre modifié.",
        "Pattern": "^Nettoyage\\ refusé\\ :\\ aucun\\ fichier\\ déplacé\\ ni\\ registre\\ modifié\\.$",
        "English": "Cleanup declined: no files moved or registry changed.",
        "Count": 0,
        "Weight": 61
    },
    {
        "French": "profil redirigé non parcouru — P pour indiquer le chemin réel",
        "Pattern": "^profil\\ redirigé\\ non\\ parcouru\\ —\\ P\\ pour\\ indiquer\\ le\\ chemin\\ réel$",
        "English": "redirected profile not scanned — press P to specify its real path",
        "Count": 0,
        "Weight": 61
    },
    {
        "French": "Utiliser un chemin local absolu, par exemple D:\\Jeux\\NIKKE : $Path",
        "Pattern": "^Utiliser\\ un\\ chemin\\ local\\ absolu,\\ par\\ exemple\\ D:\\\\Jeux\\\\NIKKE\\ :\\ (?<v0>.*?)$",
        "English": "Use an absolute local path, such as D:\\Games\\NIKKE: {0}",
        "Count": 1,
        "Weight": 61
    },
    {
        "French": "Ces sites sont déjà bloqués ; aucune modification nécessaire.",
        "Pattern": "^Ces\\ sites\\ sont\\ déjà\\ bloqués\\ ;\\ aucune\\ modification\\ nécessaire\\.$",
        "English": "These websites are already blocked; no changes are needed.",
        "Count": 0,
        "Weight": 61
    },
    {
        "French": "Ancien fichier du programme malveillant reconnu par empreinte",
        "Pattern": "^Ancien\\ fichier\\ du\\ programme\\ malveillant\\ reconnu\\ par\\ empreinte$",
        "English": "Old malware file identified by its hash",
        "Count": 0,
        "Weight": 61
    },
    {
        "French": "Installation non localisée : les autres contrôles continuent.",
        "Pattern": "^Installation\\ non\\ localisée\\ :\\ les\\ autres\\ contrôles\\ continuent\\.$",
        "English": "Installation not located: other checks continue.",
        "Count": 0,
        "Weight": 61
    },
    {
        "French": "Journaux NIKKE : lecture incomplète — impossible de conclure",
        "Pattern": "^Journaux\\ NIKKE\\ :\\ lecture\\ incomplète\\ —\\ impossible\\ de\\ conclure$",
        "English": "NIKKE logs: incomplete read — unable to conclude",
        "Count": 0,
        "Weight": 60
    },
    {
        "French": "",
        "Pattern": "^Affichage des preuves limité à 40 lignes correspondantes : (?<v0>.*?)$",
        "English": "Evidence display limited to 40 matching lines: {0}",
        "Count": 1,
        "Weight": 60
    },
    {
        "French": "Nettoyage : {0} action(s) confirmée(s), {1} non terminée(s).",
        "Pattern": "^Nettoyage\\ :\\ (?<v0>.*?)\\ action\\(s\\)\\ confirmée\\(s\\),\\ (?<v1>.*?)\\ non\\ terminée\\(s\\)\\.$",
        "English": "Cleanup: {0} confirmed action(s), {1} unfinished.",
        "Count": 2,
        "Weight": 60
    },
    {
        "French": "$Name : contrôle interrompu ($($_.Exception.Message)). Les autres contrôles continuent.",
        "Pattern": "^(?<v0>.*?)\\ :\\ contrôle\\ interrompu\\ \\((?<v1>.*?)\\)\\.\\ Les\\ autres\\ contrôles\\ continuent\\.$",
        "English": "{0}: check interrupted ({1}). Other checks will continue.",
        "Count": 2,
        "Weight": 59
    },
    {
        "French": "Voulez-vous indiquer un dossier ou le chemin de debug.log ?",
        "Pattern": "^Voulez\\-vous\\ indiquer\\ un\\ dossier\\ ou\\ le\\ chemin\\ de\\ debug\\.log\\ \\?$",
        "English": "Would you like to specify a folder or a debug.log path?",
        "Count": 0,
        "Weight": 59
    },
    {
        "French": "Redémarrage Windows confirmé : le nettoyage peut continuer.",
        "Pattern": "^Redémarrage\\ Windows\\ confirmé\\ :\\ le\\ nettoyage\\ peut\\ continuer\\.$",
        "English": "Windows restart confirmed: cleanup can continue.",
        "Count": 0,
        "Weight": 59
    },
    {
        "French": "Coller le chemin du dossier NIKKE/Launcher ou de debug.log",
        "Pattern": "^Coller\\ le\\ chemin\\ du\\ dossier\\ NIKKE/Launcher\\ ou\\ de\\ debug\\.log$",
        "English": "Paste the NIKKE/Launcher folder path or the debug.log path",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "Le retrait sur un lecteur réseau n est pas pris en charge.",
        "Pattern": "^Le\\ retrait\\ sur\\ un\\ lecteur\\ réseau\\ n\\ est\\ pas\\ pris\\ en\\ charge\\.$",
        "English": "Removal from a network drive is not supported.",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "Aucune trace connue trouvée dans les éléments accessibles.",
        "Pattern": "^Aucune\\ trace\\ connue\\ trouvée\\ dans\\ les\\ éléments\\ accessibles\\.$",
        "English": "No known traces found in accessible items.",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "Rapport sauvegardé hors du cache requis avant suppression.",
        "Pattern": "^Rapport\\ sauvegardé\\ hors\\ du\\ cache\\ requis\\ avant\\ suppression\\.$",
        "English": "A report saved outside the cache is required before deletion.",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "Rapport non sauvegardé : aucun nettoyage ne sera effectué.",
        "Pattern": "^Rapport\\ non\\ sauvegardé\\ :\\ aucun\\ nettoyage\\ ne\\ sera\\ effectué\\.$",
        "English": "Report not saved: no cleanup will be performed.",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "Actions confirmées : {0} ; actions échouées ou partielles : {1}.",
        "Pattern": "^Actions\\ confirmées\\ :\\ (?<v0>.*?)\\ ;\\ actions\\ échouées\\ ou\\ partielles\\ :\\ (?<v1>.*?)\\.$",
        "English": "Confirmed actions: {0}; failed or partial actions: {1}.",
        "Count": 2,
        "Weight": 58
    },
    {
        "French": "Ouvrez ce fichier dans le Bloc-notes pour lire le rapport.",
        "Pattern": "^Ouvrez\\ ce\\ fichier\\ dans\\ le\\ Bloc\\-notes\\ pour\\ lire\\ le\\ rapport\\.$",
        "English": "Open this file in Notepad to read the report.",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "Aucune trace actuelle détectée dans les éléments vérifiés.",
        "Pattern": "^Aucune\\ trace\\ actuelle\\ détectée\\ dans\\ les\\ éléments\\ vérifiés\\.$",
        "English": "No current traces detected in the items checked.",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "Ce fichier ne fait pas partie du nettoyage ciblé autorisé.",
        "Pattern": "^Ce\\ fichier\\ ne\\ fait\\ pas\\ partie\\ du\\ nettoyage\\ ciblé\\ autorisé\\.$",
        "English": "This file is outside the permitted targeted cleanup.",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "Aucun blocage du navigateur créé par NikkeTrace à retirer.",
        "Pattern": "^Aucun\\ blocage\\ du\\ navigateur\\ créé\\ par\\ NikkeTrace\\ à\\ retirer\\.$",
        "English": "No browser block created by NikkeTrace was found to remove.",
        "Count": 0,
        "Weight": 58
    },
    {
        "French": "---------------- QUE VOULEZ-VOUS FAIRE ? ----------------",
        "Pattern": "^\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\ QUE\\ VOULEZ\\-VOUS\\ FAIRE\\ \\?\\ \\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-$",
        "English": "---------------- WHAT WOULD YOU LIKE TO DO? ----------------",
        "Count": 0,
        "Weight": 57
    },
    {
        "French": "B  Retour au menu principal / choisir un autre navigateur",
        "Pattern": "^B\\ \\ Retour\\ au\\ menu\\ principal\\ /\\ choisir\\ un\\ autre\\ navigateur$",
        "English": "B  Main menu / choose another browser",
        "Count": 0,
        "Weight": 57
    },
    {
        "French": "CONTRÔLE PARTIEL — impossible de conclure pour tout le PC",
        "Pattern": "^CONTRÔLE\\ PARTIEL\\ —\\ impossible\\ de\\ conclure\\ pour\\ tout\\ le\\ PC$",
        "English": "PARTIAL CHECK — unable to conclude for the whole PC",
        "Count": 0,
        "Weight": 57
    },
    {
        "French": "Vérification des noms de fichiers temporaires incomplète.",
        "Pattern": "^Vérification\\ des\\ noms\\ de\\ fichiers\\ temporaires\\ incomplète\\.$",
        "English": "Reported temporary filename check incomplete.",
        "Count": 0,
        "Weight": 57
    },
    {
        "French": "Fichier hosts non vérifiable dans les limites de lecture.",
        "Pattern": "^Fichier\\ hosts\\ non\\ vérifiable\\ dans\\ les\\ limites\\ de\\ lecture\\.$",
        "English": "Hosts file cannot be checked within the reading limits.",
        "Count": 0,
        "Weight": 57
    },
    {
        "French": "Ce dossier ne fait pas partie des caches NIKKE autorisés.",
        "Pattern": "^Ce\\ dossier\\ ne\\ fait\\ pas\\ partie\\ des\\ caches\\ NIKKE\\ autorisés\\.$",
        "English": "This folder is not an allowed NIKKE launcher cache.",
        "Count": 0,
        "Weight": 57
    },
    {
        "French": "Interface Windows ouverte ; désinstallation non confirmée",
        "Pattern": "^Interface\\ Windows\\ ouverte\\ ;\\ désinstallation\\ non\\ confirmée$",
        "English": "Windows interface opened; uninstall not confirmed",
        "Count": 0,
        "Weight": 57
    },
    {
        "French": "Ancienne copie non identifiée : conservée pour assistance",
        "Pattern": "^Ancienne\\ copie\\ non\\ identifiée\\ :\\ conservée\\ pour\\ assistance$",
        "English": "Unidentified old copy: kept for assistance",
        "Count": 0,
        "Weight": 57
    },
    {
        "French": "  Historique NIKKE : inconnu — aucun journal exploitable",
        "Pattern": "^\\ \\ Historique\\ NIKKE\\ :\\ inconnu\\ —\\ aucun\\ journal\\ exploitable$",
        "English": "  NIKKE history: unknown — no usable log",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "Ce dossier système ou personnel ne peut pas être retiré.",
        "Pattern": "^Ce\\ dossier\\ système\\ ou\\ personnel\\ ne\\ peut\\ pas\\ être\\ retiré\\.$",
        "English": "This system or personal folder cannot be removed.",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "Choisissez le dossier NIKKE ou Launcher, pas un fichier.",
        "Pattern": "^Choisissez\\ le\\ dossier\\ NIKKE\\ ou\\ Launcher,\\ pas\\ un\\ fichier\\.$",
        "English": "Select the NIKKE or Launcher folder, not a file.",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "Cette option ajoute uniquement ces domaines dans hosts :",
        "Pattern": "^Cette\\ option\\ ajoute\\ uniquement\\ ces\\ domaines\\ dans\\ hosts\\ :$",
        "English": "This option adds only these domains to hosts:",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "1  Vérification complète et nettoyage guidé (recommandé)",
        "Pattern": "^1\\ \\ Vérification\\ complète\\ et\\ nettoyage\\ guidé\\ \\(recommandé\\)$",
        "English": "1  Full check and guided cleanup (recommended)",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "Retirer aussi cette installation du jeu et son lanceur ?",
        "Pattern": "^Retirer\\ aussi\\ cette\\ installation\\ du\\ jeu\\ et\\ son\\ lanceur\\ \\?$",
        "English": "Also remove this game installation and its launcher?",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "Les contrôles disponibles ne permettent pas de conclure.",
        "Pattern": "^Les\\ contrôles\\ disponibles\\ ne\\ permettent\\ pas\\ de\\ conclure\\.$",
        "English": "The available checks do not allow a conclusion.",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "Ancien fichier k2f.lua à examiner ; contenu non confirmé",
        "Pattern": "^Ancien\\ fichier\\ k2f\\.lua\\ à\\ examiner\\ ;\\ contenu\\ non\\ confirmé$",
        "English": "Old k2f.lua file needs review; contents unconfirmed",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "Ancienne référence de démarrage vide liée à cet incident",
        "Pattern": "^Ancienne\\ référence\\ de\\ démarrage\\ vide\\ liée\\ à\\ cet\\ incident$",
        "English": "Empty old startup reference linked to this incident",
        "Count": 0,
        "Weight": 56
    },
    {
        "French": "  $($Snapshot.Issues.Count) limite(s) de vérification — D pour lire les détails.",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ limite\\(s\\)\\ de\\ vérification\\ —\\ D\\ pour\\ lire\\ les\\ détails\\.$",
        "English": "  {0} verification limitation(s) — press D for details.",
        "Count": 1,
        "Weight": 55
    },
    {
        "French": "Cette option est disponible depuis le contrôle complet.",
        "Pattern": "^Cette\\ option\\ est\\ disponible\\ depuis\\ le\\ contrôle\\ complet\\.$",
        "English": "This option is available from the full check.",
        "Count": 0,
        "Weight": 55
    },
    {
        "French": "lecture partielle — D pour connaître le chemin concerné",
        "Pattern": "^lecture\\ partielle\\ —\\ D\\ pour\\ connaître\\ le\\ chemin\\ concerné$",
        "English": "partial read — press D to see the affected path",
        "Count": 0,
        "Weight": 55
    },
    {
        "French": "Vérification locale. Aucun nettoyage sans votre accord.",
        "Pattern": "^Vérification\\ locale\\.\\ Aucun\\ nettoyage\\ sans\\ votre\\ accord\\.$",
        "English": "Local verification. No cleanup without your consent.",
        "Count": 0,
        "Weight": 55
    },
    {
        "French": "CACHE DU LANCEUR — CONTRÔLE INDÉPENDANT DU JEU INSTALLÉ",
        "Pattern": "^CACHE\\ DU\\ LANCEUR\\ —\\ CONTRÔLE\\ INDÉPENDANT\\ DU\\ JEU\\ INSTALLÉ$",
        "English": "LAUNCHER CACHE — CHECKED INDEPENDENTLY OF THE GAME INSTALLATION",
        "Count": 0,
        "Weight": 55
    },
    {
        "French": "TRACES ENCORE PRÉSENTES OU À EXAMINER DANS LES CACHES :",
        "Pattern": "^TRACES\\ ENCORE\\ PRÉSENTES\\ OU\\ À\\ EXAMINER\\ DANS\\ LES\\ CACHES\\ :$",
        "English": "TRACES STILL PRESENT OR NEEDING REVIEW IN THE CACHES:",
        "Count": 0,
        "Weight": 55
    },
    {
        "French": "Appuyez sur Entrée pour fermer, puis redémarrez Windows",
        "Pattern": "^Appuyez\\ sur\\ Entrée\\ pour\\ fermer,\\ puis\\ redémarrez\\ Windows$",
        "English": "Press Enter to close, then restart Windows",
        "Count": 0,
        "Weight": 55
    },
    {
        "French": "Historique NIKKE : inconnu — aucun journal exploitable",
        "Pattern": "^Historique\\ NIKKE\\ :\\ inconnu\\ —\\ aucun\\ journal\\ exploitable$",
        "English": "NIKKE history: unknown — no usable log",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "4  Préparer une analyse Defender hors connexion (aide)",
        "Pattern": "^4\\ \\ Préparer\\ une\\ analyse\\ Defender\\ hors\\ connexion\\ \\(aide\\)$",
        "English": "4  Prepare a Defender Offline scan (help)",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "Choisissez le dossier du profil, pas un disque entier.",
        "Pattern": "^Choisissez\\ le\\ dossier\\ du\\ profil,\\ pas\\ un\\ disque\\ entier\\.$",
        "English": "Select the profile folder, not an entire drive.",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "  Les autres éléments trouvés sont accessibles avec D.",
        "Pattern": "^\\ \\ Les\\ autres\\ éléments\\ trouvés\\ sont\\ accessibles\\ avec\\ D\\.$",
        "English": "  Other findings are available with D.",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "Avant une vérification : fermez NIKKE et son launcher.",
        "Pattern": "^Avant\\ une\\ vérification\\ :\\ fermez\\ NIKKE\\ et\\ son\\ launcher\\.$",
        "English": "Before a check: close NIKKE and its launcher.",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "Rapport non sauvegardé : aucun cache ne sera supprimé.",
        "Pattern": "^Rapport\\ non\\ sauvegardé\\ :\\ aucun\\ cache\\ ne\\ sera\\ supprimé\\.$",
        "English": "Report not saved: no cache will be deleted.",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "Suppression du cache refusée : aucun fichier supprimé.",
        "Pattern": "^Suppression\\ du\\ cache\\ refusée\\ :\\ aucun\\ fichier\\ supprimé\\.$",
        "English": "Cache deletion declined: no files deleted.",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "Suppression du cache limitée aux disques locaux fixes.",
        "Pattern": "^Suppression\\ du\\ cache\\ limitée\\ aux\\ disques\\ locaux\\ fixes\\.$",
        "English": "Cache deletion is restricted to local fixed drives.",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "Empreinte manquante ou invalide : suppression annulée.",
        "Pattern": "^Empreinte\\ manquante\\ ou\\ invalide\\ :\\ suppression\\ annulée\\.$",
        "English": "Missing or invalid hash: deletion cancelled.",
        "Count": 0,
        "Weight": 54
    },
    {
        "French": "  Aucun profil habituel accessible — voir les détails",
        "Pattern": "^\\ \\ Aucun\\ profil\\ habituel\\ accessible\\ —\\ voir\\ les\\ détails$",
        "English": "  No standard profile folder accessible — see details",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "==================== BILAN FINAL ====================",
        "Pattern": "^====================\\ BILAN\\ FINAL\\ ====================$",
        "English": "==================== FINAL REPORT ====================",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "Aucun nettoyage automatique proposé pour ce résultat.",
        "Pattern": "^Aucun\\ nettoyage\\ automatique\\ proposé\\ pour\\ ce\\ résultat\\.$",
        "English": "No automatic cleanup is available for this result.",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "Choisir le dossier du jeu, pas la racine du disque : $Path",
        "Pattern": "^Choisir\\ le\\ dossier\\ du\\ jeu,\\ pas\\ la\\ racine\\ du\\ disque\\ :\\ (?<v0>.*?)$",
        "English": "Select the game folder, not the drive root: {0}",
        "Count": 1,
        "Weight": 53
    },
    {
        "French": "Pour quel navigateur voulez-vous indiquer le profil ?",
        "Pattern": "^Pour\\ quel\\ navigateur\\ voulez\\-vous\\ indiquer\\ le\\ profil\\ \\?$",
        "English": "Which browser profile would you like to specify?",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "PROTÉGER VOS COMPTES — MÊME SI LES TRACES ONT DISPARU",
        "Pattern": "^PROTÉGER\\ VOS\\ COMPTES\\ —\\ MÊME\\ SI\\ LES\\ TRACES\\ ONT\\ DISPARU$",
        "English": "PROTECT YOUR ACCOUNTS — EVEN IF INDICATORS HAVE DISAPPEARED",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "Connexion TCP résiduelle TIME_WAIT vers l IP signalée",
        "Pattern": "^Connexion\\ TCP\\ résiduelle\\ TIME_WAIT\\ vers\\ l\\ IP\\ signalée$",
        "English": "Residual TIME_WAIT TCP connection to the reported IP",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "AUCUNE TRACE CONNUE TROUVÉE DANS LES CACHES VÉRIFIÉS.",
        "Pattern": "^AUCUNE\\ TRACE\\ CONNUE\\ TROUVÉE\\ DANS\\ LES\\ CACHES\\ VÉRIFIÉS\\.$",
        "English": "NO KNOWN TRACES FOUND IN THE CHECKED CACHES.",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "La suppression du fichier ne peut pas être confirmée.",
        "Pattern": "^La\\ suppression\\ du\\ fichier\\ ne\\ peut\\ pas\\ être\\ confirmée\\.$",
        "English": "File deletion could not be confirmed.",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "Ouverture de la désinstallation Windows non confirmée",
        "Pattern": "^Ouverture\\ de\\ la\\ désinstallation\\ Windows\\ non\\ confirmée$",
        "English": "Opening Windows uninstall could not be confirmed",
        "Count": 0,
        "Weight": 53
    },
    {
        "French": "  Journaux du jeu : non consultés dans cette option.",
        "Pattern": "^\\ \\ Journaux\\ du\\ jeu\\ :\\ non\\ consultés\\ dans\\ cette\\ option\\.$",
        "English": "  Game logs: not checked by this option.",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "2  Jeu déjà supprimé : vérifier les traces restantes",
        "Pattern": "^2\\ \\ Jeu\\ déjà\\ supprimé\\ :\\ vérifier\\ les\\ traces\\ restantes$",
        "English": "2  Game already removed: check remaining indicators",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "Choisissez un navigateur précis, par exemple Chrome.",
        "Pattern": "^Choisissez\\ un\\ navigateur\\ précis,\\ par\\ exemple\\ Chrome\\.$",
        "English": "Choose a specific browser, such as Chrome.",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "Demarrage Chrome Helper : ce nom seul ne prouve rien",
        "Pattern": "^Demarrage\\ Chrome\\ Helper\\ :\\ ce\\ nom\\ seul\\ ne\\ prouve\\ rien$",
        "English": "Chrome Helper startup entry: this name alone proves nothing",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "Empreinte du payload signalé dans un fichier tinyget",
        "Pattern": "^Empreinte\\ du\\ payload\\ signalé\\ dans\\ un\\ fichier\\ tinyget$",
        "English": "Known payload fingerprint in a tinyget file",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "Reference du registre correspondant aux signalements",
        "Pattern": "^Reference\\ du\\ registre\\ correspondant\\ aux\\ signalements$",
        "English": "Registry reference matching reported indicators",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "SUPPRESSION CONFIRMÉE de la référence de registre : $($f.Location)",
        "Pattern": "^SUPPRESSION\\ CONFIRMÉE\\ de\\ la\\ référence\\ de\\ registre\\ :\\ (?<v0>.*?)$",
        "English": "REGISTRY REFERENCE REMOVAL CONFIRMED: {0}",
        "Count": 1,
        "Weight": 52
    },
    {
        "French": "Marqueur de cache non retrouvé ; déplacement annulé.",
        "Pattern": "^Marqueur\\ de\\ cache\\ non\\ retrouvé\\ ;\\ déplacement\\ annulé\\.$",
        "English": "Cache marker no longer found; move cancelled.",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "1  Rechercher les traces connues de l incident NIKKE",
        "Pattern": "^1\\ \\ Rechercher\\ les\\ traces\\ connues\\ de\\ l\\ incident\\ NIKKE$",
        "English": "1  Check for known traces of the NIKKE incident",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "6  Bloquer les domaines signalés (facultatif, admin)",
        "Pattern": "^6\\ \\ Bloquer\\ les\\ domaines\\ signalés\\ \\(facultatif,\\ admin\\)$",
        "English": "6  Block reported domains (optional, admin)",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "Aucun cache NIKKE trouvé aux emplacements habituels.",
        "Pattern": "^Aucun\\ cache\\ NIKKE\\ trouvé\\ aux\\ emplacements\\ habituels\\.$",
        "English": "No NIKKE launcher cache found in the usual locations.",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "Ce contrôle ciblé ne certifie pas la sécurité du PC.",
        "Pattern": "^Ce\\ contrôle\\ ciblé\\ ne\\ certifie\\ pas\\ la\\ sécurité\\ du\\ PC\\.$",
        "English": "This targeted check does not certify the security of the PC.",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "Fichier supprimé définitivement ; absence confirmée.",
        "Pattern": "^Fichier\\ supprimé\\ définitivement\\ ;\\ absence\\ confirmée\\.$",
        "English": "File permanently deleted; absence confirmed.",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "ACCÈS INTERNET DU NAVIGATEUR DU LANCEUR (FACULTATIF)",
        "Pattern": "^ACCÈS\\ INTERNET\\ DU\\ NAVIGATEUR\\ DU\\ LANCEUR\\ \\(FACULTATIF\\)$",
        "English": "LAUNCHER BROWSER INTERNET ACCESS (OPTIONAL)",
        "Count": 0,
        "Weight": 52
    },
    {
        "French": "Aucun profil habituel accessible — voir les détails",
        "Pattern": "^Aucun\\ profil\\ habituel\\ accessible\\ —\\ voir\\ les\\ détails$",
        "English": "No standard profile folder accessible — see details",
        "Count": 0,
        "Weight": 51
    },
    {
        "French": "  L'absence de marqueur ne garantit pas un PC sain.",
        "Pattern": "^\\ \\ L'absence\\ de\\ marqueur\\ ne\\ garantit\\ pas\\ un\\ PC\\ sain\\.$",
        "English": "  An absence of indicators does not guarantee a clean PC.",
        "Count": 0,
        "Weight": 51
    },
    {
        "French": "dossier trouvé, recherche limitée — D pour la cause",
        "Pattern": "^dossier\\ trouvé,\\ recherche\\ limitée\\ —\\ D\\ pour\\ la\\ cause$",
        "English": "folder found, search limit reached — press D for the cause",
        "Count": 0,
        "Weight": 51
    },
    {
        "French": "P  Indiquer le dossier d un profil, puis revérifier",
        "Pattern": "^P\\ \\ Indiquer\\ le\\ dossier\\ d\\ un\\ profil,\\ puis\\ revérifier$",
        "English": "P  Specify a profile folder, then recheck",
        "Count": 0,
        "Weight": 51
    },
    {
        "French": "Surcharge utilisateur du CLSID signale : a examiner",
        "Pattern": "^Surcharge\\ utilisateur\\ du\\ CLSID\\ signale\\ :\\ a\\ examiner$",
        "English": "User override of the reported CLSID: investigate",
        "Count": 0,
        "Weight": 51
    },
    {
        "French": "Contrôle des anciennes copies NikkeTrace incomplet.",
        "Pattern": "^Contrôle\\ des\\ anciennes\\ copies\\ NikkeTrace\\ incomplet\\.$",
        "English": "Old NikkeTrace copy check is incomplete.",
        "Count": 0,
        "Weight": 51
    },
    {
        "French": "Journaux du jeu : non consultés dans cette option.",
        "Pattern": "^Journaux\\ du\\ jeu\\ :\\ non\\ consultés\\ dans\\ cette\\ option\\.$",
        "English": "Game logs: not checked by this option.",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "REVÉRIFICATION AUTOMATIQUE — merci de patienter...",
        "Pattern": "^REVÉRIFICATION\\ AUTOMATIQUE\\ —\\ merci\\ de\\ patienter\\.\\.\\.$",
        "English": "AUTOMATIC RECHECK — please wait...",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "Un résultat sans trace ne garantit pas un PC sain.",
        "Pattern": "^Un\\ résultat\\ sans\\ trace\\ ne\\ garantit\\ pas\\ un\\ PC\\ sain\\.$",
        "English": "A result without indicators does not guarantee a clean PC.",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "  Cache : contrôle incomplet — D pour les détails.",
        "Pattern": "^\\ \\ Cache\\ :\\ contrôle\\ incomplet\\ —\\ D\\ pour\\ les\\ détails\\.$",
        "English": "  Cache: incomplete check — D for details.",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "Blocage des domaines refusé : aucune modification.",
        "Pattern": "^Blocage\\ des\\ domaines\\ refusé\\ :\\ aucune\\ modification\\.$",
        "English": "Domain block declined: no changes made.",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "TRACES TROUVÉES — CHEMINS COMPLETS DANS LE RAPPORT",
        "Pattern": "^TRACES\\ TROUVÉES\\ —\\ CHEMINS\\ COMPLETS\\ DANS\\ LE\\ RAPPORT$",
        "English": "TRACES FOUND — FULL LOCATIONS IN THE REPORT",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "Ouverture refusée : aucune désinstallation lancée.",
        "Pattern": "^Ouverture\\ refusée\\ :\\ aucune\\ désinstallation\\ lancée\\.$",
        "English": "Opening declined: no uninstall started.",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "Ancienne copie de fichier conservée par NikkeTrace",
        "Pattern": "^Ancienne\\ copie\\ de\\ fichier\\ conservée\\ par\\ NikkeTrace$",
        "English": "Old file copy retained by NikkeTrace",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "1  Bloquer les connexions du navigateur du lanceur",
        "Pattern": "^1\\ \\ Bloquer\\ les\\ connexions\\ du\\ navigateur\\ du\\ lanceur$",
        "English": "1  Block launcher browser connections",
        "Count": 0,
        "Weight": 50
    },
    {
        "French": "L'absence de marqueur ne garantit pas un PC sain.",
        "Pattern": "^L'absence\\ de\\ marqueur\\ ne\\ garantit\\ pas\\ un\\ PC\\ sain\\.$",
        "English": "An absence of indicators does not guarantee a clean PC.",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "1  Contrôle complet : jeu + navigateurs + Windows",
        "Pattern": "^1\\ \\ Contrôle\\ complet\\ :\\ jeu\\ \\+\\ navigateurs\\ \\+\\ Windows$",
        "English": "1  Full check: game + browsers + Windows",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "Dossier non parcouru ou partiellement parcouru : $dir",
        "Pattern": "^Dossier\\ non\\ parcouru\\ ou\\ partiellement\\ parcouru\\ :\\ (?<v0>.*?)$",
        "English": "Folder not scanned, or only partly scanned: {0}",
        "Count": 1,
        "Weight": 49
    },
    {
        "French": "Un lien ou une jonction empêche un nettoyage sûr.",
        "Pattern": "^Un\\ lien\\ ou\\ une\\ jonction\\ empêche\\ un\\ nettoyage\\ sûr\\.$",
        "English": "A link or junction prevents safe cleanup.",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "VERIFICATION INCOMPLETE - impossible de conclure.",
        "Pattern": "^VERIFICATION\\ INCOMPLETE\\ \\-\\ impossible\\ de\\ conclure\\.$",
        "English": "INCOMPLETE CHECK — unable to conclude.",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "TRACE PRÉCÉDEMMENT TROUVÉE — retrait non confirmé",
        "Pattern": "^TRACE\\ PRÉCÉDEMMENT\\ TROUVÉE\\ —\\ retrait\\ non\\ confirmé$",
        "English": "PREVIOUSLY FOUND TRACE — removal not confirmed",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "Suppression du cache incomplète ou non confirmée.",
        "Pattern": "^Suppression\\ du\\ cache\\ incomplète\\ ou\\ non\\ confirmée\\.$",
        "English": "Cache deletion incomplete or unconfirmed.",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "TRACES HISTORIQUES — EXPOSITION PASSÉE À EXAMINER",
        "Pattern": "^TRACES\\ HISTORIQUES\\ —\\ EXPOSITION\\ PASSÉE\\ À\\ EXAMINER$",
        "English": "HISTORICAL TRACES — REVIEW PAST EXPOSURE",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "6  Aide pour une analyse antivirus hors connexion",
        "Pattern": "^6\\ \\ Aide\\ pour\\ une\\ analyse\\ antivirus\\ hors\\ connexion$",
        "English": "6  Offline antivirus scan guidance",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "Dossier du jeu ou de debug.log [Entrée = annuler]",
        "Pattern": "^Dossier\\ du\\ jeu\\ ou\\ de\\ debug\\.log\\ \\[Entrée\\ =\\ annuler\\]$",
        "English": "Game or debug.log folder [Enter = cancel]",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "5  Aide pour une analyse antivirus hors connexion",
        "Pattern": "^5\\ \\ Aide\\ pour\\ une\\ analyse\\ antivirus\\ hors\\ connexion$",
        "English": "5  Help with an offline antivirus scan",
        "Count": 0,
        "Weight": 49
    },
    {
        "French": "À FAIRE PAR PRÉCAUTION DEPUIS UN APPAREIL SAIN :",
        "Pattern": "^À\\ FAIRE\\ PAR\\ PRÉCAUTION\\ DEPUIS\\ UN\\ APPAREIL\\ SAIN\\ :$",
        "English": "PRECAUTIONS TO TAKE FROM A CLEAN DEVICE:",
        "Count": 0,
        "Weight": 48
    },
    {
        "French": "Cache source toujours présent après déplacement.",
        "Pattern": "^Cache\\ source\\ toujours\\ présent\\ après\\ déplacement\\.$",
        "English": "Source cache still present after the move.",
        "Count": 0,
        "Weight": 48
    },
    {
        "French": "Domaine signalé redirigé dans hosts : à examiner",
        "Pattern": "^Domaine\\ signalé\\ redirigé\\ dans\\ hosts\\ :\\ à\\ examiner$",
        "English": "Reported domain redirected in hosts: investigate",
        "Count": 0,
        "Weight": 48
    },
    {
        "French": "CONTRÔLES COMPLÉMENTAIRES — OBSERVATIONS LOCALES",
        "Pattern": "^CONTRÔLES\\ COMPLÉMENTAIRES\\ —\\ OBSERVATIONS\\ LOCALES$",
        "English": "ADDITIONAL CHECKS — LOCAL OBSERVATIONS",
        "Count": 0,
        "Weight": 48
    },
    {
        "French": "Avant de choisir : fermez NIKKE et son launcher.",
        "Pattern": "^Avant\\ de\\ choisir\\ :\\ fermez\\ NIKKE\\ et\\ son\\ launcher\\.$",
        "English": "Before choosing: close NIKKE and its launcher.",
        "Count": 0,
        "Weight": 48
    },
    {
        "French": "RETRAIT NON CONFIRMÉ — VÉRIFICATIONS NÉCESSAIRES",
        "Pattern": "^RETRAIT\\ NON\\ CONFIRMÉ\\ —\\ VÉRIFICATIONS\\ NÉCESSAIRES$",
        "English": "REMOVAL UNCONFIRMED — FURTHER CHECKS NEEDED",
        "Count": 0,
        "Weight": 48
    },
    {
        "French": "3  Indiquer un profil de navigateur personnalisé",
        "Pattern": "^3\\ \\ Indiquer\\ un\\ profil\\ de\\ navigateur\\ personnalisé$",
        "English": "3  Specify a custom browser profile",
        "Count": 0,
        "Weight": 48
    },
    {
        "French": "Installation proposée à la désinstallation : {0}",
        "Pattern": "^Installation\\ proposée\\ à\\ la\\ désinstallation\\ :\\ (?<v0>.*?)$",
        "English": "Installation offered for uninstall: {0}",
        "Count": 1,
        "Weight": 48
    },
    {
        "French": "1  Traiter $cleanable trace(s) connue(s), puis revérifier",
        "Pattern": "^1\\ \\ Traiter\\ (?<v0>.*?)\\ trace\\(s\\)\\ connue\\(s\\),\\ puis\\ revérifier$",
        "English": "1  Handle {0} known indicator(s), then recheck",
        "Count": 1,
        "Weight": 47
    },
    {
        "French": "Ce chemin de navigateur n est pas un dossier : $Root",
        "Pattern": "^Ce\\ chemin\\ de\\ navigateur\\ n\\ est\\ pas\\ un\\ dossier\\ :\\ (?<v0>.*?)$",
        "English": "This browser path is not a folder: {0}",
        "Count": 1,
        "Weight": 47
    },
    {
        "French": "Informations d'installation inaccessibles : $hive / $view",
        "Pattern": "^Informations\\ d'installation\\ inaccessibles\\ :\\ (?<v0>.*?)\\ /\\ (?<v1>.*?)$",
        "English": "Installation information inaccessible: {0} / {1}",
        "Count": 2,
        "Weight": 47
    },
    {
        "French": "Ouvrir Sécurité Windows sans lancer l analyse ?",
        "Pattern": "^Ouvrir\\ Sécurité\\ Windows\\ sans\\ lancer\\ l\\ analyse\\ \\?$",
        "English": "Open Windows Security without starting the scan?",
        "Count": 0,
        "Weight": 47
    },
    {
        "French": "profil non trouvé — P pour indiquer son dossier",
        "Pattern": "^profil\\ non\\ trouvé\\ —\\ P\\ pour\\ indiquer\\ son\\ dossier$",
        "English": "profile not found — press P to specify its folder",
        "Count": 0,
        "Weight": 47
    },
    {
        "French": "IMPORTANT — CHANGEZ LES MOTS DE PASSE CONCERNÉS",
        "Pattern": "^IMPORTANT\\ —\\ CHANGEZ\\ LES\\ MOTS\\ DE\\ PASSE\\ CONCERNÉS$",
        "English": "IMPORTANT — CHANGE AFFECTED PASSWORDS",
        "Count": 0,
        "Weight": 47
    },
    {
        "French": "Modules non vérifiables pour le processus PID {0}.",
        "Pattern": "^Modules\\ non\\ vérifiables\\ pour\\ le\\ processus\\ PID\\ (?<v0>.*?)\\.$",
        "English": "Modules could not be checked for process PID {0}.",
        "Count": 1,
        "Weight": 47
    },
    {
        "French": "CACHE NON SUPPRIMÉ OU SUPPRESSION INCOMPLÈTE : {0}",
        "Pattern": "^CACHE\\ NON\\ SUPPRIMÉ\\ OU\\ SUPPRESSION\\ INCOMPLÈTE\\ :\\ (?<v0>.*?)$",
        "English": "CACHE NOT DELETED OR DELETION INCOMPLETE: {0}",
        "Count": 1,
        "Weight": 47
    },
    {
        "French": "Cache restant ou recréé pendant la suppression.",
        "Pattern": "^Cache\\ restant\\ ou\\ recréé\\ pendant\\ la\\ suppression\\.$",
        "English": "Cache remains or was recreated during deletion.",
        "Count": 0,
        "Weight": 47
    },
    {
        "French": "NETTOYAGE GUIDÉ — JEU INSTALLÉ OU DÉJÀ SUPPRIMÉ",
        "Pattern": "^NETTOYAGE\\ GUIDÉ\\ —\\ JEU\\ INSTALLÉ\\ OU\\ DÉJÀ\\ SUPPRIMÉ$",
        "English": "GUIDED CLEANUP — GAME INSTALLED OR ALREADY REMOVED",
        "Count": 0,
        "Weight": 47
    },
    {
        "French": "NETTOYAGE PROPOSÉ — VOTRE ACCORD EST NÉCESSAIRE",
        "Pattern": "^NETTOYAGE\\ PROPOSÉ\\ —\\ VOTRE\\ ACCORD\\ EST\\ NÉCESSAIRE$",
        "English": "PROPOSED CLEANUP — YOUR CONSENT IS REQUIRED",
        "Count": 0,
        "Weight": 47
    },
    {
        "French": "Ouvrir les applications installées de Windows ?",
        "Pattern": "^Ouvrir\\ les\\ applications\\ installées\\ de\\ Windows\\ \\?$",
        "English": "Open Windows Installed apps?",
        "Count": 0,
        "Weight": 47
    },
    {
        "French": "3  Voir les conseils pour protéger mes comptes",
        "Pattern": "^3\\ \\ Voir\\ les\\ conseils\\ pour\\ protéger\\ mes\\ comptes$",
        "English": "3  Account protection advice",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "Avez-vous déjà supprimé ou désinstallé NIKKE ?",
        "Pattern": "^Avez\\-vous\\ déjà\\ supprimé\\ ou\\ désinstallé\\ NIKKE\\ \\?$",
        "English": "Have you already removed or uninstalled NIKKE?",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "Collez le chemin du dossier [Entrée = annuler]",
        "Pattern": "^Collez\\ le\\ chemin\\ du\\ dossier\\ \\[Entrée\\ =\\ annuler\\]$",
        "English": "Paste the folder path [Enter = cancel]",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "Les profils réseau ne sont pas pris en charge.",
        "Pattern": "^Les\\ profils\\ réseau\\ ne\\ sont\\ pas\\ pris\\ en\\ charge\\.$",
        "English": "Network profiles are not supported.",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "Marqueur du signalement dans un ancien journal",
        "Pattern": "^Marqueur\\ du\\ signalement\\ dans\\ un\\ ancien\\ journal$",
        "English": "Reported indicator in an old log",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "Numéro du dossier à retirer [Entrée = annuler]",
        "Pattern": "^Numéro\\ du\\ dossier\\ à\\ retirer\\ \\[Entrée\\ =\\ annuler\\]$",
        "English": "Folder number to remove [Enter = cancel]",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "Référence de démarrage Chrome dans le registre",
        "Pattern": "^Référence\\ de\\ démarrage\\ Chrome\\ dans\\ le\\ registre$",
        "English": "Chrome startup registry reference",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "Retrait du jeu refusé : aucun dossier déplacé.",
        "Pattern": "^Retrait\\ du\\ jeu\\ refusé\\ :\\ aucun\\ dossier\\ déplacé\\.$",
        "English": "Game removal declined: no folder moved.",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "Cache du lanceur supprimé ; absence confirmée.",
        "Pattern": "^Cache\\ du\\ lanceur\\ supprimé\\ ;\\ absence\\ confirmée\\.$",
        "English": "Launcher cache deleted; absence confirmed.",
        "Count": 0,
        "Weight": 46
    },
    {
        "French": "================ RÉSULTAT — $title ================",
        "Pattern": "^================\\ RÉSULTAT\\ —\\ (?<v0>.*?)\\ ================$",
        "English": "================ RESULT — {0} ================",
        "Count": 1,
        "Weight": 45
    },
    {
        "French": "ÉLÉMENTS À EXAMINER — infection non confirmée",
        "Pattern": "^ÉLÉMENTS\\ À\\ EXAMINER\\ —\\ infection\\ non\\ confirmée$",
        "English": "ITEMS TO INVESTIGATE — infection not confirmed",
        "Count": 0,
        "Weight": 45
    },
    {
        "French": "Recherche de debug.log et de ses rotations : $($item.FullName)",
        "Pattern": "^Recherche\\ de\\ debug\\.log\\ et\\ de\\ ses\\ rotations\\ :\\ (?<v0>.*?)$",
        "English": "Searching debug.log and rotated logs: {0}",
        "Count": 1,
        "Weight": 45
    },
    {
        "French": "2  Indiquer le dossier du jeu ou de debug.log",
        "Pattern": "^2\\ \\ Indiquer\\ le\\ dossier\\ du\\ jeu\\ ou\\ de\\ debug\\.log$",
        "English": "2  Specify the game or debug.log folder",
        "Count": 0,
        "Weight": 45
    },
    {
        "French": "Ancien fichier signalé dans le dossier Chrome",
        "Pattern": "^Ancien\\ fichier\\ signalé\\ dans\\ le\\ dossier\\ Chrome$",
        "English": "Reported legacy file in the Chrome folder",
        "Count": 0,
        "Weight": 45
    },
    {
        "French": "Entrée de démarrage Windows dans le registre",
        "Pattern": "^Entrée\\ de\\ démarrage\\ Windows\\ dans\\ le\\ registre$",
        "English": "Windows startup registry entry",
        "Count": 0,
        "Weight": 44
    },
    {
        "French": "RETIRER LE JEU SANS LANCER SON DÉSINSTALLEUR",
        "Pattern": "^RETIRER\\ LE\\ JEU\\ SANS\\ LANCER\\ SON\\ DÉSINSTALLEUR$",
        "English": "REMOVE THE GAME WITHOUT RUNNING ITS UNINSTALLER",
        "Count": 0,
        "Weight": 44
    },
    {
        "French": "Vérification en cours... merci de patienter.",
        "Pattern": "^Vérification\\ en\\ cours\\.\\.\\.\\ merci\\ de\\ patienter\\.$",
        "English": "Checking... please wait.",
        "Count": 0,
        "Weight": 44
    },
    {
        "French": "Détail technique — programme non inspecté : {0}",
        "Pattern": "^Détail\\ technique\\ —\\ programme\\ non\\ inspecté\\ :\\ (?<v0>.*?)$",
        "English": "Technical detail — program not inspected: {0}",
        "Count": 1,
        "Weight": 44
    },
    {
        "French": "CACHE NIKKE SUPPRIMÉ ET ABSENCE CONFIRMÉE : {0}",
        "Pattern": "^CACHE\\ NIKKE\\ SUPPRIMÉ\\ ET\\ ABSENCE\\ CONFIRMÉE\\ :\\ (?<v0>.*?)$",
        "English": "NIKKE LAUNCHER CACHE DELETED AND ABSENCE CONFIRMED: {0}",
        "Count": 1,
        "Weight": 44
    },
    {
        "French": "DÉTAILS TECHNIQUES ET HISTORIQUE DES ACTIONS",
        "Pattern": "^DÉTAILS\\ TECHNIQUES\\ ET\\ HISTORIQUE\\ DES\\ ACTIONS$",
        "English": "TECHNICAL DETAILS AND ACTION HISTORY",
        "Count": 0,
        "Weight": 44
    },
    {
        "French": "Référence du registre retirée et sauvegardée",
        "Pattern": "^Référence\\ du\\ registre\\ retirée\\ et\\ sauvegardée$",
        "English": "Startup entry removed and backed up",
        "Count": 0,
        "Weight": 44
    },
    {
        "French": "Aucun nettoyage à proposer pour ce résultat.",
        "Pattern": "^Aucun\\ nettoyage\\ à\\ proposer\\ pour\\ ce\\ résultat\\.$",
        "English": "No cleanup to offer for this result.",
        "Count": 0,
        "Weight": 44
    },
    {
        "French": "Blocage des sites confirmé par vérification.",
        "Pattern": "^Blocage\\ des\\ sites\\ confirmé\\ par\\ vérification\\.$",
        "English": "Website blocking confirmed by verification.",
        "Count": 0,
        "Weight": 44
    },
    {
        "French": "Dossier NIKKE ou Launcher [Entrée = annuler]",
        "Pattern": "^Dossier\\ NIKKE\\ ou\\ Launcher\\ \\[Entrée\\ =\\ annuler\\]$",
        "English": "NIKKE or Launcher folder [Enter = cancel]",
        "Count": 0,
        "Weight": 44
    },
    {
        "French": "    - $($Rows.Count - 3) autre(s) élément(s) dans les détails",
        "Pattern": "^\\ \\ \\ \\ \\-\\ (?<v0>.*?)\\ autre\\(s\\)\\ élément\\(s\\)\\ dans\\ les\\ détails$",
        "English": "    {0} more item(s) in the details",
        "Count": 1,
        "Weight": 43
    },
    {
        "French": "Journaux et informations de récupération : $($result.Backup)",
        "Pattern": "^Journaux\\ et\\ informations\\ de\\ récupération\\ :\\ (?<v0>.*?)$",
        "English": "Logs and recovery information: {0}",
        "Count": 1,
        "Weight": 43
    },
    {
        "French": "État de l agent signalé dans le cache NIKKE",
        "Pattern": "^État\\ de\\ l\\ agent\\ signalé\\ dans\\ le\\ cache\\ NIKKE$",
        "English": "Reported agent state in NIKKE cache",
        "Count": 0,
        "Weight": 43
    },
    {
        "French": "Cache : limite globale de 128 Mio atteinte.",
        "Pattern": "^Cache\\ :\\ limite\\ globale\\ de\\ 128\\ Mio\\ atteinte\\.$",
        "English": "Cache: overall 128 MiB limit reached.",
        "Count": 0,
        "Weight": 43
    },
    {
        "French": "AUCUNE TRACE CONNUE DE CET INCIDENT TROUVÉE",
        "Pattern": "^AUCUNE\\ TRACE\\ CONNUE\\ DE\\ CET\\ INCIDENT\\ TROUVÉE$",
        "English": "NO KNOWN TRACES OF THIS INCIDENT FOUND",
        "Count": 0,
        "Weight": 43
    },
    {
        "French": "Supprimer définitivement ces caches NIKKE ?",
        "Pattern": "^Supprimer\\ définitivement\\ ces\\ caches\\ NIKKE\\ \\?$",
        "English": "Permanently delete these NIKKE launcher caches?",
        "Count": 0,
        "Weight": 43
    },
    {
        "French": "5  Bloquer les domaines signalés dans hosts",
        "Pattern": "^5\\ \\ Bloquer\\ les\\ domaines\\ signalés\\ dans\\ hosts$",
        "English": "5  Block reported websites",
        "Count": 0,
        "Weight": 43
    },
    {
        "French": "Cache : limite de 512 fichiers atteinte : {0}",
        "Pattern": "^Cache\\ :\\ limite\\ de\\ 512\\ fichiers\\ atteinte\\ :\\ (?<v0>.*?)$",
        "English": "Cache: 512-file limit reached: {0}",
        "Count": 1,
        "Weight": 42
    },
    {
        "French": "Cause technique du retrait non confirmé : {0}",
        "Pattern": "^Cause\\ technique\\ du\\ retrait\\ non\\ confirmé\\ :\\ (?<v0>.*?)$",
        "English": "Technical cause of unconfirmed removal: {0}",
        "Count": 1,
        "Weight": 42
    },
    {
        "French": "Demander la fermeture de ces navigateurs ?",
        "Pattern": "^Demander\\ la\\ fermeture\\ de\\ ces\\ navigateurs\\ \\?$",
        "English": "Request that these browsers close?",
        "Count": 0,
        "Weight": 42
    },
    {
        "French": "Cache NIKKE et profil CEF : traces connues",
        "Pattern": "^Cache\\ NIKKE\\ et\\ profil\\ CEF\\ :\\ traces\\ connues$",
        "English": "NIKKE launcher cache and CEF profile: known traces",
        "Count": 0,
        "Weight": 42
    },
    {
        "French": "[V] Revérifier   [D] Détails   [Q] Quitter",
        "Pattern": "^\\[V\\]\\ Revérifier\\ \\ \\ \\[D\\]\\ Détails\\ \\ \\ \\[Q\\]\\ Quitter$",
        "English": "[V] Check again   [D] Details   [Q] Quit",
        "Count": 0,
        "Weight": 42
    },
    {
        "French": "La vérification n a pas pu être effectuée.",
        "Pattern": "^La\\ vérification\\ n\\ a\\ pas\\ pu\\ être\\ effectuée\\.$",
        "English": "The check could not be performed.",
        "Count": 0,
        "Weight": 42
    },
    {
        "French": "Connexions locales vers l adresse signalée",
        "Pattern": "^Connexions\\ locales\\ vers\\ l\\ adresse\\ signalée$",
        "English": "Local connections to the reported address",
        "Count": 0,
        "Weight": 42
    },
    {
        "French": "Opération refusée : aucune règle modifiée.",
        "Pattern": "^Opération\\ refusée\\ :\\ aucune\\ règle\\ modifiée\\.$",
        "English": "Operation declined: no rule changed.",
        "Count": 0,
        "Weight": 42
    },
    {
        "French": "ANALYSE MICROSOFT DEFENDER HORS CONNEXION",
        "Pattern": "^ANALYSE\\ MICROSOFT\\ DEFENDER\\ HORS\\ CONNEXION$",
        "English": "MICROSOFT DEFENDER OFFLINE SCAN",
        "Count": 0,
        "Weight": 41
    },
    {
        "French": "Fichier temporaire portant un nom signalé",
        "Pattern": "^Fichier\\ temporaire\\ portant\\ un\\ nom\\ signalé$",
        "English": "Temporary file with a reported name",
        "Count": 0,
        "Weight": 41
    },
    {
        "French": "NAVIGATEURS — TRACES PRÉSENTES MAINTENANT",
        "Pattern": "^NAVIGATEURS\\ —\\ TRACES\\ PRÉSENTES\\ MAINTENANT$",
        "English": "BROWSERS — INDICATORS PRESENT NOW",
        "Count": 0,
        "Weight": 41
    },
    {
        "French": "Registre partiellement inaccessible : $hive / $view",
        "Pattern": "^Registre\\ partiellement\\ inaccessible\\ :\\ (?<v0>.*?)\\ /\\ (?<v1>.*?)$",
        "English": "Registry partly inaccessible: {0} / {1}",
        "Count": 2,
        "Weight": 41
    },
    {
        "French": "Liste des processus vide ou indisponible.",
        "Pattern": "^Liste\\ des\\ processus\\ vide\\ ou\\ indisponible\\.$",
        "English": "Process list empty or unavailable.",
        "Count": 0,
        "Weight": 41
    },
    {
        "French": "Nettoyage refusé : aucun élément modifié.",
        "Pattern": "^Nettoyage\\ refusé\\ :\\ aucun\\ élément\\ modifié\\.$",
        "English": "Cleanup declined: nothing changed.",
        "Count": 0,
        "Weight": 41
    },
    {
        "French": "NAVIGATEUR — TRACES PRÉSENTES MAINTENANT",
        "Pattern": "^NAVIGATEUR\\ —\\ TRACES\\ PRÉSENTES\\ MAINTENANT$",
        "English": "BROWSER — INDICATORS PRESENT NOW",
        "Count": 0,
        "Weight": 40
    },
    {
        "French": "BLOCAGE FACULTATIF DES DOMAINES SIGNALÉS",
        "Pattern": "^BLOCAGE\\ FACULTATIF\\ DES\\ DOMAINES\\ SIGNALÉS$",
        "English": "OPTIONAL BLOCKING OF REPORTED DOMAINS",
        "Count": 0,
        "Weight": 40
    },
    {
        "French": "Dossier AppData du lanceur indisponible.",
        "Pattern": "^Dossier\\ AppData\\ du\\ lanceur\\ indisponible\\.$",
        "English": "The launcher's AppData folder is unavailable.",
        "Count": 0,
        "Weight": 40
    },
    {
        "French": "contrôle incomplet — D pour les détails",
        "Pattern": "^contrôle\\ incomplet\\ —\\ D\\ pour\\ les\\ détails$",
        "English": "incomplete check — press D for details",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "Dossier de profil fourni introuvable : $Root",
        "Pattern": "^Dossier\\ de\\ profil\\ fourni\\ introuvable\\ :\\ (?<v0>.*?)$",
        "English": "Provided profile folder not found: {0}",
        "Count": 1,
        "Weight": 39
    },
    {
        "French": "Le dossier temporaire est indisponible.",
        "Pattern": "^Le\\ dossier\\ temporaire\\ est\\ indisponible\\.$",
        "English": "The temporary folder is unavailable.",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "Marqueur signalé dans un ancien journal",
        "Pattern": "^Marqueur\\ signalé\\ dans\\ un\\ ancien\\ journal$",
        "English": "Reported indicator in an old log",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "Un dossier local absolu est nécessaire.",
        "Pattern": "^Un\\ dossier\\ local\\ absolu\\ est\\ nécessaire\\.$",
        "English": "An absolute local folder is required.",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "Modules chargés dans la session Windows",
        "Pattern": "^Modules\\ chargés\\ dans\\ la\\ session\\ Windows$",
        "English": "Loaded modules in the current Windows session",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "Liste des modules vide ou indisponible.",
        "Pattern": "^Liste\\ des\\ modules\\ vide\\ ou\\ indisponible\\.$",
        "English": "Module list empty or unavailable.",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "3  Changer vos mots de passe : conseils",
        "Pattern": "^3\\ \\ Changer\\ vos\\ mots\\ de\\ passe\\ :\\ conseils$",
        "English": "3  Change your passwords: guidance",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "5  Changer vos mots de passe : conseils",
        "Pattern": "^5\\ \\ Changer\\ vos\\ mots\\ de\\ passe\\ :\\ conseils$",
        "English": "5  Change your passwords: guidance",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "Cache NIKKE proposé à la suppression : {0}",
        "Pattern": "^Cache\\ NIKKE\\ proposé\\ à\\ la\\ suppression\\ :\\ (?<v0>.*?)$",
        "English": "NIKKE launcher cache proposed for deletion: {0}",
        "Count": 1,
        "Weight": 39
    },
    {
        "French": "Rapport sauvegardé avant suppression : {0}",
        "Pattern": "^Rapport\\ sauvegardé\\ avant\\ suppression\\ :\\ (?<v0>.*?)$",
        "English": "Report saved before deletion: {0}",
        "Count": 1,
        "Weight": 39
    },
    {
        "French": "Trace signalée dans le cache du lanceur",
        "Pattern": "^Trace\\ signalée\\ dans\\ le\\ cache\\ du\\ lanceur$",
        "English": "Reported trace in the launcher cache",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "Élément de démarrage lié à cet incident",
        "Pattern": "^Élément\\ de\\ démarrage\\ lié\\ à\\ cet\\ incident$",
        "English": "Startup entry linked to this incident",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "BLOQUER LES SITES SIGNALÉS (FACULTATIF)",
        "Pattern": "^BLOQUER\\ LES\\ SITES\\ SIGNALÉS\\ \\(FACULTATIF\\)$",
        "English": "BLOCK REPORTED WEBSITES (OPTIONAL)",
        "Count": 0,
        "Weight": 39
    },
    {
        "French": "0  Terminer et afficher le bilan final",
        "Pattern": "^0\\ \\ Terminer\\ et\\ afficher\\ le\\ bilan\\ final$",
        "English": "0  Finish and show the final report",
        "Count": 0,
        "Weight": 38
    },
    {
        "French": "Déjà absente au moment du nettoyage : $($f.Location)",
        "Pattern": "^Déjà\\ absente\\ au\\ moment\\ du\\ nettoyage\\ :\\ (?<v0>.*?)$",
        "English": "Already absent when cleanup started: {0}",
        "Count": 1,
        "Weight": 38
    },
    {
        "French": "NETTOYAGE CIBLÉ DES TRACES DOCUMENTÉES",
        "Pattern": "^NETTOYAGE\\ CIBLÉ\\ DES\\ TRACES\\ DOCUMENTÉES$",
        "English": "TARGETED CLEANUP OF DOCUMENTED INDICATORS",
        "Count": 0,
        "Weight": 38
    },
    {
        "French": "SUPPRESSION FACULTATIVE DU CACHE NIKKE",
        "Pattern": "^SUPPRESSION\\ FACULTATIVE\\ DU\\ CACHE\\ NIKKE$",
        "English": "OPTIONAL NIKKE LAUNCHER CACHE DELETION",
        "Count": 0,
        "Weight": 38
    },
    {
        "French": "Élément de démarrage suspect à retirer",
        "Pattern": "^Élément\\ de\\ démarrage\\ suspect\\ à\\ retirer$",
        "English": "Suspicious startup entry to remove",
        "Count": 0,
        "Weight": 38
    },
    {
        "French": "Contrôles terminés : {0} ; incomplets : {1}.",
        "Pattern": "^Contrôles\\ terminés\\ :\\ (?<v0>.*?)\\ ;\\ incomplets\\ :\\ (?<v1>.*?)\\.$",
        "English": "Completed checks: {0}; incomplete: {1}.",
        "Count": 2,
        "Weight": 38
    },
    {
        "French": "4  Conseils pour sécuriser les comptes",
        "Pattern": "^4\\ \\ Conseils\\ pour\\ sécuriser\\ les\\ comptes$",
        "English": "4  Account security guidance",
        "Count": 0,
        "Weight": 38
    },
    {
        "French": "Retrait de l installation non confirmé",
        "Pattern": "^Retrait\\ de\\ l\\ installation\\ non\\ confirmé$",
        "English": "Installation removal unconfirmed",
        "Count": 0,
        "Weight": 38
    },
    {
        "French": "NAVIGATEUR DU LANCEUR — ACCÈS INTERNET",
        "Pattern": "^NAVIGATEUR\\ DU\\ LANCEUR\\ —\\ ACCÈS\\ INTERNET$",
        "English": "LAUNCHER BROWSER — INTERNET ACCESS",
        "Count": 0,
        "Weight": 38
    },
    {
        "French": "Dossier $name ajouté pour cette session : $root",
        "Pattern": "^Dossier\\ (?<v0>.*?)\\ ajouté\\ pour\\ cette\\ session\\ :\\ (?<v1>.*?)$",
        "English": "{0} folder added for this session: {1}",
        "Count": 2,
        "Weight": 37
    },
    {
        "French": "Fichiers des navigateurs sélectionnés",
        "Pattern": "^Fichiers\\ des\\ navigateurs\\ sélectionnés$",
        "English": "Files in the selected browsers",
        "Count": 0,
        "Weight": 37
    },
    {
        "French": "Cache volumineux : lecture limitée : {0}",
        "Pattern": "^Cache\\ volumineux\\ :\\ lecture\\ limitée\\ :\\ (?<v0>.*?)$",
        "English": "Large cache file: limited read: {0}",
        "Count": 1,
        "Weight": 37
    },
    {
        "French": "IMPORTANT — CHANGEZ VOS MOTS DE PASSE",
        "Pattern": "^IMPORTANT\\ —\\ CHANGEZ\\ VOS\\ MOTS\\ DE\\ PASSE$",
        "English": "IMPORTANT — CHANGE YOUR PASSWORDS",
        "Count": 0,
        "Weight": 37
    },
    {
        "French": "Caches du lanceur à réinitialiser : {0}.",
        "Pattern": "^Caches\\ du\\ lanceur\\ à\\ réinitialiser\\ :\\ (?<v0>.*?)\\.$",
        "English": "Launcher caches to reset: {0}.",
        "Count": 1,
        "Weight": 37
    },
    {
        "French": "Rapport sauvegardé avant nettoyage : {0}",
        "Pattern": "^Rapport\\ sauvegardé\\ avant\\ nettoyage\\ :\\ (?<v0>.*?)$",
        "English": "Report saved before cleanup: {0}",
        "Count": 1,
        "Weight": 37
    },
    {
        "French": "Installation NIKKE encore présente : {0}",
        "Pattern": "^Installation\\ NIKKE\\ encore\\ présente\\ :\\ (?<v0>.*?)$",
        "English": "NIKKE installation still present: {0}",
        "Count": 1,
        "Weight": 37
    },
    {
        "French": "Traces dans les applications ouvertes",
        "Pattern": "^Traces\\ dans\\ les\\ applications\\ ouvertes$",
        "English": "Traces in open applications",
        "Count": 0,
        "Weight": 37
    },
    {
        "French": "Références locales aux sites signalés",
        "Pattern": "^Références\\ locales\\ aux\\ sites\\ signalés$",
        "English": "Local references to reported websites",
        "Count": 0,
        "Weight": 37
    },
    {
        "French": "DÉSINSTALLATION DE NIKKE (FACULTATIF)",
        "Pattern": "^DÉSINSTALLATION\\ DE\\ NIKKE\\ \\(FACULTATIF\\)$",
        "English": "UNINSTALL NIKKE (OPTIONAL)",
        "Count": 0,
        "Weight": 37
    },
    {
        "French": "3  Contrôle d'un navigateur au choix",
        "Pattern": "^3\\ \\ Contrôle\\ d'un\\ navigateur\\ au\\ choix$",
        "English": "3  Check a browser of your choice",
        "Count": 0,
        "Weight": 36
    },
    {
        "French": "Journal ou dossier non vérifiable : $path",
        "Pattern": "^Journal\\ ou\\ dossier\\ non\\ vérifiable\\ :\\ (?<v0>.*?)$",
        "English": "Log or folder could not be checked: {0}",
        "Count": 1,
        "Weight": 36
    },
    {
        "French": "Limite de recherche atteinte sous : $Root",
        "Pattern": "^Limite\\ de\\ recherche\\ atteinte\\ sous\\ :\\ (?<v0>.*?)$",
        "English": "Search limit reached under: {0}",
        "Count": 1,
        "Weight": 36
    },
    {
        "French": "NIKKE assistance 3.2 — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz') — Mode : $Mode / $Navigateur",
        "Pattern": "^NIKKE\\ assistance\\ 3\\.2\\ —\\ (?<v0>.*?)\\ —\\ Mode\\ :\\ (?<v1>.*?)\\ /\\ (?<v2>.*?)$",
        "English": "NIKKE assistance 3.2 — {0} — Mode: {1} / {2}",
        "Count": 3,
        "Weight": 36
    },
    {
        "French": "TRACES SUSPECTES ACTUELLES DÉTECTÉES",
        "Pattern": "^TRACES\\ SUSPECTES\\ ACTUELLES\\ DÉTECTÉES$",
        "English": "CURRENT SUSPICIOUS INDICATORS DETECTED",
        "Count": 0,
        "Weight": 36
    },
    {
        "French": "Trace historique liée à cet incident",
        "Pattern": "^Trace\\ historique\\ liée\\ à\\ cet\\ incident$",
        "English": "Historical trace linked to this incident",
        "Count": 0,
        "Weight": 36
    },
    {
        "French": "Nettoyage interrompu ou non confirmé",
        "Pattern": "^Nettoyage\\ interrompu\\ ou\\ non\\ confirmé$",
        "English": "Cleanup interrupted or unconfirmed",
        "Count": 0,
        "Weight": 36
    },
    {
        "French": "  Toujours en attente : {0} ({1} s).",
        "Pattern": "^\\ \\ Toujours\\ en\\ attente\\ :\\ (?<v0>.*?)\\ \\((?<v1>.*?)\\ s\\)\\.$",
        "English": "  Still waiting: {0} ({1} s).",
        "Count": 2,
        "Weight": 36
    },
    {
        "French": "Dossier AppData indisponible pour $($pair[0]).",
        "Pattern": "^Dossier\\ AppData\\ indisponible\\ pour\\ (?<v0>.*?)\\.$",
        "English": "AppData folder unavailable for {0}.",
        "Count": 1,
        "Weight": 35
    },
    {
        "French": "Registre HKCU/HKLM, vues 32/64 bits",
        "Pattern": "^Registre\\ HKCU/HKLM,\\ vues\\ 32/64\\ bits$",
        "English": "HKCU/HKLM registry, 32/64-bit views",
        "Count": 0,
        "Weight": 35
    },
    {
        "French": "Dossier du profil CEF indisponible.",
        "Pattern": "^Dossier\\ du\\ profil\\ CEF\\ indisponible\\.$",
        "English": "The CEF profile location is unavailable.",
        "Count": 0,
        "Weight": 35
    },
    {
        "French": "NETTOYAGE EN ATTENTE DU REDÉMARRAGE",
        "Pattern": "^NETTOYAGE\\ EN\\ ATTENTE\\ DU\\ REDÉMARRAGE$",
        "English": "CLEANUP WAITING FOR A RESTART",
        "Count": 0,
        "Weight": 35
    },
    {
        "French": "Ancienne copie non vérifiable : {0}",
        "Pattern": "^Ancienne\\ copie\\ non\\ vérifiable\\ :\\ (?<v0>.*?)$",
        "English": "Old copy could not be checked: {0}",
        "Count": 1,
        "Weight": 35
    },
    {
        "French": "Bilan de ce contrôle enregistré : $script:ReportPath",
        "Pattern": "^Bilan\\ de\\ ce\\ contrôle\\ enregistré\\ :\\ (?<v0>.*?)$",
        "English": "Report for this check saved: {0}",
        "Count": 1,
        "Weight": 34
    },
    {
        "French": "D  Lire les détails de ce résultat",
        "Pattern": "^D\\ \\ Lire\\ les\\ détails\\ de\\ ce\\ résultat$",
        "English": "D  Read details of this result",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "JEU — TRACES D'UNE ACTIVITÉ PASSÉE",
        "Pattern": "^JEU\\ —\\ TRACES\\ D'UNE\\ ACTIVITÉ\\ PASSÉE$",
        "English": "GAME — INDICATORS OF PAST ACTIVITY",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "Répondre O pour Oui ou N pour Non.",
        "Pattern": "^Répondre\\ O\\ pour\\ Oui\\ ou\\ N\\ pour\\ Non\\.$",
        "English": "Answer Y for Yes or N for No.",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "Trace antérieure non vérifiable : $($f.Location)",
        "Pattern": "^Trace\\ antérieure\\ non\\ vérifiable\\ :\\ (?<v0>.*?)$",
        "English": "Earlier indicator could not be rechecked: {0}",
        "Count": 1,
        "Weight": 34
    },
    {
        "French": "Déplacement du cache non confirmé.",
        "Pattern": "^Déplacement\\ du\\ cache\\ non\\ confirmé\\.$",
        "English": "Cache move not confirmed.",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "Programmes en cours (DLL chargées)",
        "Pattern": "^Programmes\\ en\\ cours\\ \\(DLL\\ chargées\\)$",
        "English": "Running programs (loaded DLLs)",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "Cache non parcouru complètement : {0}",
        "Pattern": "^Cache\\ non\\ parcouru\\ complètement\\ :\\ (?<v0>.*?)$",
        "English": "Cache not fully checked: {0}",
        "Count": 1,
        "Weight": 34
    },
    {
        "French": "La sauvegarde du rapport a échoué.",
        "Pattern": "^La\\ sauvegarde\\ du\\ rapport\\ a\\ échoué\\.$",
        "English": "Saving the report failed.",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "NIKKETRACE — VERSION 3.2 — WINDOWS",
        "Pattern": "^NIKKETRACE\\ —\\ VERSION\\ 3\\.2\\ —\\ WINDOWS$",
        "English": "NIKKETRACE — VERSION 3.2 — WINDOWS",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "Fichier suspect lié à cet incident",
        "Pattern": "^Fichier\\ suspect\\ lié\\ à\\ cet\\ incident$",
        "English": "Suspicious file linked to this incident",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "1  Vérifier un navigateur au choix",
        "Pattern": "^1\\ \\ Vérifier\\ un\\ navigateur\\ au\\ choix$",
        "English": "1  Check a browser of your choice",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "Choisissez une lettre de la liste.",
        "Pattern": "^Choisissez\\ une\\ lettre\\ de\\ la\\ liste\\.$",
        "English": "Choose a letter from the list.",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "Suppression du cache non confirmée",
        "Pattern": "^Suppression\\ du\\ cache\\ non\\ confirmée$",
        "English": "Cache deletion unconfirmed",
        "Count": 0,
        "Weight": 34
    },
    {
        "French": "Contrôles effectués : {0} sur {1}.",
        "Pattern": "^Contrôles\\ effectués\\ :\\ (?<v0>.*?)\\ sur\\ (?<v1>.*?)\\.$",
        "English": "Completed checks: {0} of {1}.",
        "Count": 2,
        "Weight": 34
    },
    {
        "French": "Choisissez un numéro de la liste.",
        "Pattern": "^Choisissez\\ un\\ numéro\\ de\\ la\\ liste\\.$",
        "English": "Choose a number from the menu.",
        "Count": 0,
        "Weight": 33
    },
    {
        "French": "Lecture du profil $Name interrompue : $Root",
        "Pattern": "^Lecture\\ du\\ profil\\ (?<v0>.*?)\\ interrompue\\ :\\ (?<v1>.*?)$",
        "English": "Reading the {0} profile was interrupted: {1}",
        "Count": 2,
        "Weight": 33
    },
    {
        "French": "Windows (registre et temporaires)",
        "Pattern": "^Windows\\ \\(registre\\ et\\ temporaires\\)$",
        "English": "Windows (registry and temporary files)",
        "Count": 0,
        "Weight": 33
    },
    {
        "French": "Cache hors du périmètre autorisé.",
        "Pattern": "^Cache\\ hors\\ du\\ périmètre\\ autorisé\\.$",
        "English": "Cache outside the permitted scope.",
        "Count": 0,
        "Weight": 33
    },
    {
        "French": "Domaine déjà bloqué dans hosts : {0}",
        "Pattern": "^Domaine\\ déjà\\ bloqué\\ dans\\ hosts\\ :\\ (?<v0>.*?)$",
        "English": "Domain already blocked in hosts: {0}",
        "Count": 1,
        "Weight": 33
    },
    {
        "French": "Ajouter ce blocage des domaines ?",
        "Pattern": "^Ajouter\\ ce\\ blocage\\ des\\ domaines\\ \\?$",
        "English": "Add this domain block?",
        "Count": 0,
        "Weight": 33
    },
    {
        "French": "Cache non lisible ou incomplet : {0}",
        "Pattern": "^Cache\\ non\\ lisible\\ ou\\ incomplet\\ :\\ (?<v0>.*?)$",
        "English": "Cache unreadable or incomplete: {0}",
        "Count": 1,
        "Weight": 33
    },
    {
        "French": "NETTOYAGE PARTIEL OU NON CONFIRMÉ",
        "Pattern": "^NETTOYAGE\\ PARTIEL\\ OU\\ NON\\ CONFIRMÉ$",
        "English": "CLEANUP PARTIAL OR UNCONFIRMED",
        "Count": 0,
        "Weight": 33
    },
    {
        "French": "Fichier supprimé sans copie : {0}",
        "Pattern": "^Fichier\\ supprimé\\ sans\\ copie\\ :\\ (?<v0>.*?)$",
        "English": "File deleted without a copy: {0}",
        "Count": 1,
        "Weight": 33
    },
    {
        "French": "Retirer ces blocages NikkeTrace ?",
        "Pattern": "^Retirer\\ ces\\ blocages\\ NikkeTrace\\ \\?$",
        "English": "Remove these NikkeTrace blocks?",
        "Count": 0,
        "Weight": 33
    },
    {
        "French": "Fichier suspect utilisé par Steam",
        "Pattern": "^Fichier\\ suspect\\ utilisé\\ par\\ Steam$",
        "English": "Suspicious file used by Steam",
        "Count": 0,
        "Weight": 33
    },
    {
        "French": "  $Label : aucun marqueur connu trouvé",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ :\\ aucun\\ marqueur\\ connu\\ trouvé$",
        "English": "  {0}: no known indicator found",
        "Count": 1,
        "Weight": 32
    },
    {
        "French": "Choisissez un navigateur précis.",
        "Pattern": "^Choisissez\\ un\\ navigateur\\ précis\\.$",
        "English": "Choose a specific browser.",
        "Count": 0,
        "Weight": 32
    },
    {
        "French": "NON TRAITÉ OU NON CONFIRMÉ : $($f.Location) — $($_.Exception.Message)",
        "Pattern": "^NON\\ TRAITÉ\\ OU\\ NON\\ CONFIRMÉ\\ :\\ (?<v0>.*?)\\ —\\ (?<v1>.*?)$",
        "English": "NOT HANDLED OR NOT CONFIRMED: {0} — {1}",
        "Count": 2,
        "Weight": 32
    },
    {
        "French": "Retrait du registre non confirmé",
        "Pattern": "^Retrait\\ du\\ registre\\ non\\ confirmé$",
        "English": "Startup entry removal unconfirmed",
        "Count": 0,
        "Weight": 32
    },
    {
        "French": "{0} [O/N/R = rapport, Entrée = Non]",
        "Pattern": "^(?<v0>.*?)\\ \\[O/N/R\\ =\\ rapport,\\ Entrée\\ =\\ Non\\]$",
        "English": "{0} [Y/N/R = report, Enter = No]",
        "Count": 1,
        "Weight": 32
    },
    {
        "French": "Blocages des sites déjà présents",
        "Pattern": "^Blocages\\ des\\ sites\\ déjà\\ présents$",
        "English": "Existing website blocks",
        "Count": 0,
        "Weight": 32
    },
    {
        "French": "Fichier suspect utilisé par Alt1",
        "Pattern": "^Fichier\\ suspect\\ utilisé\\ par\\ Alt1$",
        "English": "Suspicious file used by Alt1",
        "Count": 0,
        "Weight": 32
    },
    {
        "French": "2  Relancer le même contrôle : $scope",
        "Pattern": "^2\\ \\ Relancer\\ le\\ même\\ contrôle\\ :\\ (?<v0>.*?)$",
        "English": "2  Repeat this check: {0}",
        "Count": 1,
        "Weight": 31
    },
    {
        "French": "DÉTAILS DU CONTRÔLE SÉLECTIONNÉ",
        "Pattern": "^DÉTAILS\\ DU\\ CONTRÔLE\\ SÉLECTIONNÉ$",
        "English": "DETAILS FOR THE SELECTED CHECK",
        "Count": 0,
        "Weight": 31
    },
    {
        "French": "Profil redirigé non parcouru : $Root",
        "Pattern": "^Profil\\ redirigé\\ non\\ parcouru\\ :\\ (?<v0>.*?)$",
        "English": "Redirected profile not scanned: {0}",
        "Count": 1,
        "Weight": 31
    },
    {
        "French": "Votre choix [Entrée = Terminer]",
        "Pattern": "^Votre\\ choix\\ \\[Entrée\\ =\\ Terminer\\]$",
        "English": "Your choice [Enter = Finish]",
        "Count": 0,
        "Weight": 31
    },
    {
        "French": "Empreinte DLL non vérifiable : {0}",
        "Pattern": "^Empreinte\\ DLL\\ non\\ vérifiable\\ :\\ (?<v0>.*?)$",
        "English": "DLL fingerprint could not be checked: {0}",
        "Count": 1,
        "Weight": 31
    },
    {
        "French": "Cache partiellement conservé : {0}",
        "Pattern": "^Cache\\ partiellement\\ conservé\\ :\\ (?<v0>.*?)$",
        "English": "Cache partially preserved: {0}",
        "Count": 1,
        "Weight": 31
    },
    {
        "French": "Retrait du fichier non confirmé",
        "Pattern": "^Retrait\\ du\\ fichier\\ non\\ confirmé$",
        "English": "File removal unconfirmed",
        "Count": 0,
        "Weight": 31
    },
    {
        "French": "La vérification est incomplète.",
        "Pattern": "^La\\ vérification\\ est\\ incomplète\\.$",
        "English": "The check is incomplete.",
        "Count": 0,
        "Weight": 31
    },
    {
        "French": "Références de démarrage connues",
        "Pattern": "^Références\\ de\\ démarrage\\ connues$",
        "English": "Known startup references",
        "Count": 0,
        "Weight": 31
    },
    {
        "French": "Durée du contrôle : {0} — {1} s",
        "Pattern": "^Durée\\ du\\ contrôle\\ :\\ (?<v0>.*?)\\ —\\ (?<v1>.*?)\\ s$",
        "English": "Check duration: {0} — {1} s",
        "Count": 2,
        "Weight": 31
    },
    {
        "French": "Fichier supprimé définitivement",
        "Pattern": "^Fichier\\ supprimé\\ définitivement$",
        "English": "File permanently deleted",
        "Count": 0,
        "Weight": 31
    },
    {
        "French": " NikkeTrace — FR — VERSION 3.2",
        "Pattern": "^\\ NikkeTrace\\ —\\ FR\\ —\\ VERSION\\ 3\\.2$",
        "English": " NikkeTrace — EN — VERSION 3.2",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Appuyez sur Entrée pour fermer",
        "Pattern": "^Appuyez\\ sur\\ Entrée\\ pour\\ fermer$",
        "English": "Press Enter to close",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Effectuer ce nettoyage ciblé ?",
        "Pattern": "^Effectuer\\ ce\\ nettoyage\\ ciblé\\ \\?$",
        "English": "Perform this targeted cleanup?",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Fichiers NIKKE encore présents",
        "Pattern": "^Fichiers\\ NIKKE\\ encore\\ présents$",
        "English": "NIKKE files still present",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Chemin du module indisponible.",
        "Pattern": "^Chemin\\ du\\ module\\ indisponible\\.$",
        "English": "Module path unavailable.",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Cache partiellement vérifié : {0}",
        "Pattern": "^Cache\\ partiellement\\ vérifié\\ :\\ (?<v0>.*?)$",
        "English": "Cache partially checked: {0}",
        "Count": 1,
        "Weight": 30
    },
    {
        "French": "Effectuer ce nettoyage guidé ?",
        "Pattern": "^Effectuer\\ ce\\ nettoyage\\ guidé\\ \\?$",
        "English": "Perform this guided cleanup?",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Votre choix [Entrée = Quitter]",
        "Pattern": "^Votre\\ choix\\ \\[Entrée\\ =\\ Quitter\\]$",
        "English": "Your choice [Enter = Quit]",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "NIKKETRACE 3.2 — RAPPORT PRIVÉ",
        "Pattern": "^NIKKETRACE\\ 3\\.2\\ —\\ RAPPORT\\ PRIVÉ$",
        "English": "NIKKETRACE 3.2 — PRIVATE REPORT",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Revérification après nettoyage",
        "Pattern": "^Revérification\\ après\\ nettoyage$",
        "English": "Post-cleanup recheck",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Données temporaires du lanceur",
        "Pattern": "^Données\\ temporaires\\ du\\ lanceur$",
        "English": "Temporary launcher data",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Bloquer ces sites maintenant ?",
        "Pattern": "^Bloquer\\ ces\\ sites\\ maintenant\\ \\?$",
        "English": "Block these websites now?",
        "Count": 0,
        "Weight": 30
    },
    {
        "French": "Marqueur de cache : {0} — {1}",
        "Pattern": "^Marqueur\\ de\\ cache\\ :\\ (?<v0>.*?)\\ —\\ (?<v1>.*?)$",
        "English": "Cache marker: {0} — {1}",
        "Count": 2,
        "Weight": 29
    },
    {
        "French": "NikkeTrace — FR — VERSION 3.2",
        "Pattern": "^NikkeTrace\\ —\\ FR\\ —\\ VERSION\\ 3\\.2$",
        "English": "NikkeTrace — EN — VERSION 3.2",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "$label : TRACES SUSPECTES DÉTECTÉES",
        "Pattern": "^(?<v0>.*?)\\ :\\ TRACES\\ SUSPECTES\\ DÉTECTÉES$",
        "English": "{0}: SUSPICIOUS INDICATORS DETECTED",
        "Count": 1,
        "Weight": 29
    },
    {
        "French": "Chemin indique introuvable : $Path",
        "Pattern": "^Chemin\\ indique\\ introuvable\\ :\\ (?<v0>.*?)$",
        "English": "Specified path not found: {0}",
        "Count": 1,
        "Weight": 29
    },
    {
        "French": "Chemin lie/jonction ignore : $Path",
        "Pattern": "^Chemin\\ lie/jonction\\ ignore\\ :\\ (?<v0>.*?)$",
        "English": "Linked path / junction skipped: {0}",
        "Count": 1,
        "Weight": 29
    },
    {
        "French": "Fichiers temporaires signalés",
        "Pattern": "^Fichiers\\ temporaires\\ signalés$",
        "English": "Reported temporary files",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "PC APRÈS SUPPRESSION DE NIKKE",
        "Pattern": "^PC\\ APRÈS\\ SUPPRESSION\\ DE\\ NIKKE$",
        "English": "PC AFTER NIKKE REMOVAL",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "Cache NIKKE : état de l agent",
        "Pattern": "^Cache\\ NIKKE\\ :\\ état\\ de\\ l\\ agent$",
        "English": "NIKKE cache: agent state",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "Preuve de cache non reconnue.",
        "Pattern": "^Preuve\\ de\\ cache\\ non\\ reconnue\\.$",
        "English": "Unrecognised cache evidence.",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "Dossier Windows indisponible.",
        "Pattern": "^Dossier\\ Windows\\ indisponible\\.$",
        "English": "Windows folder unavailable.",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "Échec de l opération hosts : {0}",
        "Pattern": "^Échec\\ de\\ l\\ opération\\ hosts\\ :\\ (?<v0>.*?)$",
        "English": "Hosts operation failed: {0}",
        "Count": 1,
        "Weight": 29
    },
    {
        "French": "Cache après suppression : {0} — {1}",
        "Pattern": "^Cache\\ après\\ suppression\\ :\\ (?<v0>.*?)\\ —\\ (?<v1>.*?)$",
        "English": "Cache after deletion: {0} — {1}",
        "Count": 2,
        "Weight": 29
    },
    {
        "French": "5  Bloquer les sites signalés",
        "Pattern": "^5\\ \\ Bloquer\\ les\\ sites\\ signalés$",
        "English": "5  Block reported websites",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "4  Bloquer les sites signalés",
        "Pattern": "^4\\ \\ Bloquer\\ les\\ sites\\ signalés$",
        "English": "4  Block reported websites",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "[C] Voir le nettoyage proposé",
        "Pattern": "^\\[C\\]\\ Voir\\ le\\ nettoyage\\ proposé$",
        "English": "[C] View proposed cleanup",
        "Count": 0,
        "Weight": 29
    },
    {
        "French": "    Emplacement recherché : $path",
        "Pattern": "^\\ \\ \\ \\ Emplacement\\ recherché\\ :\\ (?<v0>.*?)$",
        "English": "    Location checked: {0}",
        "Count": 1,
        "Weight": 28
    },
    {
        "French": "Cet outil nécessite Windows.",
        "Pattern": "^Cet\\ outil\\ nécessite\\ Windows\\.$",
        "English": "This tool requires Windows.",
        "Count": 0,
        "Weight": 28
    },
    {
        "French": "Revérification non confirmée",
        "Pattern": "^Revérification\\ non\\ confirmée$",
        "English": "Recheck unconfirmed",
        "Count": 0,
        "Weight": 28
    },
    {
        "French": "Aucune trace connue trouvée.",
        "Pattern": "^Aucune\\ trace\\ connue\\ trouvée\\.$",
        "English": "No known traces found.",
        "Count": 0,
        "Weight": 28
    },
    {
        "French": "S  Conseils pour vos comptes",
        "Pattern": "^S\\ \\ Conseils\\ pour\\ vos\\ comptes$",
        "English": "S  Account security advice",
        "Count": 0,
        "Weight": 28
    },
    {
        "French": "Bloquer cet accès Internet ?",
        "Pattern": "^Bloquer\\ cet\\ accès\\ Internet\\ \\?$",
        "English": "Block this Internet access?",
        "Count": 0,
        "Weight": 28
    },
    {
        "French": "PC après suppression du jeu",
        "Pattern": "^PC\\ après\\ suppression\\ du\\ jeu$",
        "English": "PC after game removal",
        "Count": 0,
        "Weight": 27
    },
    {
        "French": "Votre choix [Entrée = Tous]",
        "Pattern": "^Votre\\ choix\\ \\[Entrée\\ =\\ Tous\\]$",
        "English": "Your choice [Enter = All]",
        "Count": 0,
        "Weight": 27
    },
    {
        "French": "Empreinte SHA-256 DLL : {0} — {1}",
        "Pattern": "^Empreinte\\ SHA\\-256\\ DLL\\ :\\ (?<v0>.*?)\\ —\\ (?<v1>.*?)$",
        "English": "DLL SHA-256 fingerprint: {0} — {1}",
        "Count": 2,
        "Weight": 27
    },
    {
        "French": "DÉTAILS DES TRACES TROUVÉES",
        "Pattern": "^DÉTAILS\\ DES\\ TRACES\\ TROUVÉES$",
        "English": "DETAILS OF TRACES FOUND",
        "Count": 0,
        "Weight": 27
    },
    {
        "French": "Échec de relecture hosts : {0}",
        "Pattern": "^Échec\\ de\\ relecture\\ hosts\\ :\\ (?<v0>.*?)$",
        "English": "Failed to read hosts back: {0}",
        "Count": 1,
        "Weight": 27
    },
    {
        "French": "AUCUNE TRACE CONNUE TROUVÉE",
        "Pattern": "^AUCUNE\\ TRACE\\ CONNUE\\ TROUVÉE$",
        "English": "NO KNOWN TRACES FOUND",
        "Count": 0,
        "Weight": 27
    },
    {
        "French": "RÉSULTAT DE LA VÉRIFICATION",
        "Pattern": "^RÉSULTAT\\ DE\\ LA\\ VÉRIFICATION$",
        "English": "CHECK RESULT",
        "Count": 0,
        "Weight": 27
    },
    {
        "French": "  Contrôle terminé ({0} s).",
        "Pattern": "^\\ \\ Contrôle\\ terminé\\ \\((?<v0>.*?)\\ s\\)\\.$",
        "English": "  Check finished ({0} s).",
        "Count": 1,
        "Weight": 27
    },
    {
        "French": "0 Retour au menu principal",
        "Pattern": "^0\\ Retour\\ au\\ menu\\ principal$",
        "English": "0  Back to the main menu",
        "Count": 0,
        "Weight": 26
    },
    {
        "French": "Dossier qui sera retiré : $root",
        "Pattern": "^Dossier\\ qui\\ sera\\ retiré\\ :\\ (?<v0>.*?)$",
        "English": "Folder to be removed: {0}",
        "Count": 1,
        "Weight": 26
    },
    {
        "French": "Journaux NIKKE disponibles",
        "Pattern": "^Journaux\\ NIKKE\\ disponibles$",
        "English": "Available NIKKE logs",
        "Count": 0,
        "Weight": 26
    },
    {
        "French": "Réponse TCP inexploitable.",
        "Pattern": "^Réponse\\ TCP\\ inexploitable\\.$",
        "English": "Unusable TCP response.",
        "Count": 0,
        "Weight": 26
    },
    {
        "French": "Réponse DNS inexploitable.",
        "Pattern": "^Réponse\\ DNS\\ inexploitable\\.$",
        "English": "Unusable DNS response.",
        "Count": 0,
        "Weight": 26
    },
    {
        "French": "Ligne hosts inexploitable.",
        "Pattern": "^Ligne\\ hosts\\ inexploitable\\.$",
        "English": "Unusable hosts line.",
        "Count": 0,
        "Weight": 26
    },
    {
        "French": "TRACES ACTUELLES À TRAITER",
        "Pattern": "^TRACES\\ ACTUELLES\\ À\\ TRAITER$",
        "English": "CURRENT TRACES TO ADDRESS",
        "Count": 0,
        "Weight": 26
    },
    {
        "French": "  $Label : $($Rows.Count) trace(s) à examiner",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ :\\ (?<v1>.*?)\\ trace\\(s\\)\\ à\\ examiner$",
        "English": "  {0}: {1} indicator(s) to investigate",
        "Count": 2,
        "Weight": 25
    },
    {
        "French": "  Fichier déplacé vers : $destination",
        "Pattern": "^\\ \\ Fichier\\ déplacé\\ vers\\ :\\ (?<v0>.*?)$",
        "English": "  File moved to: {0}",
        "Count": 1,
        "Weight": 25
    },
    {
        "French": "Bilan privé enregistré : $script:ReportPath",
        "Pattern": "^Bilan\\ privé\\ enregistré\\ :\\ (?<v0>.*?)$",
        "English": "Private report saved: {0}",
        "Count": 1,
        "Weight": 25
    },
    {
        "French": "Lecteur non accessible : $Path",
        "Pattern": "^Lecteur\\ non\\ accessible\\ :\\ (?<v0>.*?)$",
        "English": "Drive inaccessible: {0}",
        "Count": 1,
        "Weight": 25
    },
    {
        "French": "Lien temporaire ignoré : $($file.FullName)",
        "Pattern": "^Lien\\ temporaire\\ ignoré\\ :\\ (?<v0>.*?)$",
        "English": "Temporary link skipped: {0}",
        "Count": 1,
        "Weight": 25
    },
    {
        "French": "Échec de lecture hosts : {0}",
        "Pattern": "^Échec\\ de\\ lecture\\ hosts\\ :\\ (?<v0>.*?)$",
        "English": "Failed to read hosts: {0}",
        "Count": 1,
        "Weight": 25
    },
    {
        "French": "VÉRIFICATION NON RÉALISÉE",
        "Pattern": "^VÉRIFICATION\\ NON\\ RÉALISÉE$",
        "English": "CHECK NOT COMPLETED",
        "Count": 0,
        "Weight": 25
    },
    {
        "French": "Lecteur reseau ignore : $Path",
        "Pattern": "^Lecteur\\ reseau\\ ignore\\ :\\ (?<v0>.*?)$",
        "English": "Network drive skipped: {0}",
        "Count": 1,
        "Weight": 24
    },
    {
        "French": "Non demandé dans ce mode",
        "Pattern": "^Non\\ demandé\\ dans\\ ce\\ mode$",
        "English": "Not requested in this mode",
        "Count": 0,
        "Weight": 24
    },
    {
        "French": "Rapport privé complet : $script:ReportPath",
        "Pattern": "^Rapport\\ privé\\ complet\\ :\\ (?<v0>.*?)$",
        "English": "Full private report: {0}",
        "Count": 1,
        "Weight": 24
    },
    {
        "French": "Votre choix [Entrée = 1]",
        "Pattern": "^Votre\\ choix\\ \\[Entrée\\ =\\ 1\\]$",
        "English": "Your choice [Enter = 1]",
        "Count": 0,
        "Weight": 24
    },
    {
        "French": "Connexions TCP actuelles",
        "Pattern": "^Connexions\\ TCP\\ actuelles$",
        "English": "Current TCP connections",
        "Count": 0,
        "Weight": 24
    },
    {
        "French": "Processus inexploitable.",
        "Pattern": "^Processus\\ inexploitable\\.$",
        "English": "Unusable process data.",
        "Count": 0,
        "Weight": 24
    },
    {
        "French": "Cache NIKKE introuvable.",
        "Pattern": "^Cache\\ NIKKE\\ introuvable\\.$",
        "English": "NIKKE launcher cache not found.",
        "Count": 0,
        "Weight": 24
    },
    {
        "French": "H  Comprendre NikkeTrace",
        "Pattern": "^H\\ \\ Comprendre\\ NikkeTrace$",
        "English": "H  About NikkeTrace",
        "Count": 0,
        "Weight": 24
    },
    {
        "French": "Dossiers des navigateurs",
        "Pattern": "^Dossiers\\ des\\ navigateurs$",
        "English": "Browser folders",
        "Count": 0,
        "Weight": 24
    },
    {
        "French": "Contrôle sélectionné : $scope",
        "Pattern": "^Contrôle\\ sélectionné\\ :\\ (?<v0>.*?)$",
        "English": "Selected check: {0}",
        "Count": 1,
        "Weight": 23
    },
    {
        "French": "Jonction/lien ignore : $($child.FullName)",
        "Pattern": "^Jonction/lien\\ ignore\\ :\\ (?<v0>.*?)$",
        "English": "Junction / link skipped: {0}",
        "Count": 1,
        "Weight": 23
    },
    {
        "French": "RETRAIT NON CONFIRMÉ : $($_.Exception.Message)",
        "Pattern": "^RETRAIT\\ NON\\ CONFIRMÉ\\ :\\ (?<v0>.*?)$",
        "English": "REMOVAL NOT CONFIRMED: {0}",
        "Count": 1,
        "Weight": 23
    },
    {
        "French": "État TCP inexploitable.",
        "Pattern": "^État\\ TCP\\ inexploitable\\.$",
        "English": "Unusable TCP state.",
        "Count": 0,
        "Weight": 23
    },
    {
        "French": "Début du contrôle : {0}",
        "Pattern": "^Début\\ du\\ contrôle\\ :\\ (?<v0>.*?)$",
        "English": "Starting check: {0}",
        "Count": 1,
        "Weight": 23
    },
    {
        "French": "  Sauvegarde privée : $backup",
        "Pattern": "^\\ \\ Sauvegarde\\ privée\\ :\\ (?<v0>.*?)$",
        "English": "  Private backup: {0}",
        "Count": 1,
        "Weight": 22
    },
    {
        "French": "$label : ÉLÉMENTS À EXAMINER",
        "Pattern": "^(?<v0>.*?)\\ :\\ ÉLÉMENTS\\ À\\ EXAMINER$",
        "English": "{0}: ITEMS TO INVESTIGATE",
        "Count": 1,
        "Weight": 22
    },
    {
        "French": "[TRACE A EXAMINER] $Kind : $Location",
        "Pattern": "^\\[TRACE\\ A\\ EXAMINER\\]\\ (?<v0>.*?)\\ :\\ (?<v1>.*?)$",
        "English": "[INDICATOR TO INVESTIGATE] {0}: {1}",
        "Count": 2,
        "Weight": 22
    },
    {
        "French": "ACTION NON TERMINÉE : $($_.Exception.Message)",
        "Pattern": "^ACTION\\ NON\\ TERMINÉE\\ :\\ (?<v0>.*?)$",
        "English": "ACTION NOT COMPLETED: {0}",
        "Count": 1,
        "Weight": 22
    },
    {
        "French": "Nettoyage incomplet : $($_.Exception.Message)",
        "Pattern": "^Nettoyage\\ incomplet\\ :\\ (?<v0>.*?)$",
        "English": "Cleanup incomplete: {0}",
        "Count": 1,
        "Weight": 22
    },
    {
        "French": "Navigateurs ouverts : {0}",
        "Pattern": "^Navigateurs\\ ouverts\\ :\\ (?<v0>.*?)$",
        "English": "Open browsers: {0}",
        "Count": 1,
        "Weight": 22
    },
    {
        "French": "Domaines en conflit : {0}",
        "Pattern": "^Domaines\\ en\\ conflit\\ :\\ (?<v0>.*?)$",
        "English": "Conflicting domains: {0}",
        "Count": 1,
        "Weight": 22
    },
    {
        "French": "Actuelle ou à examiner",
        "Pattern": "^Actuelle\\ ou\\ à\\ examiner$",
        "English": "Current or needing review",
        "Count": 0,
        "Weight": 22
    },
    {
        "French": "Anciens journaux NIKKE",
        "Pattern": "^Anciens\\ journaux\\ NIKKE$",
        "English": "Old NIKKE logs",
        "Count": 0,
        "Weight": 22
    },
    {
        "French": "    Dossier trouvé : $path",
        "Pattern": "^\\ \\ \\ \\ Dossier\\ trouvé\\ :\\ (?<v0>.*?)$",
        "English": "    Folder found: {0}",
        "Count": 1,
        "Weight": 21
    },
    {
        "French": "$label : CONTRÔLE INCOMPLET",
        "Pattern": "^(?<v0>.*?)\\ :\\ CONTRÔLE\\ INCOMPLET$",
        "English": "{0}: INCOMPLETE CHECK",
        "Count": 1,
        "Weight": 21
    },
    {
        "French": "4  Comprendre l outil",
        "Pattern": "^4\\ \\ Comprendre\\ l\\ outil$",
        "English": "4  About this tool",
        "Count": 0,
        "Weight": 21
    },
    {
        "French": "Dossier non ajouté : $($_.Exception.Message)",
        "Pattern": "^Dossier\\ non\\ ajouté\\ :\\ (?<v0>.*?)$",
        "English": "Folder not added: {0}",
        "Count": 1,
        "Weight": 21
    },
    {
        "French": "Cache non parcouru : {0}",
        "Pattern": "^Cache\\ non\\ parcouru\\ :\\ (?<v0>.*?)$",
        "English": "Cache folder not scanned: {0}",
        "Count": 1,
        "Weight": 21
    },
    {
        "French": "Fichier hosts Windows",
        "Pattern": "^Fichier\\ hosts\\ Windows$",
        "English": "Windows hosts file",
        "Count": 0,
        "Weight": 21
    },
    {
        "French": "Module inexploitable.",
        "Pattern": "^Module\\ inexploitable\\.$",
        "English": "Unusable module data.",
        "Count": 0,
        "Weight": 21
    },
    {
        "French": "Contrôle incomplet : {0}",
        "Pattern": "^Contrôle\\ incomplet\\ :\\ (?<v0>.*?)$",
        "English": "Incomplete check: {0}",
        "Count": 1,
        "Weight": 21
    },
    {
        "French": "--- Contrôle du $(Get-Date -Format 'HH:mm:ss') ---",
        "Pattern": "^\\-\\-\\-\\ Contrôle\\ du\\ (?<v0>.*?)\\ \\-\\-\\-$",
        "English": "--- Check at {0} ---",
        "Count": 1,
        "Weight": 20
    },
    {
        "French": "$Question [O/N, Entrée = Non]",
        "Pattern": "^(?<v0>.*?)\\ \\[O/N,\\ Entrée\\ =\\ Non\\]$",
        "English": "{0} [Y/N, Enter = No]",
        "Count": 1,
        "Weight": 20
    },
    {
        "French": "DOSSIER DU PROFIL — $name",
        "Pattern": "^DOSSIER\\ DU\\ PROFIL\\ —\\ (?<v0>.*?)$",
        "English": "PROFILE FOLDER — {0}",
        "Count": 1,
        "Weight": 20
    },
    {
        "French": "Journal illisible : $Path",
        "Pattern": "^Journal\\ illisible\\ :\\ (?<v0>.*?)$",
        "English": "Unreadable log: {0}",
        "Count": 1,
        "Weight": 20
    },
    {
        "French": "MODIFIÉ — à examiner",
        "Pattern": "^MODIFIÉ\\ —\\ à\\ examiner$",
        "English": "CHANGED — investigate",
        "Count": 0,
        "Weight": 20
    },
    {
        "French": "NOUVEAU — à examiner",
        "Pattern": "^NOUVEAU\\ —\\ à\\ examiner$",
        "English": "NEW — investigate",
        "Count": 0,
        "Weight": 20
    },
    {
        "French": "",
        "Pattern": "^\\s+Où : (?<v0>.*?)$",
        "English": "      Where: {0}",
        "Count": 1,
        "Weight": 20
    },
    {
        "French": "Cache non lisible : {0}",
        "Pattern": "^Cache\\ non\\ lisible\\ :\\ (?<v0>.*?)$",
        "English": "Unreadable cache file: {0}",
        "Count": 1,
        "Weight": 20
    },
    {
        "French": "Référence à examiner",
        "Pattern": "^Référence\\ à\\ examiner$",
        "English": "Reference to investigate",
        "Count": 0,
        "Weight": 20
    },
    {
        "French": "Retrait non confirmé",
        "Pattern": "^Retrait\\ non\\ confirmé$",
        "English": "Removal not confirmed",
        "Count": 0,
        "Weight": 20
    },
    {
        "French": "ACTIONS RECOMMANDÉES",
        "Pattern": "^ACTIONS\\ RECOMMANDÉES$",
        "English": "RECOMMENDED ACTIONS",
        "Count": 0,
        "Weight": 20
    },
    {
        "French": "Cache NIKKE supprimé",
        "Pattern": "^Cache\\ NIKKE\\ supprimé$",
        "English": "NIKKE launcher cache deleted",
        "Count": 0,
        "Weight": 20
    },
    {
        "French": "Acces impossible : $Path",
        "Pattern": "^Acces\\ impossible\\ :\\ (?<v0>.*?)$",
        "English": "Access unavailable: {0}",
        "Count": 1,
        "Weight": 19
    },
    {
        "French": "BILAN AVANT / APRÈS",
        "Pattern": "^BILAN\\ AVANT\\ /\\ APRÈS$",
        "English": "BEFORE / AFTER REPORT",
        "Count": 0,
        "Weight": 19
    },
    {
        "French": "Contrôle terminé — $finished",
        "Pattern": "^Contrôle\\ terminé\\ —\\ (?<v0>.*?)$",
        "English": "Check finished — {0}",
        "Count": 1,
        "Weight": 19
    },
    {
        "French": "Marqueur « $($Finding.Target.Marker) » dans $([IO.Path]::GetFileName($Finding.Target.Path))",
        "Pattern": "^Marqueur\\ «\\ (?<v0>.*?)\\ »\\ dans\\ (?<v1>.*?)$",
        "English": "Indicator \"{0}\" in {1}",
        "Count": 2,
        "Weight": 19
    },
    {
        "French": "Programmes en cours",
        "Pattern": "^Programmes\\ en\\ cours$",
        "English": "Running programs",
        "Count": 0,
        "Weight": 19
    },
    {
        "French": "NIKKE déjà supprimé",
        "Pattern": "^NIKKE\\ déjà\\ supprimé$",
        "English": "NIKKE already removed",
        "Count": 0,
        "Weight": 19
    },
    {
        "French": "Fichier concerné : {0}",
        "Pattern": "^Fichier\\ concerné\\ :\\ (?<v0>.*?)$",
        "English": "Affected file: {0}",
        "Count": 1,
        "Weight": 19
    },
    {
        "French": "A  Options avancées",
        "Pattern": "^A\\ \\ Options\\ avancées$",
        "English": "A  Advanced options",
        "Count": 0,
        "Weight": 19
    },
    {
        "French": "ÉLÉMENTS À EXAMINER",
        "Pattern": "^ÉLÉMENTS\\ À\\ EXAMINER$",
        "English": "ITEMS NEEDING REVIEW",
        "Count": 0,
        "Weight": 19
    },
    {
        "French": "    Emplacement : $($row.Finding.Location)",
        "Pattern": "^\\ \\ \\ \\ Emplacement\\ :\\ (?<v0>.*?)$",
        "English": "    Location: {0}",
        "Count": 1,
        "Weight": 18
    },
    {
        "French": "$hive / $view / $sub / valeur '$name'",
        "Pattern": "^(?<v0>.*?)\\ /\\ (?<v1>.*?)\\ /\\ (?<v2>.*?)\\ /\\ valeur\\ '(?<v3>.*?)'$",
        "English": "{0} / {1} / {2} / value '{3}'",
        "Count": 4,
        "Weight": 18
    },
    {
        "French": "Copie conservée : $($result.Destination)",
        "Pattern": "^Copie\\ conservée\\ :\\ (?<v0>.*?)$",
        "English": "Copy retained: {0}",
        "Count": 1,
        "Weight": 18
    },
    {
        "French": "DLL signalee pour $Name",
        "Pattern": "^DLL\\ signalee\\ pour\\ (?<v0>.*?)$",
        "English": "Reported DLL for {0}",
        "Count": 1,
        "Weight": 18
    },
    {
        "French": "Entrée pour fermer",
        "Pattern": "^Entrée\\ pour\\ fermer$",
        "English": "Press Enter to close",
        "Count": 0,
        "Weight": 18
    },
    {
        "French": "Dossier refusé : $($_.Exception.Message)",
        "Pattern": "^Dossier\\ refusé\\ :\\ (?<v0>.*?)$",
        "English": "Folder rejected: {0}",
        "Count": 1,
        "Weight": 17
    },
    {
        "French": "Profil $Name trouvé : $($item.FullName)",
        "Pattern": "^Profil\\ (?<v0>.*?)\\ trouvé\\ :\\ (?<v1>.*?)$",
        "English": "{0} profile found: {1}",
        "Count": 2,
        "Weight": 17
    },
    {
        "French": "TOUJOURS PRÉSENT",
        "Pattern": "^TOUJOURS\\ PRÉSENT$",
        "English": "STILL PRESENT",
        "Count": 0,
        "Weight": 16
    },
    {
        "French": "Rapport privé : {0}",
        "Pattern": "^Rapport\\ privé\\ :\\ (?<v0>.*?)$",
        "English": "Private report: {0}",
        "Count": 1,
        "Weight": 16
    },
    {
        "French": "OPTIONS AVANCÉES",
        "Pattern": "^OPTIONS\\ AVANCÉES$",
        "English": "ADVANCED OPTIONS",
        "Count": 0,
        "Weight": 16
    },
    {
        "French": "Anciennes copies",
        "Pattern": "^Anciennes\\ copies$",
        "English": "Old copies",
        "Count": 0,
        "Weight": 16
    },
    {
        "French": "  CONCLUSION : $($conclusion.Text)",
        "Pattern": "^\\ \\ CONCLUSION\\ :\\ (?<v0>.*?)$",
        "English": "  CONCLUSION: {0}",
        "Count": 1,
        "Weight": 15
    },
    {
        "French": "Cache DNS local",
        "Pattern": "^Cache\\ DNS\\ local$",
        "English": "Local DNS cache",
        "Count": 0,
        "Weight": 15
    },
    {
        "French": "Élément présent",
        "Pattern": "^Élément\\ présent$",
        "English": "Item present",
        "Count": 0,
        "Weight": 15
    },
    {
        "French": "[CONTRÔLE] $Name : $state",
        "Pattern": "^\\[CONTRÔLE\\]\\ (?<v0>.*?)\\ :\\ (?<v1>.*?)$",
        "English": "[CHECK] {0}: {1}",
        "Count": 2,
        "Weight": 14
    },
    {
        "French": "Contrôle : $($check.Name) — $($check.State)",
        "Pattern": "^Contrôle\\ :\\ (?<v0>.*?)\\ —\\ (?<v1>.*?)$",
        "English": "Check: {0} — {1}",
        "Count": 2,
        "Weight": 14
    },
    {
        "French": "NON VÉRIFIABLE",
        "Pattern": "^NON\\ VÉRIFIABLE$",
        "English": "UNVERIFIABLE",
        "Count": 0,
        "Weight": 14
    },
    {
        "French": "    Limite : $Reason",
        "Pattern": "^\\ \\ \\ \\ Limite\\ :\\ (?<v0>.*?)$",
        "English": "    Limitation: {0}",
        "Count": 1,
        "Weight": 13
    },
    {
        "French": "Journal lu : $Path",
        "Pattern": "^Journal\\ lu\\ :\\ (?<v0>.*?)$",
        "English": "Log read: {0}",
        "Count": 1,
        "Weight": 13
    },
    {
        "French": "    Cause : $reason",
        "Pattern": "^\\ \\ \\ \\ Cause\\ :\\ (?<v0>.*?)$",
        "English": "    Cause: {0}",
        "Count": 1,
        "Weight": 12
    },
    {
        "French": "[INCOMPLET] $Text",
        "Pattern": "^\\[INCOMPLET\\]\\ (?<v0>.*?)$",
        "English": "[INCOMPLETE] {0}",
        "Count": 1,
        "Weight": 12
    },
    {
        "French": "NonRecherche",
        "Pattern": "^NonRecherche$",
        "English": "Not checked",
        "Count": 0,
        "Weight": 12
    },
    {
        "French": "Traces NIKKE",
        "Pattern": "^Traces\\ NIKKE$",
        "English": "NIKKE traces",
        "Count": 0,
        "Weight": 12
    },
    {
        "French": "Trace passée",
        "Pattern": "^Trace\\ passée$",
        "English": "Past trace",
        "Count": 0,
        "Weight": 12
    },
    {
        "French": "  Limite : $issue",
        "Pattern": "^\\ \\ Limite\\ :\\ (?<v0>.*?)$",
        "English": "  Limitation: {0}",
        "Count": 1,
        "Weight": 11
    },
    {
        "French": "Hors de $selected — $name",
        "Pattern": "^Hors\\ de\\ (?<v0>.*?)\\ —\\ (?<v1>.*?)$",
        "English": "Outside {0} — {1}",
        "Count": 2,
        "Weight": 11
    },
    {
        "French": "NIKKE ET PC",
        "Pattern": "^NIKKE\\ ET\\ PC$",
        "English": "NIKKE AND PC",
        "Count": 0,
        "Weight": 11
    },
    {
        "French": "PC et NIKKE",
        "Pattern": "^PC\\ et\\ NIKKE$",
        "English": "PC and NIKKE",
        "Count": 0,
        "Weight": 11
    },
    {
        "French": "NAVIGATEURS",
        "Pattern": "^NAVIGATEURS$",
        "English": "BROWSERS",
        "Count": 0,
        "Weight": 11
    },
    {
        "French": "Navigateurs",
        "Pattern": "^Navigateurs$",
        "English": "Browser check",
        "Count": 0,
        "Weight": 11
    },
    {
        "French": "Cache NIKKE",
        "Pattern": "^Cache\\ NIKKE$",
        "English": "NIKKE cache",
        "Count": 0,
        "Weight": 11
    },
    {
        "French": "Votre choix",
        "Pattern": "^Votre\\ choix$",
        "English": "Your choice",
        "Count": 0,
        "Weight": 11
    },
    {
        "French": "  Raison : {0}",
        "Pattern": "^\\ \\ Raison\\ :\\ (?<v0>.*?)$",
        "English": "  Reason: {0}",
        "Count": 1,
        "Weight": 11
    },
    {
        "French": "Suppression",
        "Pattern": "^Suppression$",
        "English": "Deletion",
        "Count": 0,
        "Weight": 11
    },
    {
        "French": "Information",
        "Pattern": "^Information$",
        "English": "Information",
        "Count": 0,
        "Weight": 11
    },
    {
        "French": "0  Quitter",
        "Pattern": "^0\\ \\ Quitter$",
        "English": "0  Quit",
        "Count": 0,
        "Weight": 10
    },
    {
        "French": "Historique",
        "Pattern": "^Historique$",
        "English": "Historical",
        "Count": 0,
        "Weight": 10
    },
    {
        "French": "$Path (ligne $($match.LineNumber))",
        "Pattern": "^(?<v0>.*?)\\ \\(ligne\\ (?<v1>.*?)\\)$",
        "English": "{0} (line {1})",
        "Count": 2,
        "Weight": 9
    },
    {
        "French": "B  Retour",
        "Pattern": "^B\\ \\ Retour$",
        "English": "B  Back",
        "Count": 0,
        "Weight": 9
    },
    {
        "French": "  [$label] $(Get-FindingArea $row.Finding) — $(Get-FindingLabel $row.Finding)",
        "Pattern": "^\\ \\ \\[(?<v0>.*?)\\]\\ (?<v1>.*?)\\ —\\ (?<v2>.*?)$",
        "English": "  [{0}] {1} — {2}",
        "Count": 3,
        "Weight": 8
    },
    {
        "French": "Fichier $([IO.Path]::GetFileName($Finding.Target.Path))",
        "Pattern": "^Fichier\\ (?<v0>.*?)$",
        "English": "File {0}",
        "Count": 1,
        "Weight": 8
    },
    {
        "French": "Effectué",
        "Pattern": "^Effectué$",
        "English": "Completed",
        "Count": 0,
        "Weight": 8
    },
    {
        "French": "Registre",
        "Pattern": "^Registre$",
        "English": "Registry",
        "Count": 0,
        "Weight": 8
    },
    {
        "French": "Verifier",
        "Pattern": "^Verifier$",
        "English": "Full check",
        "Count": 0,
        "Weight": 8
    },
    {
        "French": "  {0} — {1} : {2}",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ —\\ (?<v1>.*?)\\ :\\ (?<v2>.*?)$",
        "English": "  {0} — {1}: {2}",
        "Count": 3,
        "Weight": 8
    },
    {
        "French": "BILAN : {0}",
        "Pattern": "^BILAN\\ :\\ (?<v0>.*?)$",
        "English": "RESULT: {0}",
        "Count": 1,
        "Weight": 8
    },
    {
        "French": "Partiel",
        "Pattern": "^Partiel$",
        "English": "Partial",
        "Count": 0,
        "Weight": 7
    },
    {
        "French": "DISPARU",
        "Pattern": "^DISPARU$",
        "English": "MISSING",
        "Count": 0,
        "Weight": 7
    },
    {
        "French": "SansJeu",
        "Pattern": "^SansJeu$",
        "English": "Game removed",
        "Count": 0,
        "Weight": 7
    },
    {
        "French": "Modules",
        "Pattern": "^Modules$",
        "English": "Modules",
        "Count": 0,
        "Weight": 7
    },
    {
        "French": "H  Aide",
        "Pattern": "^H\\ \\ Aide$",
        "English": "H  Help",
        "Count": 0,
        "Weight": 7
    },
    {
        "French": "    - $(Get-FindingLabel $f)",
        "Pattern": "^\\ \\ \\ \\ \\-\\ (?<v0>.*?)$",
        "English": "    - {0}",
        "Count": 1,
        "Weight": 6
    },
    {
        "French": "    - $(Get-FindingLabel $finding)",
        "Pattern": "^\\ \\ \\ \\ \\-\\ (?<v0>.*?)$",
        "English": "    - {0}",
        "Count": 1,
        "Weight": 6
    },
    {
        "French": "Absent",
        "Pattern": "^Absent$",
        "English": "Not found",
        "Count": 0,
        "Weight": 6
    },
    {
        "French": "Réseau",
        "Pattern": "^Réseau$",
        "English": "Network",
        "Count": 0,
        "Weight": 6
    },
    {
        "French": "  $($action.Action) : $($action.Finding.Location)",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ :\\ (?<v1>.*?)$",
        "English": "  {0}: {1}",
        "Count": 2,
        "Weight": 5
    },
    {
        "French": "  $($check.Name) : $($check.State)",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ :\\ (?<v1>.*?)$",
        "English": "  {0}: {1}",
        "Count": 2,
        "Weight": 5
    },
    {
        "French": "  $($entry.Name) : $($entry.State)",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ :\\ (?<v1>.*?)$",
        "English": "  {0}: {1}",
        "Count": 2,
        "Weight": 5
    },
    {
        "French": "  $($i + 1) : $($candidates[$i])",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ :\\ (?<v1>.*?)$",
        "English": "  {0}: {1}",
        "Count": 2,
        "Weight": 5
    },
    {
        "French": "  $(Get-FindingArea $finding) — $(Get-FindingLabel $finding)",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ —\\ (?<v1>.*?)$",
        "English": "  {0} — {1}",
        "Count": 2,
        "Weight": 5
    },
    {
        "French": "  $Label : $Reason",
        "Pattern": "^\\ \\ (?<v0>.*?)\\ :\\ (?<v1>.*?)$",
        "English": "  {0}: {1}",
        "Count": 2,
        "Weight": 5
    },
    {
        "French": "  [{0}] {1}",
        "Pattern": "^\\ \\ \\[(?<v0>.*?)\\]\\ (?<v1>.*?)$",
        "English": "  [{0}] {1}",
        "Count": 2,
        "Weight": 5
    },
    {
        "French": "    $($finding.Location)",
        "Pattern": "^\\ \\ \\ \\ (?<v0>.*?)$",
        "English": "    {0}",
        "Count": 1,
        "Weight": 4
    },
    {
        "French": "Tous",
        "Pattern": "^Tous$",
        "English": "All",
        "Count": 0,
        "Weight": 4
    }
]
'@ | ConvertFrom-Json
$script:UiLiterals = @{}
foreach ($entry in $script:UiCatalog) {
    if ($entry.Count -eq 0) {
        $script:UiLiterals[$entry.French] = $entry.English
    }
    $entry | Add-Member -NotePropertyName Matcher -NotePropertyValue ([regex]::new($entry.Pattern, [Text.RegularExpressions.RegexOptions]::Singleline))
}

function Convert-UiText([string]$Text, [int]$Depth = 0) {
    if ($script:Language -ne 'en' -or $Depth -gt 6 -or [string]::IsNullOrEmpty($Text)) {
        return $Text
    }
    if ($script:TranslationCache.ContainsKey($Text)) {
        return $script:TranslationCache[$Text]
    }
    if ($script:UiLiterals.ContainsKey($Text)) {
        return $script:UiLiterals[$Text]
    }
    if ($Text -match '^[A-Za-z]:[\\/]' -or $Text -match '^\\\\') {
        return $Text
    }
    foreach ($entry in $script:UiCatalog) {
        if ($entry.Count -eq 0) {
            continue
        }
        $match = $entry.Matcher.Match($Text)
        if (-not $match.Success) {
            continue
        }
        $values = @()
        for ($i = 0; $i -lt $entry.Count; $i++) {
            $values += Convert-UiText $match.Groups["v$i"].Value ($Depth + 1)
        }
        $result = [string]::Format([Globalization.CultureInfo]::InvariantCulture, $entry.English, [object[]]$values)
        $script:TranslationCache[$Text] = $result
        return $result
    }
    return $Text
}

function Write-Host {
    [CmdletBinding()]
    param([Parameter(Position = 0, ValueFromRemainingArguments = $true)][object[]]$Object, [ConsoleColor]$ForegroundColor = 'Gray')
    Microsoft.PowerShell.Utility\Write-Host -Object (Convert-UiText ([string]($Object -join ' '))) -ForegroundColor $ForegroundColor
}

function Read-Host {
    param([string]$Prompt)
    $value = Microsoft.PowerShell.Utility\Read-Host -Prompt (Convert-UiText $Prompt)
    if ($null -eq $value) {
        throw [OperationCanceledException]::new('Input stream closed; no automatic action.')
    }
    return ([string]$value).Trim()
}

function Select-UiLanguage {
    do {
        Microsoft.PowerShell.Utility\Write-Host '1  English'
        Microsoft.PowerShell.Utility\Write-Host '2  Français / French'
        $choice = Microsoft.PowerShell.Utility\Read-Host 'Language / Langue [Enter = English]'
        if ($null -eq $choice) {
            throw [OperationCanceledException]::new('Input stream closed; no automatic action.')
        }
        $choice = $choice.Trim().ToLowerInvariant()
        if ($choice -in @('', '1', 'en', 'english', 'anglais')) {
            $script:Language = 'en'
            return
        }
        if ($choice -in @('2', 'fr', 'français', 'french')) {
            $script:Language = 'fr'
            return
        }
    } while ($true)
}

# END LANGUAGE SUPPORT

function Initialize-Report {
    $script:Report = New-Object 'System.Collections.Generic.List[string]'
    $script:Findings = New-Object 'System.Collections.Generic.List[object]'
    $script:SeenFindings = @{}
    $script:BrowserCheckMap = @{}
    $script:Issues = New-Object 'System.Collections.Generic.List[string]'
    $script:SeenLogs = @{}
    $script:DllHashCache = @{}
    $script:LogsRead = 0
    $script:BrowserRoots = 0
    $script:ReportPath = $null
    $script:QuietScan = $false
    $script:ScanPaths = @()
    $script:DiscoveryIssues = @()
    $script:CurrentSnapshot = $null
    $script:HistoricalExposure = $false
    $script:BrowserNames = New-Object 'System.Collections.Generic.List[string]'
    $script:AdviceShown = $false
    $script:CleanupNeedsRestart = $false
    $script:CleanupOutcomes = New-Object 'System.Collections.Generic.List[object]'
}

function Write-Report([string]$Text, [ConsoleColor]$Color = 'Gray') {
    $script:Report.Add((Convert-UiText $Text))
    if (-not $script:QuietScan) {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Write-Detail([string]$Text) {
    $script:Report.Add((Convert-UiText $Text))
}

function Add-Issue([string]$Text) {
    $script:Issues.Add($Text)
    Write-Report "[INCOMPLET] $Text"
}

function Add-Finding([string]$Kind, [string]$Location, [bool]$Strong = $true, [string]$Type = 'Observation', [hashtable]$Target = @{}) {
    $id = "$Type|$Location"
    if ($Type -eq 'Historique' -and $Target.ContainsKey('Marker')) {
        $id += "|$($Target.Marker)"
    }
    if ($script:SeenFindings.ContainsKey($id)) {
        return
    }
    $script:SeenFindings[$id] = $true
    $script:Findings.Add([pscustomobject]@{
            Id = $id; Kind = $Kind; Location = $Location; Strong = $Strong; Type = $Type; Target = $Target
        })
    Write-Report "[TRACE A EXAMINER] $Kind : $Location"
}

function Get-LocalItem([string]$Path) {
    try {
        Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        # Missing optional locations are expected.
    } catch {
        Add-Issue "Acces impossible : $Path"
    }
}

function Find-IndicatorFiles([string]$Root, [string[]]$Filter, [ValidateRange(0, 64)][int]$MaxDepth = 7) {
    # Bound the search and skip junctions.
    $pending = New-Object 'System.Collections.Generic.Queue[object]'
    $pending.Enqueue(@($Root, 0))
    $visited = 0
    $limited = $false
    while ($pending.Count -gt 0) {
        $entry = $pending.Dequeue()
        $dir = [string]$entry[0]
        $depth = [int]$entry[1]
        $visited++
        if ($visited -gt 12000) {
            $limited = $true
            break
        }
        try {
            # The search pattern also counts toward legacy Windows path limits.
            $readPath = if ($dir -match '^[A-Za-z]:\\') {
                '\\?\' + $dir
            } else {
                $dir
            }
            foreach ($fileFilter in $Filter) {
                Get-ChildItem -LiteralPath $readPath -File -Force -Filter $fileFilter -ErrorAction Stop |
                Where-Object {
                    -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
                } | ForEach-Object {
                    if ($_.FullName.StartsWith('\\?\', [StringComparison]::Ordinal)) {
                        [IO.FileInfo]::new($_.FullName.Substring(4))
                    } else {
                        $_
                    }
                }
            }
            $children = @(Get-ChildItem -LiteralPath $readPath -Directory -Force -ErrorAction Stop)
            foreach ($child in $children) {
                if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    Add-Issue "Jonction/lien ignore : $($child.FullName)"
                    continue
                }
                if ($child.Name -match '^(Cache|Code Cache|GPUCache|CacheStorage|Service Worker|ShaderCache|GrShaderCache|DawnCache|node_modules|Game|Games|NIKKE_Data)$') {
                    continue
                }
                if ($depth -ge $MaxDepth) {
                    $limited = $true
                    continue
                }
                $childPath = $child.FullName
                if ($childPath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
                    $childPath = $childPath.Substring(4)
                }
                $pending.Enqueue(@($childPath, ($depth + 1)))
            }
        } catch {
            Add-Issue "Dossier non parcouru ou partiellement parcouru : $dir"
        }
    }
    if ($limited) {
        Add-Issue "Limite de recherche atteinte sous : $Root"
    }
}

function Test-LogFile([string]$Path) {
    if ($script:SeenLogs.ContainsKey($Path)) {
        return
    }
    $script:SeenLogs[$Path] = $true
    try {
        if ([IO.Path]::GetFileName($Path) -ieq 'k2f.lua') {
            $info = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($info.Length -gt 64MB) {
                throw 'Ancien fichier Lua trop volumineux.'
            }
            $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($hash -ieq 'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec') {
                Add-Finding 'Ancien fichier du programme malveillant reconnu par empreinte' $Path $true 'Fichier' @{
                    Path = $Path
                    PayloadHash = $hash
                }
            } else {
                Add-Finding 'Ancien fichier k2f.lua à examiner ; contenu non confirmé' $Path $false 'Observation' @{
                    Path = $Path
                    Area = 'NIKKE'
                }
            }
            return
        }
        if ([IO.Path]::GetFileName($Path) -like 'tinyget.*.log') {
            $info = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($info.Length -eq 205135) {
                $fileHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
                $knownHash = $fileHash -eq 'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec'
                if (-not $knownHash) {
                    if (Test-OfficialPayloadPath $Path) {
                        Add-Finding 'Fichier correspondant aux critères du guide officiel ; empreinte malveillante non confirmée' $Path $false 'Fichier' @{
                            Path = $Path
                            Area = 'NIKKE'
                            OfficialPayload = $true
                            Sha256 = $fileHash
                        }
                    } else {
                        Add-Finding 'Fichier téléchargé à examiner : taille signalée, contenu non confirmé' $Path $false 'Observation' @{
                            Path = $Path
                            Area = 'NIKKE'
                            SizeCandidate = $true
                        }
                    }
                } else {
                    Add-Finding 'Empreinte du payload signalé dans un fichier tinyget' $Path $true 'Fichier' @{
                        Path = $Path
                        PayloadHash = 'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec'
                    }
                }
            }
        }
        $markers = @('k2f_chan', 'insightjs.com', 'insightjs.org', '89.127.233.127', 'insight.bundle', 'agent started as', 'lua downloaded to log')
        $logHits = @(Select-String -LiteralPath $Path -Pattern $markers -SimpleMatch -AllMatches -ErrorAction Stop | Select-Object -First 40)
        $script:LogsRead++
        Write-Report "Journal lu : $Path"
        foreach ($hit in $logHits) {
            foreach ($marker in $markers) {
                if ($hit.Line.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    continue
                }
                # Report the marker only; log lines may contain secrets or computer names.
                $evidence = if ($marker -eq 'k2f_chan' -and $hit.Line.IndexOf('k2f_chan registered', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    'k2f_chan registered'
                } else {
                    $marker
                }
                $lineLabel = if ($script:Language -eq 'en') {
                    'line'
                } else {
                    'ligne'
                }
                $strong = $marker -in @('k2f_chan', 'agent started as')
                Add-Finding 'Marqueur du signalement dans un ancien journal' "$Path ($lineLabel $($hit.LineNumber))" $strong 'Historique' @{
                    Path = $Path
                    Marker = $marker
                    Evidence = $evidence
                    LineNumber = $hit.LineNumber
                }
            }
        }
        if ($logHits.Count -eq 40) {
            Add-Issue "Affichage des preuves limité à 40 lignes correspondantes : $Path"
        }
    } catch {
        Add-Issue "Journal illisible : $Path"
    }
}

function Test-NikkePath([string]$Path, [switch]$Required) {
    $Path = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($Path -notmatch '^[A-Za-z]:[\\/]') {
        Add-Issue "Utiliser un chemin local absolu, par exemple D:\Jeux\NIKKE : $Path"
        return
    }
    try {
        $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($Path))
        if ($drive.DriveType -eq [IO.DriveType]::Network) {
            Add-Issue "Lecteur reseau ignore : $Path"
            return
        }
    } catch {
        Add-Issue "Lecteur non accessible : $Path"
        return
    }
    $item = Get-LocalItem $Path
    if ($null -eq $item) {
        if ($Required) {
            Add-Issue "Chemin indique introuvable : $Path"
        }
        return
    }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Add-Issue "Chemin lie/jonction ignore : $Path"
        return
    }
    if (-not $item.PSIsContainer) {
        Test-LogFile $item.FullName
        return
    }
    # Reject drive roots to avoid an accidental full-drive scan.
    if ($item.FullName.TrimEnd('\') -eq [IO.Path]::GetPathRoot($item.FullName).TrimEnd('\')) {
        Add-Issue "Choisir le dossier du jeu, pas la racine du disque : $Path"
        return
    }
    Write-Report "Recherche de debug.log et de ses rotations : $($item.FullName)"
    foreach ($file in @(Find-IndicatorFiles $item.FullName @('debug.log*', 'tinyget.*.log', 'k2f.lua'))) {
        Test-LogFile $file.FullName
    }
}

function Get-NikkeLauncherDirectory([string]$Value) {
    $executable = ($Value.Trim() -replace ',\s*-?\d+$', '').Trim('"')
    if ($executable -match '^[A-Za-z]:[\\/]' -and [IO.Path]::GetFileName($executable) -match '^nikke_launcher(?:_google|_hmt)?\.exe$') {
        [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($executable))
    }
}

function Get-NikkeInstallPaths {
    foreach ($drive in [IO.DriveInfo]::GetDrives()) {
        if ($drive.DriveType -eq [IO.DriveType]::Fixed -and $drive.IsReady) {
            foreach ($suffix in @('NIKKE', 'NIKKE_GOOGLE', 'Program Files\NIKKE', 'Program Files (x86)\NIKKE', 'Games\NIKKE', 'Level Infinite\NIKKE')) {
                Join-Path $drive.RootDirectory.FullName $suffix
            }
        }
    }
    foreach ($local in @($env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($local) {
            Join-Path $local 'NIKKE'
        }
    }
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            $base = $null
            $uninstall = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
                if ($hive -eq [Microsoft.Win32.RegistryHive]::CurrentUser) {
                    $protocol = $base.OpenSubKey('Software\Classes\nikkelauncher\DefaultIcon', $false)
                    try {
                        if ($null -ne $protocol) {
                            Get-NikkeLauncherDirectory ([string]$protocol.GetValue(''))
                        }
                    } finally {
                        if ($null -ne $protocol) {
                            $protocol.Dispose()
                        }
                    }
                }
                $uninstall = $base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall', $false)
                if ($null -eq $uninstall) {
                    continue
                }
                foreach ($name in $uninstall.GetSubKeyNames()) {
                    $key = $null
                    try {
                        $key = $uninstall.OpenSubKey($name, $false)
                        if ($null -ne $key -and [string]$key.GetValue('DisplayName') -match '(?i)\bNIKKE\b') {
                            foreach ($field in @('InstallLocation', 'GameInstallPath')) {
                                $location = [string]$key.GetValue($field)
                                if ($location) {
                                    $location
                                }
                            }
                        }
                    } finally {
                        if ($null -ne $key) {
                            $key.Dispose()
                        }
                    }
                }
            } catch {
                Add-Issue "Informations d'installation inaccessibles : $hive / $view"
            }
            finally {
                if ($null -ne $uninstall) {
                    $uninstall.Dispose()
                }
                if ($null -ne $base) {
                    $base.Dispose()
                }
            }
        }
    }
}

function Get-BrowserScanInfo($Snapshot, [string]$Name) {
    if ($Snapshot.PSObject.Properties['BrowserChecks']) {
        $entry = @($Snapshot.BrowserChecks | Where-Object {
                $_.Name -eq $Name
            })
        if ($entry.Count -gt 0) {
            return $entry[0]
        }
    }
    # Allow snapshots without per-browser details.
    $state = if ($Name -in $Snapshot.CheckedBrowsers -and (Get-CheckComplete $Snapshot 'Fichiers des navigateurs*')) {
        'Effectué'
    } else {
        'Absent'
    }
    return [pscustomobject]@{
        Name = $Name
        State = $state
        Paths = @()
        Reasons = @()
    }
}

function Test-BrowserRoot([string]$Name, [string]$Root, [bool]$Required = $false) {
    $record = $script:BrowserCheckMap[$Name]
    if ($record.Attempted.Contains($Root)) {
        return
    }
    $record.Attempted.Add($Root)
    $before = $script:Issues.Count
    try {
        $item = Get-LocalItem $Root
        if ($null -eq $item) {
            if ($Required) {
                Add-Issue "Dossier de profil fourni introuvable : $Root"
            }
            return
        }
        if (-not $item.PSIsContainer) {
            Add-Issue "Ce chemin de navigateur n est pas un dossier : $Root"
            return
        }
        $script:BrowserRoots++
        $record.Paths.Add($item.FullName)
        if (-not $script:BrowserNames.Contains($Name)) {
            $script:BrowserNames.Add($Name)
        }
        Write-Detail "Profil $Name trouvé : $($item.FullName)"
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Add-Issue "Profil redirigé non parcouru : $Root"
            return
        }
        $filters = @('platform_experience_helper.dll')
        if ($Name -eq 'Chrome' -and $item.Name -eq 'PlatformExperienceHelper') {
            $filters += @('platform_experience_helper.dll.old', 'old-clsid.txt', 'service_util.dll')
        }
        foreach ($filter in $filters) {
            foreach ($file in @(Find-IndicatorFiles $item.FullName $filter -MaxDepth 64)) {
                $evidence = Get-DllHashEvidence $file.FullName
                $kind = if ($filter -eq 'platform_experience_helper.dll') {
                    "DLL signalee pour $Name"
                } else {
                    'Ancien fichier signalé dans le dossier Chrome'
                }
                Add-Finding $kind $file.FullName ($evidence.Known -or (Test-KnownChromeDllPath $file.FullName)) 'Fichier' @{
                    Path = $file.FullName
                    Browser = $Name
                    Sha256 = $evidence.Hash
                    KnownDllHash = $evidence.Known
                }
            }
        }
    } catch {
        Add-Issue "Lecture du profil $Name interrompue : $Root"
    }
    finally {
        for ($i = $before; $i -lt $script:Issues.Count; $i++) {
            $record.Reasons.Add($script:Issues[$i])
        }
        $record.State = if ($record.Reasons.Count -gt 0) {
            'Partiel'
        } elseif ($record.Paths.Count -gt 0) {
            'Effectué'
        } else {
            'Absent'
        }
    }
}

function Test-BrowserFiles {
    foreach ($name in @('Chrome', 'Edge', 'Firefox', 'Brave', 'Opera', 'Vivaldi')) {
        if ($Navigateur -ne 'Tous' -and $Navigateur -ne $name) {
            continue
        }
        $script:BrowserCheckMap[$name] = [pscustomobject]@{
            Name = $name
            State = 'Absent'
            Paths = New-Object 'System.Collections.Generic.List[string]'
            Attempted = New-Object 'System.Collections.Generic.List[string]'
            Reasons = New-Object 'System.Collections.Generic.List[string]'
        }
    }
    $relative = @(
        @('Chrome', $env:LOCALAPPDATA, 'Google\Chrome\User Data'),
        @('Chrome', $env:LOCALAPPDATA, 'Google\Chrome Beta\User Data'),
        @('Chrome', $env:LOCALAPPDATA, 'Google\Chrome Dev\User Data'),
        @('Chrome', $env:LOCALAPPDATA, 'Google\Chrome SxS\User Data'),
        @('Edge', $env:LOCALAPPDATA, 'Microsoft\Edge\User Data'),
        @('Edge', $env:LOCALAPPDATA, 'Microsoft\Edge Beta\User Data'),
        @('Edge', $env:LOCALAPPDATA, 'Microsoft\Edge Dev\User Data'),
        @('Edge', $env:LOCALAPPDATA, 'Microsoft\Edge SxS\User Data'),
        @('Brave', $env:LOCALAPPDATA, 'BraveSoftware\Brave-Browser\User Data'),
        @('Vivaldi', $env:LOCALAPPDATA, 'Vivaldi\User Data'),
        @('Opera', $env:APPDATA, 'Opera Software'),
        @('Firefox', $env:APPDATA, 'Mozilla\Firefox\Profiles'),
        @('Firefox', $env:LOCALAPPDATA, 'Mozilla\Firefox\Profiles')
    )
    foreach ($pair in $relative) {
        if (-not $script:BrowserCheckMap.ContainsKey($pair[0])) {
            continue
        }
        if (-not $pair[1]) {
            $reason = "Dossier AppData indisponible pour $($pair[0])."
            $script:BrowserCheckMap[$pair[0]].Reasons.Add($reason)
            $script:BrowserCheckMap[$pair[0]].State = 'Partiel'
            Add-Issue $reason
            continue
        }
        Test-BrowserRoot $pair[0] (Join-Path $pair[1] $pair[2])
    }
    if ($script:BrowserCheckMap.ContainsKey('Chrome')) {
        foreach ($root in @(Get-AdditionalChromeRoots)) {
            Test-BrowserRoot 'Chrome' $root
        }
    }
    foreach ($custom in $script:CustomBrowserRoots) {
        if ($script:BrowserCheckMap.ContainsKey($custom.Name)) {
            Test-BrowserRoot $custom.Name $custom.Path $true
        }
    }
}

function Add-CustomBrowserRoot([string]$Name, [string]$Path) {
    if ($Name -notin @('Chrome', 'Edge', 'Firefox', 'Brave', 'Opera', 'Vivaldi')) {
        throw 'Choisissez un navigateur précis.'
    }
    $pathValue = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($pathValue -notmatch '^[A-Za-z]:[\\/]') {
        throw 'Indiquez un dossier local absolu, par exemple D:\Profils\Chrome.'
    }
    $full = [IO.Path]::GetFullPath($pathValue)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -eq [IO.DriveType]::Network) {
        throw 'Les profils réseau ne sont pas pris en charge.'
    }
    if ($full.TrimEnd('\') -eq [IO.Path]::GetPathRoot($full).TrimEnd('\')) {
        throw 'Choisissez le dossier du profil, pas un disque entier.'
    }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        throw 'Choisissez le dossier du profil, pas le fichier EXE du navigateur.'
    }
    Assert-NoReparsePoint $full
    if ($Name -ne 'Firefox') {
        # Check User Data alongside Default and Profile N.
        $parent = [IO.Path]::GetDirectoryName($full.TrimEnd('\'))
        if ($parent -and ($item.Name -match '^(Default|Profile \d+)$' -or (Test-Path -LiteralPath (Join-Path $parent 'Local State') -PathType Leaf -ErrorAction Stop))) {
            if ($parent.TrimEnd('\') -ne [IO.Path]::GetPathRoot($parent).TrimEnd('\')) {
                Assert-NoReparsePoint $parent
                $full = $parent
            }
        }
    }
    if (@($script:CustomBrowserRoots | Where-Object {
                $_.Name -eq $Name -and $_.Path -eq $full
            }).Count -eq 0) {
        $script:CustomBrowserRoots.Add([pscustomobject]@{
                Name = $Name; Path = $full
            })
    }
    return $full
}

function Offer-CustomBrowserRoot {
    $name = $Navigateur
    if ($Mode -ne 'Navigateurs' -or $name -eq 'Tous') {
        do {
            Write-Host 'Pour quel navigateur voulez-vous indiquer le profil ?'
            $name = Select-Browser
            if ($name -eq 'Retour') {
                return $false
            }
            if ($name -eq 'Tous') {
                Write-Host 'Choisissez un navigateur précis, par exemple Chrome.'
            }
        } while ($name -eq 'Tous')
    }
    Write-Host "DOSSIER DU PROFIL — $name" -ForegroundColor Cyan
    Write-Host 'Indiquez un dossier de données, pas chrome.exe, msedge.exe ou firefox.exe.'
    Write-Host 'Emplacements habituels à ouvrir dans l Explorateur ou avec Windows + R :'
    switch ($name) {
        'Chrome' {
            Write-Host '  %LOCALAPPDATA%\Google\Chrome\User Data'
        }
        'Edge' {
            Write-Host '  %LOCALAPPDATA%\Microsoft\Edge\User Data'
        }
        'Firefox' {
            Write-Host '  %APPDATA%\Mozilla\Firefox\Profiles'
        }
        default {
            Write-Host '  Le dossier User Data ou le profil de votre installation portable.'
        }
    }
    Write-Host 'Si le navigateur est déjà ouvert : Chrome chrome://version ; Edge edge://version ; Firefox about:profiles.'
    Write-Host 'Relevez le chemin du profil (dossier racine pour Firefox). Ne lancez pas un navigateur suspect uniquement pour cela.'
    $path = Read-Host 'Collez le chemin du dossier [Entrée = annuler]'
    if ([string]::IsNullOrWhiteSpace($path)) {
        return $false
    }
    try {
        $root = Add-CustomBrowserRoot $name $path
        Write-Report "Dossier $name ajouté pour cette session : $root"
        return $true
    } catch {
        Write-Report "Dossier non ajouté : $($_.Exception.Message)" Yellow
        return $false
    }
}

function Test-PersistenceValue([string]$Sub, [string]$Name, [string]$Value, [string]$Location, [hashtable]$Target = @{}) {
    $com = 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32'
    if ($Sub -eq $com -and $Target.ContainsKey('Hive') -and $Target.Hive -eq 'LocalMachine') {
        return
    }
    $Target['Fingerprint'] = Get-ValueFingerprint $Value
    $Target['KnownChromeOverride'] = $Sub -eq $com -and $Target.ContainsKey('Hive') -and $Target.Hive -eq 'CurrentUser' -and (Test-KnownChromeDllPath $Value)
    if ($Value -match '(?i)platform_experience_helper\.dll|k2f_chan|(?:^|[^a-z0-9.-])(?:[a-z0-9-]+\.)*insightjs\.(?:com|org)(?:[^a-z0-9.-]|$)|(?:^|[^0-9.])89\.127\.233\.127(?:[^0-9.]|$)') {
        Add-Finding 'Reference du registre correspondant aux signalements' $Location ([bool]$Target.KnownChromeOverride -or $Value -match '(?i)k2f_chan') 'Registre' $Target
    } elseif ($Name -eq 'Chrome Helper') {
        Write-Detail 'Entrée de démarrage Chrome Helper : nom seul non retenu comme trace de cet incident.'
    } elseif ($Sub -eq $com -and $Name -eq '') {
        Add-Finding 'Surcharge utilisateur du CLSID signale : a examiner' $Location $false 'Registre' $Target
    }
}

function Test-EmptyUserClsid([Microsoft.Win32.RegistryKey]$Base, [string]$View) {
    $parent = 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
    $key = $Base.OpenSubKey($parent, $false)
    try {
        if ($null -ne $key -and $key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0) {
            Add-Finding 'Ancienne référence de démarrage vide liée à cet incident' "$View / $parent" $false 'Registre' @{
                Hive = 'CurrentUser'
                View = $View
                SubKey = $parent
                Name = ''
                EmptyClsid = $true
                Fingerprint = 'empty'
            }
        }
    } finally {
        if ($null -ne $key) {
            $key.Dispose()
        }
    }
}

function Remove-EmptyUserClsid([hashtable]$Target, [string]$BackupPath) {
    $parent = 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
    if ($Target.Hive -ne 'CurrentUser' -or $Target.SubKey -ne $parent) {
        throw 'Référence hors du périmètre autorisé.'
    }
    $view = [Microsoft.Win32.RegistryView][Enum]::Parse([Microsoft.Win32.RegistryView], $Target.View)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)
    $key = $null
    try {
        $key = $base.OpenSubKey($parent, $false)
        if ($null -eq $key) {
            return $false
        }
        if ($key.GetValueNames().Count -ne 0 -or $key.GetSubKeyNames().Count -ne 0) {
            throw 'La référence a changé : retrait annulé.'
        }
        $Target | Export-Clixml -LiteralPath $BackupPath -Encoding UTF8 -ErrorAction Stop
        $key.Dispose()
        $key = $null
        # Non-recursive deletion refuses any newly added child key.
        $base.DeleteSubKey($parent, $false)
        return $true
    } finally {
        if ($null -ne $key) {
            $key.Dispose()
        }
        $base.Dispose()
    }
}


function Test-Persistence {
    $com = 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32'
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            $base = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
                if ($hive -eq [Microsoft.Win32.RegistryHive]::CurrentUser) {
                    Test-EmptyUserClsid $base ([string]$view)
                }
                foreach ($sub in @($com, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
                    # The HKLM CLSID normally belongs to the Windows component wpc.dll.
                    if ($sub -eq $com -and $hive -eq [Microsoft.Win32.RegistryHive]::LocalMachine) {
                        continue
                    }
                    $key = $null
                    try {
                        $key = $base.OpenSubKey($sub, $false)
                        if ($null -eq $key) {
                            continue
                        }
                        foreach ($name in $key.GetValueNames()) {
                            $value = [string]$key.GetValue($name)
                            $where = "$hive / $view / $sub / valeur '$name'"
                            Test-PersistenceValue $sub $name $value $where @{
                                Hive = [string]$hive
                                View = [string]$view
                                SubKey = $sub
                                Name = $name
                            }
                        }
                    } finally {
                        if ($null -ne $key) {
                            $key.Dispose()
                        }
                    }
                }
            } catch {
                Add-Issue "Registre partiellement inaccessible : $hive / $view"
            }
            finally {
                if ($null -ne $base) {
                    $base.Dispose()
                }
            }
        }
    }
}

function Get-Verdict([int]$StrongCount, [int]$WeakCount, [int]$ReadCount, [int]$IssueCount) {
    if ($StrongCount -gt 0) {
        return 'TRACES SIGNALEES TROUVEES - traiter le PC comme potentiellement compromis.'
    }
    if ($WeakCount -gt 0) {
        return 'ELEMENTS A EXAMINER - presence insuffisante pour conclure a une infection.'
    }
    if ($ReadCount -eq 0 -or $IssueCount -gt 0) {
        return 'VERIFICATION INCOMPLETE - impossible de conclure.'
    }
    return 'AUCUNE TRACE CONNUE DETECTEE DANS LE PERIMETRE VERIFIE - aucune garantie que le PC soit sain.'
}

function Confirm-Action([string]$Question, [switch]$AllowReport) {
    do {
        $prompt = if ($AllowReport) {
            "$Question [O/N/R = rapport, Entrée = Non]"
        } else {
            "$Question [O/N, Entrée = Non]"
        }
        $answer = (Read-Host $prompt).Trim().ToLowerInvariant()
        if ($AllowReport -and $answer -eq 'r') {
            Open-PlayerReport
            continue
        }
        if ($answer -in @('o', 'oui', 'y', 'yes')) {
            return $true
        }
        if ($answer -in @('', 'n', 'non', 'no')) {
            return $false
        }
        Write-Host 'Répondre O pour Oui ou N pour Non.'
    } while ($true)
}

function Get-ValueFingerprint([string]$Value) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToBase64String($hash.ComputeHash([Text.Encoding]::Unicode.GetBytes($Value)))
    }
    finally {
        $hash.Dispose()
    }
}

function Test-AgentTempName([string]$Name) {
    return $Name -match '(?i)^k2f[-_](?:bcreds|keyscan)[-_].+\.db(?:-(?:wal|shm|journal))?$|^k2f[-_]screen[-_].+\.(?:jpg|jpeg|png)$'
}

function Test-AgentTempPath([string]$Path) {
    try {
        $root = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
        $full = [IO.Path]::GetFullPath($Path)
        return $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -and (Test-AgentTempName ([IO.Path]::GetFileName($full)))
    } catch {
        return $false
    }
}

function Test-LegacyCopyPath([string]$Path, [string]$Source, [string]$Hash) {
    try {
        $root = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'NIKKE-Assistance\Quarantaine')).TrimEnd('\') + '\'
        $full = [IO.Path]::GetFullPath($Path)
        if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or $full.Substring($root.Length) -notmatch '^[a-fA-F0-9]{32}\\[a-fA-F0-9]{32}\.quarantaine$') {
            return $false
        }
        if ($Hash -notmatch '^[a-fA-F0-9]{64}$') {
            return $false
        }
        if (Test-KnownChromeDllPath $Source) {
            return $true
        }
        if (Test-AgentTempPath $Source) {
            return $true
        }
        return $Hash -ieq 'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec' -and [IO.Path]::GetFileName($Source) -like 'tinyget.*.log'
    } catch {
        return $false
    }
}

function Test-LegacyInstallationCopies {
    foreach ($base in @('NIKKE-Assistance\Quarantaine', 'NIKKE-Assistance\Sauvegardes')) {
        $root = Join-Path $env:LOCALAPPDATA $base
        if ($null -eq (Get-LocalItem $root)) {
            continue
        }
        try {
            Assert-NoReparsePoint $root
            $count = 0
            foreach ($folder in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop)) {
                if ($folder.Name -notmatch '^[a-fA-F0-9]{32}$') {
                    continue
                }
                if (++$count -gt 512) {
                    throw 'Limite de contrôle des anciens dossiers atteinte.'
                }
                Assert-NoReparsePoint $folder.FullName
                $record = Get-LocalItem (Join-Path $folder.FullName 'retrait-jeu.json')
                if ($null -eq $record) {
                    continue
                }
                Assert-NoReparsePoint $record.FullName
                if ($record.PSIsContainer -or $record.Length -gt 64KB) {
                    throw 'Ancien enregistrement de retrait non reconnu.'
                }
                $metadata = [IO.File]::ReadAllText($record.FullName) | ConvertFrom-Json -ErrorAction Stop
                $origin = [IO.Path]::GetFullPath([string]$metadata.Source).TrimEnd('\')
                $destination = [IO.Path]::GetFullPath([string]$metadata.Destination).TrimEnd('\')
                $prefix = $origin + '.NIKKE-quarantaine-'
                if (-not $destination.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or $destination.Substring($prefix.Length) -notmatch '^[a-fA-F0-9]{8}$') {
                    throw 'Ancien enregistrement de retrait incohérent.'
                }
                if ($null -ne (Get-LocalItem $destination)) {
                    [void](Get-ConfirmedNikkeFolder $destination)
                    Add-Finding 'Ancienne copie du dossier NIKKE à examiner manuellement ; elle ne sera pas effacée automatiquement' $destination $false 'Observation' @{
                        Area = 'Anciennes copies'
                    }
                }
                if (@(Get-ChildItem -LiteralPath $folder.FullName -File -Filter '*.journal' -Force -ErrorAction Stop).Count -gt 0) {
                    Add-Finding 'Anciennes sauvegardes de journaux conservées par NikkeTrace ; à examiner avant suppression' $folder.FullName $false 'Observation' @{
                        Area = 'Anciennes copies'
                    }
                }
            }
        } catch {
            Add-Issue 'Contrôle des anciens dossiers conservés par NikkeTrace incomplet.'
        }
    }
}

function Test-LegacyQuarantine {
    if (-not $env:LOCALAPPDATA) {
        return
    }
    Test-LegacyInstallationCopies
    $root = Join-Path $env:LOCALAPPDATA 'NIKKE-Assistance\Quarantaine'
    if ($null -eq (Get-LocalItem $root)) {
        return
    }
    try {
        Assert-NoReparsePoint $root
        $count = 0
        [long]$remaining = 128MB
        foreach ($directory in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop)) {
            if ($directory.Name -notmatch '^[a-fA-F0-9]{32}$') {
                continue
            }
            Assert-NoReparsePoint $directory.FullName
            foreach ($file in @(Get-ChildItem -LiteralPath $directory.FullName -File -Filter '*.quarantaine' -Force -ErrorAction Stop)) {
                if (++$count -gt 512) {
                    throw 'Limite de contrôle des anciennes copies atteinte.'
                }
                try {
                    Assert-NoReparsePoint $file.FullName
                    $manifest = Get-Item -LiteralPath ($file.FullName + '.json') -Force -ErrorAction Stop
                    Assert-NoReparsePoint $manifest.FullName
                    if ($manifest.PSIsContainer -or $manifest.Length -gt 8KB) {
                        throw 'Enregistrement de copie invalide.'
                    }
                    $metadata = [IO.File]::ReadAllText($manifest.FullName) | ConvertFrom-Json -ErrorAction Stop
                    if ($metadata.Source -isnot [string] -or $metadata.Destination -isnot [string] -or [IO.Path]::GetFullPath($metadata.Destination) -ine $file.FullName) {
                        throw 'Enregistrement de copie incohérent.'
                    }
                    if ($file.Length -gt 64MB -or $file.Length -gt $remaining) {
                        throw 'Limite de lecture des anciennes copies atteinte.'
                    }
                    $remaining -= $file.Length
                    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    if (-not (Test-LegacyCopyPath $file.FullName $metadata.Source $hash)) {
                        throw 'Origine de la copie non reconnue.'
                    }
                    Add-Finding 'Ancienne copie de fichier conservée par NikkeTrace' $file.FullName $false 'Fichier' @{
                        Path = $file.FullName
                        Sha256 = $hash
                        LegacySource = $metadata.Source
                    }
                } catch {
                    Add-Finding 'Ancienne copie non identifiée : conservée pour assistance' $file.FullName $false 'Observation' @{
                        Area = 'Anciennes copies'
                    }
                    Add-Issue "Ancienne copie non vérifiable : $($file.FullName)"
                }
            }
        }
    } catch {
        Add-Issue 'Contrôle des anciennes copies NikkeTrace incomplet.'
    }
}

function Test-TemporaryFiles {
    if (-not $env:TEMP) {
        Add-Issue 'Le dossier temporaire est indisponible.'
        Test-LegacyQuarantine
        return
    }
    try {
        $tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
        if ($tempRoot -notmatch '^[A-Za-z]:\\' -or $tempRoot -ieq [IO.Path]::GetPathRoot($tempRoot).TrimEnd('\') -or $tempRoot -ieq $env:USERPROFILE) {
            throw 'Dossier temporaire trop large ou non local.'
        }
        if ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($tempRoot)).DriveType -eq [IO.DriveType]::Network) {
            throw 'Dossier temporaire réseau non parcouru.'
        }
        Assert-NoReparsePoint $tempRoot
        foreach ($file in @(Find-IndicatorFiles $env:TEMP 'k2f*' -MaxDepth 3)) {
            if ($file.Name -notmatch '^k2f[-_](?:bcreds|keyscan|screen)[-_]') { continue }
            if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                Add-Issue "Lien temporaire ignoré : $($file.FullName)"
                continue
            }
            # Inspect names only; these files may contain secrets.
            $recognized = Test-AgentTempName $file.Name
            $type = if ($recognized) {
                'Fichier'
            } else {
                'Observation'
            }
            Add-Finding 'Fichier temporaire portant un nom signalé' $file.FullName $recognized $type @{
                Path = $file.FullName
            }
        }
    } catch {
        Add-Issue 'Vérification des noms de fichiers temporaires incomplète.'
    }
    Test-LegacyQuarantine
}

function Get-NikkeResidualPaths {
    # Read known log names only, never account files.
    if ($env:APPDATA) {
        Join-Path $env:APPDATA 'nikke_launcher'
        Join-Path $env:APPDATA 'nikke_launcher_hmt'
        Join-Path $env:APPDATA 'nikke_launcher_google'
    }
    if ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA 'NIKKE'
        foreach ($name in @('nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google')) {
            Join-Path $env:LOCALAPPDATA $name
        }
    }
}

function Initialize-CacheReader {
    if ('NikkeTrace.CacheReader27' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace NikkeTrace {
    public sealed class CacheEvidence {
        public string[] Markers;
        public bool Complete;
    }

    public static class CacheReader27 {
        const int Limit = 64 * 1024 * 1024;
        static readonly string[] AgentMarkers = { "k2f.agent.state", "k2f_chan", "k2f.agent" };
        static readonly Regex Domains = new Regex(@"(?<![a-z0-9._-])(?:analytics\.insightjs\.com|insightjs\.com|insightjs\.org)(?![a-z0-9._-])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        static readonly uint[] CrcTable = MakeCrcTable();

        static uint[] MakeCrcTable() {
            uint[] table = new uint[256];
            for (uint i = 0; i < table.Length; i++) {
                uint c = i;
                for (int bit = 0; bit < 8; bit++) c = (c & 1) != 0 ? (c >> 1) ^ 0x82f63b78U : c >> 1;
                table[i] = c;
            }
            return table;
        }

        static void Find(byte[] bytes, int start, int count, HashSet<string> found) {
            string text = Encoding.ASCII.GetString(bytes, start, count);
            foreach (string marker in AgentMarkers) {
                if (text.IndexOf(marker, StringComparison.Ordinal) >= 0) { found.Add(marker); break; }
            }
            foreach (Match match in Domains.Matches(text)) found.Add(match.Value.ToLowerInvariant());
            // UTF-16 cache records can start at either byte alignment.
            for (int alignment = 0; alignment < 2; alignment++) {
                if (count <= alignment) continue;
                text = Encoding.Unicode.GetString(bytes, start + alignment, (count - alignment) & ~1);
                foreach (string marker in AgentMarkers) {
                    if (text.IndexOf(marker, StringComparison.Ordinal) >= 0) { found.Add(marker); break; }
                }
                foreach (Match match in Domains.Matches(text)) found.Add(match.Value.ToLowerInvariant());
            }
        }

        static ulong Varint(byte[] bytes, ref int position, int end) {
            ulong result = 0;
            for (int shift = 0; shift <= 63; shift += 7) {
                if (position >= end) throw new InvalidDataException("Truncated varint.");
                byte value = bytes[position++];
                if (shift == 63 && (value & 254) != 0) throw new InvalidDataException("Varint overflow.");
                result |= (ulong)(value & 127) << shift;
                if (value < 128) return result;
            }
            throw new InvalidDataException("Invalid varint.");
        }

        static byte[] Snappy(byte[] bytes, int start, int end, int available) {
            int position = start;
            ulong declared = Varint(bytes, ref position, end);
            if (declared > (ulong)available) throw new InvalidDataException("Expansion limit.");
            byte[] output = new byte[(int)declared];
            int written = 0;
            while (position < end) {
                int tag = bytes[position++];
                int kind = tag & 3;
                ulong length;
                if (kind == 0) {
                    length = (ulong)(tag >> 2);
                    if (length >= 60) {
                        int width = (int)length - 59;
                        if (width > end - position) throw new InvalidDataException("Truncated literal length.");
                        length = 0;
                        for (int i = 0; i < width; i++) length |= (ulong)bytes[position++] << (8 * i);
                    }
                    length++;
                    if (length > (ulong)(end - position) || length > (ulong)(output.Length - written)) throw new InvalidDataException("Invalid literal.");
                    Buffer.BlockCopy(bytes, position, output, written, (int)length);
                    position += (int)length;
                    written += (int)length;
                } else {
                    int width = kind == 1 ? 1 : kind == 2 ? 2 : 4;
                    if (width > end - position) throw new InvalidDataException("Truncated copy.");
                    ulong distance = 0;
                    for (int i = 0; i < width; i++) distance |= (ulong)bytes[position++] << (8 * i);
                    length = (ulong)(kind == 1 ? ((tag >> 2) & 7) + 4 : (tag >> 2) + 1);
                    if (kind == 1) distance |= (ulong)(tag >> 5) << 8;
                    if (distance == 0 || distance > (ulong)written || length > (ulong)(output.Length - written)) throw new InvalidDataException("Invalid copy.");
                    for (ulong i = 0; i < length; i++) { output[written] = output[written - (int)distance]; written++; }
                }
            }
            if (written != output.Length) throw new InvalidDataException("Incomplete Snappy output.");
            return output;
        }

        static byte[] Block(byte[] file, ulong offset, ulong size, ref int available) {
            if (file.Length < 48 || offset > (ulong)(file.Length - 48) || size > (ulong)(file.Length - 48) - offset || size + 5 > (ulong)(file.Length - 48) - offset) throw new InvalidDataException("Invalid block handle.");
            int start = (int)offset, end = start + (int)size;
            uint crc = UInt32.MaxValue;
            for (int i = start; i <= end; i++) crc = CrcTable[(crc ^ file[i]) & 255] ^ (crc >> 8);
            crc = ~crc;
            uint masked = unchecked(((crc >> 15) | (crc << 17)) + 0xa282ead8U);
            if (BitConverter.ToUInt32(file, end + 1) != masked) throw new InvalidDataException("Block checksum mismatch.");
            byte[] output;
            if (file[end] == 0) {
                if (size > (ulong)available) throw new InvalidDataException("Expansion limit.");
                output = new byte[(int)size];
                Buffer.BlockCopy(file, start, output, 0, output.Length);
            } else if (file[end] == 1) output = Snappy(file, start, end, available);
            else throw new InvalidDataException("Unsupported table compression.");
            available -= output.Length;
            return output;
        }

        static void Records(byte[] block, Action<byte[], byte[], int, int> visit, ref int available) {
            if (block.Length < 8) throw new InvalidDataException("Truncated block.");
            uint restarts = BitConverter.ToUInt32(block, block.Length - 4);
            if (restarts == 0 || restarts > (block.Length - 4) / 4) throw new InvalidDataException("Invalid restarts.");
            int end = block.Length - 4 - (int)restarts * 4;
            uint previous = 0;
            for (int i = 0; i < restarts; i++) {
                uint restart = BitConverter.ToUInt32(block, end + i * 4);
                if ((i == 0 && restart != 0) || restart > end || (i > 0 && restart <= previous)) throw new InvalidDataException("Invalid restart offset.");
                previous = restart;
            }
            int position = 0, records = 0;
            byte[] key = new byte[0];
            while (position < end) {
                if (++records > 100000) throw new InvalidDataException("Record limit.");
                ulong shared = Varint(block, ref position, end);
                ulong own = Varint(block, ref position, end);
                ulong size = Varint(block, ref position, end);
                if (shared > (ulong)key.Length || own > (ulong)(end - position) || size > (ulong)(end - position) - own || shared + own > 1024 * 1024 || shared + own > (ulong)available) throw new InvalidDataException("Invalid record.");
                byte[] next = new byte[(int)(shared + own)];
                Buffer.BlockCopy(key, 0, next, 0, (int)shared);
                Buffer.BlockCopy(block, position, next, (int)shared, (int)own);
                available -= next.Length;
                position += (int)own;
                key = next;
                visit(key, block, position, (int)size);
                position += (int)size;
            }
        }

        public static CacheEvidence Inspect(byte[] file, bool table) {
            HashSet<string> found = new HashSet<string>(StringComparer.Ordinal);
            bool complete = true;
            if (file.Length > Limit) throw new InvalidDataException("File size limit.");
            Find(file, 0, file.Length, found);
            if (table) {
                try {
                    if (file.Length < 48 || BitConverter.ToUInt64(file, file.Length - 8) != 0xdb4775248b80fb57UL) throw new InvalidDataException("Invalid table footer.");
                    int position = file.Length - 48;
                    Varint(file, ref position, file.Length - 8);
                    Varint(file, ref position, file.Length - 8);
                    ulong indexOffset = Varint(file, ref position, file.Length - 8);
                    ulong indexSize = Varint(file, ref position, file.Length - 8);
                    int budget = Limit;
                    byte[] index = Block(file, indexOffset, indexSize, ref budget);
                    List<ulong[]> handles = new List<ulong[]>();
                    Records(index, delegate(byte[] key, byte[] data, int at, int count) {
                        if (handles.Count >= 8192) throw new InvalidDataException("Block count limit.");
                        int stop = at + count;
                        ulong offset = Varint(data, ref at, stop), size = Varint(data, ref at, stop);
                        if (at != stop) throw new InvalidDataException("Invalid block handle record.");
                        handles.Add(new ulong[] { offset, size });
                    }, ref budget);
                    HashSet<ulong> visited = new HashSet<ulong>();
                    foreach (ulong[] handle in handles) {
                        try {
                            if (!visited.Add(handle[0]) || handle[0] >= indexOffset) throw new InvalidDataException("Repeated or invalid data block.");
                            byte[] block = Block(file, handle[0], handle[1], ref budget);
                            Records(block, delegate(byte[] key, byte[] data, int at, int count) { Find(key, 0, key.Length, found); Find(data, at, count, found); }, ref budget);
                        } catch (InvalidDataException) { complete = false; }
                    }
                } catch (InvalidDataException) { complete = false; }
            }
            string[] markers = new string[found.Count];
            found.CopyTo(markers);
            Array.Sort(markers, StringComparer.Ordinal);
            return new CacheEvidence { Markers = markers, Complete = complete };
        }
    }

    public static class CacheDelete27 {
        [StructLayout(LayoutKind.Sequential)]
        struct AttributeTag { public uint Attributes; public uint Tag; }
        [StructLayout(LayoutKind.Sequential)]
        struct Disposition { public byte DeleteFile; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, out AttributeTag data, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind, ref Disposition data, uint size);

        static SafeFileHandle Hold(string path) {
            // Excluding share-delete keeps this directory from being replaced while its children are examined.
            SafeFileHandle handle = CreateFile(path, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
            AttributeTag info;
            if (!GetFileInformationByHandleEx(handle, 9, out info, 8) || (info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0) {
                handle.Dispose();
                throw new IOException("Unsafe or unreadable cache directory.");
            }
            return handle;
        }

        static void Walk(string path, bool delete, int depth, ref int count) {
            if (depth > 64 || ++count > 50000) throw new IOException("Cache traversal limit.");
            using (SafeFileHandle held = Hold(path)) {
                foreach (string child in Directory.EnumerateFileSystemEntries(path)) {
                    FileAttributes attributes = File.GetAttributes(child);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Cache contains a redirected file or directory.");
                    if ((attributes & FileAttributes.Directory) != 0) Walk(child, delete, depth + 1, ref count);
                    else {
                        if (++count > 50000) throw new IOException("Cache traversal limit.");
                        if (delete) File.Delete(child);
                    }
                }
            }
            // This is never recursive; a newly substituted link cannot cause traversal outside the cache.
            if (delete) Directory.Delete(path, false);
        }

        public static void DeleteArtifact(string path, string expectedHash) {
            path = Path.GetFullPath(path);
            List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
            try {
                List<string> parents = new List<string>();
                string parent = Path.GetDirectoryName(path);
                while (!String.IsNullOrEmpty(parent)) { parents.Add(parent); parent = Path.GetDirectoryName(parent); }
                parents.Reverse();
                foreach (string directory in parents) ancestors.Add(Hold(directory));
                // Keep the same file open for validation and deletion; deny writes and replacement.
                using (SafeFileHandle file = CreateFile(path, 0x80010080, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero)) {
                    if (file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                    AttributeTag info;
                    if (!GetFileInformationByHandleEx(file, 9, out info, 8) || (info.Attributes & 0x410) != 0)
                        throw new IOException("Redirected files and directories cannot be deleted.");
                    using (FileStream stream = new FileStream(file, FileAccess.Read)) {
                        if (!String.IsNullOrEmpty(expectedHash)) {
                            if (stream.Length > 64 * 1024 * 1024) throw new IOException("File size changed beyond the validation limit.");
                            using (System.Security.Cryptography.SHA256 hash = System.Security.Cryptography.SHA256.Create()) {
                                string actual = BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "");
                                if (!String.Equals(actual, expectedHash, StringComparison.OrdinalIgnoreCase))
                                    throw new IOException("File changed since the check; deletion refused.");
                            }
                        }
                        Disposition disposition = new Disposition { DeleteFile = 1 };
                        if (!SetFileInformationByHandle(file, 4, ref disposition, 1))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }
                if (File.Exists(path) || Directory.Exists(path)) throw new IOException("File deletion could not be confirmed.");
            } finally {
                for (int i = ancestors.Count - 1; i >= 0; i--) ancestors[i].Dispose();
            }
        }

        public static void Run(string root, bool delete) {
            root = Path.GetFullPath(root);
            List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
            try {
                string parent = Path.GetDirectoryName(root);
                List<string> paths = new List<string>();
                while (!String.IsNullOrEmpty(parent)) { paths.Add(parent); parent = Path.GetDirectoryName(parent); }
                paths.Reverse();
                foreach (string path in paths) ancestors.Add(Hold(path));
                int count = 0;
                Walk(root, delete, 0, ref count);
            } finally {
                for (int i = ancestors.Count - 1; i >= 0; i--) ancestors[i].Dispose();
            }
        }
    }
}

'@ -ErrorAction Stop
}

function Get-LauncherCacheRoots {
    if (-not $env:APPDATA) {
        throw 'Dossier AppData du lanceur indisponible.'
    }
    foreach ($name in @('nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google')) {
        Join-Path $env:APPDATA "$name\tbs_cache"
    }
}

function Get-CacheLocations {
    foreach ($root in @(Get-LauncherCacheRoots)) {
        [pscustomobject]@{
            Path = $root
            Shared = $false
        }
    }
    if ($env:LOCALAPPDATA) {
        foreach ($name in @('nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google')) {
            [pscustomobject]@{
                Path = (Join-Path $env:LOCALAPPDATA "$name\tbs_cache")
                Shared = $true
            }
        }
        [pscustomobject]@{
            Path = (Join-Path $env:LOCALAPPDATA 'CEF\User Data')
            Shared = $true
        }
    } else {
        Add-Issue 'Dossier du profil CEF indisponible.'
    }
}

function Get-CacheFiles([string]$Root) {
    Assert-NoReparsePoint $Root
    $cacheProfiles = @($Root)
    $cacheProfiles += @(Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction Stop |
        Where-Object {
            $_.Name -match '^(Default|Profile \d+)$'
        } | ForEach-Object {
            Assert-NoReparsePoint $_.FullName
            $_.FullName
        })
    foreach ($cacheProfile in $cacheProfiles) {
        $db = Join-Path $cacheProfile 'Local Storage\leveldb'
        if ($null -ne (Get-LocalItem $db)) {
            Assert-NoReparsePoint $db
            Get-ChildItem -LiteralPath $db -File -Force -ErrorAction Stop | Where-Object {
                $_.Extension -in @('.log', '.ldb', '.sst')
            }
        }
        foreach ($name in @('Code Cache', 'Cache')) {
            $path = Join-Path $cacheProfile $name
            if ($null -ne (Get-LocalItem $path)) {
                Assert-NoReparsePoint $path
                Find-IndicatorFiles $path '*' -MaxDepth 5
            }
        }
        foreach ($folder in @($cacheProfile, (Join-Path $cacheProfile 'Network'))) {
            foreach ($name in @('TransportSecurity', 'Network Persistent State', 'Reporting and NEL')) {
                $item = Get-LocalItem (Join-Path $folder $name)
                if ($null -ne $item) {
                    $item
                }
            }
        }
    }
}

function Get-HstsKey([string]$Domain) {
    $wire = New-Object 'System.Collections.Generic.List[byte]'
    foreach ($label in $Domain.Split('.')) {
        $wire.Add([byte]$label.Length)
        $wire.AddRange([Text.Encoding]::ASCII.GetBytes($label))
    }
    $wire.Add(0)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        [Convert]::ToBase64String($hash.ComputeHash($wire.ToArray()))
    }
    finally {
        $hash.Dispose()
    }
}

function Read-CacheEvidence([string]$Path, [long]$Budget = 64MB) {
    Initialize-CacheReader
    Assert-NoReparsePoint $Path
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        if ($stream.Length -gt [Math]::Min(64MB, $Budget)) {
            throw 'Limite de lecture du cache atteinte.'
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) {
                throw 'Lecture de cache incomplète.'
            }
            $offset += $count
        }
        $result = [NikkeTrace.CacheReader27]::Inspect($bytes, ([IO.Path]::GetExtension($Path) -in @('.ldb', '.sst')))
        if ($stream.Length -ne $bytes.Length) {
            $result.Complete = $false
        }
        $markers = @($result.Markers)
        if ([IO.Path]::GetFileName($Path) -eq 'TransportSecurity') {
            if ($bytes.Length -gt 4MB) {
                throw 'Fichier HSTS trop volumineux.'
            }
            $json = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
            foreach ($domain in @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org')) {
                $key = Get-HstsKey $domain
                $present = $null -ne $json.PSObject.Properties[$key]
                if ($null -ne $json.PSObject.Properties['sts']) {
                    foreach ($entry in @($json.sts)) {
                        if ($null -eq $entry -or $null -eq $entry.PSObject.Properties['host']) {
                            throw 'Fichier HSTS inexploitable.'
                        }
                        if ($null -ne $entry -and $null -ne $entry.PSObject.Properties['host'] -and $entry.host -ceq $key) {
                            $present = $true
                        }
                    }
                }
                if ($present) {
                    $markers += $domain
                }
            }
        }
        [pscustomobject]@{
            Markers = @($markers | Sort-Object -Unique)
            Complete = $result.Complete
            Bytes = $bytes.Length
        }
    } finally {
        $stream.Dispose()
    }
}

function Test-LauncherCache {
    Initialize-CacheReader
    [long]$remaining = 128MB
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($location in @(Get-CacheLocations)) {
        $root = $location.Path
        if ($null -eq (Get-LocalItem $root)) {
            continue
        }
        try {
            Get-CacheFiles $root | ForEach-Object {
                $file = $_
                if (-not $seen.Add($file.FullName)) {
                    return
                }
                if ($seen.Count -gt 512 -or $remaining -le 0) {
                    throw 'Limite globale de lecture du cache atteinte.'
                }
                try {
                    $budget = [Math]::Min(64MB, $remaining)
                    $remaining -= [Math]::Min($file.Length, $budget)
                    $evidence = Read-CacheEvidence $file.FullName $budget
                    if (-not $evidence.Complete) {
                        Add-Issue "Cache partiellement vérifié : $($file.FullName)"
                    }
                    foreach ($marker in $evidence.Markers) {
                        $strong = $marker -in @('k2f.agent.state', 'k2f_chan', 'k2f.agent')
                        Write-Detail "Marqueur de cache : $marker — $($file.FullName)"
                        Add-Finding 'Trace signalée dans le cache du lanceur' $file.FullName $strong 'Historique' @{
                            Path = $file.FullName
                            Marker = $marker
                            Evidence = $marker
                            Storage = $true
                            CacheRoot = $root
                            SharedCache = $location.Shared
                        }
                    }
                } catch {
                    Add-Issue "Cache non lisible ou incomplet : $($file.FullName)"
                }
            }
        } catch {
            Add-Issue "Cache non parcouru complètement : $root"
        }
    }
}

function Invoke-CacheSnapshot {
    $savedFindings = $script:Findings
    $savedSeen = $script:SeenFindings
    $savedIssues = $script:Issues
    $savedQuiet = $script:QuietScan
    $ownFeedback = -not $NoPrompt -and $null -eq $script:ScanFeedback
    try {
        if ($ownFeedback) {
            Start-ScanFeedback -Total 1
        }
        $script:Findings = New-Object 'System.Collections.Generic.List[object]'
        $script:SeenFindings = @{}
        $script:Issues = New-Object 'System.Collections.Generic.List[string]'
        $script:QuietScan = $true
        $check = Invoke-IndependentCheck 'Cache NIKKE et profil CEF : traces connues' {
            Test-LauncherCache
        }
        $rows = @($script:Findings.ToArray())
        if (@($rows | Where-Object {
                    $_.Strong
                }).Count -gt 0) {
            $script:HistoricalExposure = $true
            $script:SessionExposure = $true
        }
        [pscustomobject]@{
            Findings = $rows
            Issues = @($script:Issues.ToArray())
            Checks = @($check)
        }
    } finally {
        if ($ownFeedback) {
            Stop-ScanFeedback
        }
        $script:Findings = $savedFindings
        $script:SeenFindings = $savedSeen
        $script:Issues = $savedIssues
        $script:QuietScan = $savedQuiet
    }
}

function Assert-NikkeCachePath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $allowed = @(Get-LauncherCacheRoots | ForEach-Object {
            [IO.Path]::GetFullPath($_).TrimEnd('\')
        })
    if ($full -notin $allowed) {
        throw 'Ce dossier ne fait pas partie des caches NIKKE autorisés.'
    }
    Assert-NoReparsePoint $full
    if (-not [IO.Directory]::Exists($full)) {
        throw 'Cache NIKKE introuvable.'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'Suppression du cache limitée aux disques locaux fixes.'
    }
    return $full
}

function Assert-LauncherClosed {
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    foreach ($process in @(Get-Process -ErrorAction Stop)) {
        if ($process.ProcessName -match '^(nikke_launcher(?:_hmt|_google)?|nikke|tbs_browser)$' -and $process.SessionId -eq $session) {
            throw 'Fermez NIKKE et son lanceur, puis réessayez. Aucun programme ne sera fermé de force.'
        }
    }
}

function Remove-NikkeCache([string]$Path, [string]$ReportFile) {
    $root = Assert-NikkeCachePath $Path
    $report = [IO.Path]::GetFullPath($ReportFile)
    if ($report.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($report) -or (Get-Item -LiteralPath $report -ErrorAction Stop).Length -eq 0) {
        throw 'Rapport sauvegardé hors du cache requis avant suppression.'
    }
    Assert-NoReparsePoint $report
    Assert-LauncherClosed
    Initialize-CacheReader
    [NikkeTrace.CacheDelete27]::Run($root, $false)
    $staged = $root + '.NikkeTrace-delete-' + [guid]::NewGuid().ToString('N')
    [IO.Directory]::Move($root, $staged)
    try {
        [NikkeTrace.CacheDelete27]::Run($staged, $true)
        if ([IO.Directory]::Exists($staged) -or [IO.Directory]::Exists($root)) {
            throw 'Cache restant ou recréé pendant la suppression.'
        }
    } catch {
        if ([IO.Directory]::Exists($staged)) {
            if (-not [IO.Directory]::Exists($root)) {
                [IO.Directory]::Move($staged, $root)
            }
            else {
                Write-Report "Cache partiellement conservé : $staged" Yellow
            }
        }
        throw
    }
}

function Get-CleanupBootId {
    (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
}

function Get-CleanupStatePath {
    if (-not $env:LOCALAPPDATA) {
        throw 'Dossier local indisponible : nettoyage suspendu.'
    }
    Join-Path $env:LOCALAPPDATA 'NIKKE-Assistance\Workflow\pending.json'
}

function Get-CleanupRestartState {
    $path = Get-CleanupStatePath
    try {
        $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return 'None'
    }
    Assert-NoReparsePoint $path
    if ($file.PSIsContainer -or $file.Length -gt 4096) {
        throw 'État de reprise invalide : nettoyage suspendu.'
    }
    $state = [IO.File]::ReadAllText($path) | ConvertFrom-Json -ErrorAction Stop
    if ($state.Version -ne 1 -or $state.UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or $state.BootId -isnot [string] -or $state.BootId.Length -gt 80) {
        throw 'État de reprise invalide : nettoyage suspendu.'
    }
    if ($state.BootId -ceq (Get-CleanupBootId)) {
        return 'Required'
    }
    return 'Observed'
}

function Save-CleanupRestartState {
    $boot = Get-CleanupBootId
    if ([string]::IsNullOrWhiteSpace($boot)) {
        throw 'Impossible de préparer une reprise fiable après redémarrage.'
    }
    $path = Get-CleanupStatePath
    $folder = [IO.Path]::GetDirectoryName($path)
    [void][IO.Directory]::CreateDirectory($folder)
    Assert-NoReparsePoint $folder
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner($sid)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($sid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    [IO.Directory]::SetAccessControl($folder, $security)
    $temporary = Join-Path $folder ([guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [pscustomobject]@{
            Version = 1
            BootId = $boot
            UserSid = $sid.Value
        } |
        ConvertTo-Json | Set-Content -LiteralPath $temporary -Encoding UTF8 -ErrorAction Stop
        if (Test-Path -LiteralPath $path -ErrorAction Stop) {
            Assert-NoReparsePoint $path
            [IO.File]::Replace($temporary, $path, $null)
        } else {
            [IO.File]::Move($temporary, $path)
        }
    } finally {
        if ([IO.File]::Exists($temporary)) {
            [IO.File]::Delete($temporary)
        }
    }
}

function Clear-CleanupRestartState {
    $path = Get-CleanupStatePath
    if (Test-Path -LiteralPath $path -ErrorAction Stop) {
        Assert-NoReparsePoint $path
        [IO.File]::Delete($path)
    }
}

function Add-CleanupOutcome([string]$Outcome, [string]$Label, [string]$Location) {
    if ($Outcome -eq 'Done') {
        foreach ($previous in $script:CleanupOutcomes) {
            if ($previous.Outcome -eq 'Failed' -and $previous.Location -eq $Location) {
                $previous.Outcome = 'Resolved'
            }
        }
    }
    $script:CleanupOutcomes.Add([pscustomobject]@{
            Outcome = $Outcome; Label = $Label; Location = $Location
        })
}

function Show-RestartInstructions {
    $script:CleanupNeedsRestart = $true
    Write-Report 'NETTOYAGE EN ATTENTE DU REDÉMARRAGE' Yellow
    Write-Report 'Enregistrez vos travaux, redémarrez Windows puis relancez ce même fichier et choisissez la vérification complète.'
    Write-Report 'Les fichiers suspects et le cache du lanceur seront traités après ce redémarrage. Ne relancez pas le jeu ni son lanceur entre-temps.'
    Write-Report 'NikkeTrace ne redémarre pas le PC et ne lance rien automatiquement au démarrage.'
    Show-AccountPriority
    Save-Report
}

function Invoke-GuidedCleanup {
    $beforeFailed = @($script:CleanupOutcomes | Where-Object {
            $_.Outcome -eq 'Failed'
        }).Count
    try {
        $result = Invoke-GuidedCleanupCore
        if ($result -isnot [string] -or $result -notin @('Failed', 'Completed', 'RestartRequired', 'Declined', 'NoAction')) {
            throw 'Unexpected cleanup result.'
        }
    } catch {
        $result = 'Failed'
        Write-Report 'Nettoyage interrompu : aucun résultat global ne peut être confirmé. Consultez le rapport.' Yellow
        Write-Detail $_.Exception.Message
    }
    if ($result -eq 'Failed' -and @($script:CleanupOutcomes | Where-Object {
                $_.Outcome -eq 'Failed'
            }).Count -eq $beforeFailed) {
        Add-CleanupOutcome 'Failed' 'Nettoyage interrompu ou non confirmé' 'Workflow'
    }
    if ($result -in @('Completed', 'NoAction')) {
        foreach ($previous in $script:CleanupOutcomes) {
            if ($previous.Outcome -eq 'Failed' -and $previous.Location -eq 'Workflow') {
                $previous.Outcome = 'Resolved'
            }
        }
    }
    return $result
}

function Invoke-GuidedCleanupCore {
    try {
        $restart = Get-CleanupRestartState
    }
    catch {
        Write-Report 'La reprise du nettoyage ne peut pas être vérifiée. Aucun fichier ne sera retiré.' Yellow
        Write-Detail $_.Exception.Message
        return 'Failed'
    }
    $script:CleanupNeedsRestart = ($restart -eq 'Required')
    if ($restart -eq 'Required') {
        Show-RestartInstructions
        return 'RestartRequired'
    }
    $roots = New-Object 'System.Collections.Generic.List[string]'
    try {
        foreach ($path in @(Get-LauncherCacheRoots)) {
            if ($null -ne (Get-LocalItem $path)) {
                $roots.Add((Assert-NikkeCachePath $path))
            }
        }
    } catch {
        Write-Report 'Un cache ne peut pas être traité automatiquement. Les autres actions restent disponibles.' Yellow
        Write-Detail $_.Exception.Message
    }
    $beforeCache = Invoke-CacheSnapshot
    if ($null -ne $script:CurrentSnapshot) {
        $previousCache = [pscustomobject]@{
            Findings = @($script:CurrentSnapshot.Findings | Where-Object {
                    $_.Target.ContainsKey('Storage')
                })
        }
        [void](Compare-TraceSnapshots $previousCache $beforeCache)
    }
    $snapshot = if ($null -ne $script:CurrentSnapshot) {
        $script:CurrentSnapshot
    } else {
        $beforeCache
    }
    $plan = @(Get-CleanupPlan $snapshot)
    $registry = @($plan | Where-Object {
            $_.Action -eq 'Registre'
        })
    $files = @($plan | Where-Object {
            $_.Action -eq 'Suppression'
        })
    $games = @(Get-NikkeRemovalCandidates)
    if ($plan.Count -eq 0 -and $roots.Count -eq 0 -and $games.Count -eq 0) {
        Write-Report 'Aucun nettoyage à proposer pour ce résultat.'
        if ($restart -eq 'Observed') {
            Clear-CleanupRestartState
        }
        return 'NoAction'
    }
    Write-Report ''
    Write-Report 'NETTOYAGE PROPOSÉ — VOTRE ACCORD EST NÉCESSAIRE' Cyan
    if ($plan.Count -eq 0 -and $roots.Count -gt 0) {
        Write-Report 'Aucune trace actuelle à retirer automatiquement. La réinitialisation du cache est proposée par précaution.'
    }
    foreach ($action in $plan) {
        $label = if ($action.Action -eq 'Registre') {
            'Élément de démarrage suspect à retirer'
        } else {
            'Fichier ciblé à supprimer définitivement, sans copie de récupération'
        }
        Write-Report $label
        Write-Detail "Action prévue : $($action.Action) — $($action.Finding.Location)"
    }
    if ($roots.Count -gt 0) {
        Write-Report "Caches du lanceur à réinitialiser : $($roots.Count)."
    }
    foreach ($path in $roots) {
        Write-Detail "Cache NIKKE proposé à la suppression : $path"
    }
    if ($roots.Count -gt 0) {
        Write-Report 'Suppression définitive du cache : vous pourrez être déconnecté et les réglages du lanceur seront réinitialisés.' Yellow
        Write-Report 'Le rapport conserve les traces détectées, pas une copie des fichiers du cache.'
    }
    if ($files.Count -gt 0) {
        Write-Report 'Les fichiers ciblés seront supprimés définitivement, sans copie conservée. Leur liste figure dans le rapport.' Yellow
    }
    Write-Report 'Les données légitimes de vos navigateurs, les autres applications et les éléments non reconnus seront conservés.'
    if ($registry.Count -gt 0) {
        Write-Report 'Étape 1 : retirer l élément de démarrage suspect. Étape 2 : redémarrer Windows avant le traitement des fichiers et du cache.' Yellow
    }
    if ($games.Count -gt 0) {
        Write-Report 'Le retrait du jeu et du lanceur sera proposé séparément. Il ne sera jamais fait sans votre accord.'
    }
    try {
        $unsafeReports = @($roots.ToArray()) + $games
        if ($script:ReportPath -and @($unsafeReports | Where-Object {
                    [IO.Path]::GetFullPath($script:ReportPath).StartsWith($_.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
                }).Count -gt 0) {
            $script:ReportPath = Join-Path $env:LOCALAPPDATA ('NIKKE-Assistance\Reports\Bilan-' + [guid]::NewGuid().ToString('N') + '.txt')
        }
        Save-Report -Required
        if (-not $script:ReportPath -or -not [IO.File]::Exists($script:ReportPath) -or (Get-Item -LiteralPath $script:ReportPath -ErrorAction Stop).Length -eq 0) {
            throw 'Rapport absent.'
        }
        foreach ($path in $unsafeReports) {
            if ([IO.Path]::GetFullPath($script:ReportPath).StartsWith($path.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Rapport situé dans un dossier à retirer.'
            }
        }
    } catch {
        Write-Report 'Rapport non sauvegardé : aucun nettoyage ne sera effectué.' Yellow
        return 'Failed'
    }
    Write-Report "Rapport sauvegardé avant nettoyage : $script:ReportPath"
    if (($plan.Count -gt 0 -or $roots.Count -gt 0) -and -not (Confirm-Action 'Effectuer ce nettoyage guidé ?' -AllowReport)) {
        Write-Report 'Nettoyage refusé : aucun élément modifié.'
        return 'Declined'
    }
    try {
        Assert-LauncherClosed
    }
    catch {
        Write-Report 'Fermez NIKKE et son lanceur, puis réessayez. Aucun programme ne sera fermé de force.' Yellow
        return 'Failed'
    }
    $failed = 0
    if ($registry.Count -gt 0) {
        try {
            $folder = New-RecoveryFolder
            Save-CleanupRestartState
            foreach ($action in $registry) {
                try {
                    $backup = Join-Path $folder ('registry-' + [guid]::NewGuid().ToString('N') + '.xml')
                    if (Remove-KnownRegistryOverride $action.Finding.Target $backup) {
                        Add-CleanupOutcome 'Done' 'Référence du registre retirée et sauvegardée' $action.Finding.Location
                        Write-Report 'Élément de démarrage suspect retiré. Redémarrage nécessaire pour continuer.' Green
                        $script:CurrentSnapshot.Findings = @($script:CurrentSnapshot.Findings | Where-Object {
                                $_.Id -ne $action.Finding.Id
                            })
                    }
                } catch {
                    Add-CleanupOutcome 'Failed' 'Retrait du registre non confirmé' $action.Finding.Location
                    Write-Report 'Le retrait d un élément de démarrage suspect n a pas pu être confirmé. Consultez le rapport.' Yellow
                    Write-Detail $_.Exception.Message
                }
            }
        } catch {
            Write-Report 'La première étape ne peut pas être terminée. Aucun traitement des fichiers suspects ou du cache ne sera tenté.' Yellow
            Write-Detail $_.Exception.Message
            Save-Report
            return 'Failed'
        }
        Show-RestartInstructions
        return 'RestartRequired'
    }
    if ($restart -eq 'Observed') {
        Write-Report 'Redémarrage Windows confirmé : le nettoyage peut continuer.' Cyan
    }
    if ($files.Count -gt 0) {
        foreach ($action in $files) {
            $finding = $action.Finding
            try {
                Remove-ConfirmedFile $finding
                Add-CleanupOutcome 'Done' 'Fichier supprimé définitivement' $finding.Location
                Write-Report 'Fichier supprimé définitivement ; absence confirmée.' Green
                Write-Detail "Fichier supprimé sans copie : $($finding.Location)"
            } catch {
                $failed++
                Add-CleanupOutcome 'Failed' 'Retrait du fichier non confirmé' $finding.Location
                Write-Report 'Un fichier suspect n a pas pu être retiré. Consultez le rapport.' Yellow
                Write-Detail $_.Exception.Message
            }
        }
    }
    foreach ($path in $roots) {
        try {
            Remove-NikkeCache $path $script:ReportPath
            Add-CleanupOutcome 'Done' 'Cache NIKKE supprimé' $path
            Write-Report 'Cache du lanceur supprimé ; absence confirmée.' Green
            Write-Detail "Cache supprimé : $path"
        } catch {
            $failed++
            Add-CleanupOutcome 'Failed' 'Suppression du cache non confirmée' $path
            Write-Report 'Suppression du cache incomplète ou non confirmée.' Yellow
            Write-Detail "Cache concerné : $path"
            Write-Detail $_.Exception.Message
        }
    }
    if (($plan.Count -gt 0 -or $roots.Count -gt 0) -and $null -ne $script:CurrentSnapshot -and $null -ne $script:CurrentSnapshot.PSObject.Properties['ScopeMode']) {
        if (-not (Invoke-PostCleanupCheck)) {
            $failed++
        }
    } elseif ($plan.Count -gt 0 -or $roots.Count -gt 0) {
        $after = Invoke-CacheSnapshot
        [void](Compare-TraceSnapshots $beforeCache $after)
        $script:CurrentSnapshot = $after
        if ($after.Findings.Count -gt 0) {
            Write-Report 'TRACES ENCORE PRÉSENTES OU À EXAMINER DANS LES CACHES :' Yellow
            foreach ($finding in $after.Findings) {
                Write-Report 'Une trace ancienne reste à examiner ; son emplacement figure dans le rapport.' Yellow
                Write-Detail "Trace conservée : $($finding.Target.Marker) — $($finding.Location)"
            }
        } elseif ($failed -eq 0 -and $after.Checks[0].State -eq 'Effectué') {
            Write-Report 'AUCUNE TRACE CONNUE TROUVÉE DANS LES CACHES VÉRIFIÉS.' Green
        }
        else {
            Write-Report 'Vérification du cache incomplète : aucun nettoyage global ne peut être confirmé.' Yellow
        }
    }
    if ($games.Count -gt 0) {
        $uninstall = Offer-NikkeUninstall $games
        if ($uninstall -eq 'Failed') {
            $failed++
        }
        if ($uninstall -eq 'Declined' -and $plan.Count -eq 0 -and $roots.Count -eq 0) {
            return 'Declined'
        }
    }
    if ($plan.Count -eq 0 -and $roots.Count -eq 0) {
        Save-Report
        return $(if ($failed -gt 0) {
                'Failed'
            } else {
                'NoAction'
            })
    }
    if ($failed -eq 0 -and $restart -eq 'Observed') {
        Clear-CleanupRestartState
    }
    Save-Report
    if ($failed -gt 0) {
        return 'Failed'
    }
    return 'Completed'
}


# Defensive observations only. No network requests, process termination or new cleanup targets.
function Get-DllHashEvidence([string]$Path) {
    if ($script:DllHashCache.ContainsKey($Path)) {
        if (-not $script:DllHashCache[$Path].Hash) {
            Add-Issue "Empreinte DLL non vérifiable : $Path"
        }
        return $script:DllHashCache[$Path]
    }
    $result = [pscustomobject]@{
        Hash = ''
        Known = $false
    }
    try {
        Assert-NoReparsePoint $Path
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -gt 64MB) {
            throw 'DLL non vérifiable dans les limites de lecture.'
        }
        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($hash -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'Empreinte DLL inexploitable.'
        }
        $result.Hash = $hash.ToUpperInvariant()
        $result.Known = $result.Hash -eq '931747D56B9639829AECD5540991D53DF336FF4E93B30C7DB0C8DF7A6038942E'
        Write-Detail "Empreinte SHA-256 DLL : $Path — $($result.Hash)"
        if (-not $result.Known) {
            Write-Detail 'Empreinte DLL différente du signalement : une variante reste possible.'
        }
    } catch {
        Add-Issue "Empreinte DLL non vérifiable : $Path"
    }
    $script:DllHashCache[$Path] = $result
    return $result
}

function Get-AdditionalChromeRoots {
    if ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\PlatformExperienceHelper'
    }
    foreach ($base in @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)}) | Sort-Object -Unique) {
        if ($base) {
            Join-Path $base 'Google\Chrome\Application\PlatformExperienceHelper'
        }
    }
}

function Get-SessionProcesses {
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $names = @('nikke', 'nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google', 'tbs_browser', 'chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 'steamwebhelper', 'runeapps.alt1')
    Get-Process -ErrorAction Stop | Where-Object {
        $_.SessionId -eq $session -and $_.ProcessName -in $names
    }
}

function Get-ProcessModuleRows($Process) {
    $Process.Refresh()
    $Process.Modules
}

function Test-LoadedModules {
    $processes = @(Get-SessionProcesses)
    if ($processes.Count -eq 0) {
        Write-Detail 'Aucun programme ciblé par cet incident n était ouvert au moment du contrôle.'
        return
    }
    $unreadable = New-Object 'System.Collections.Generic.List[string]'
    foreach ($process in $processes) {
        try {
            if (-not $process.PSObject.Properties['Id']) {
                throw 'Processus inexploitable.'
            }
            $processNumber = [int]$process.Id
            $modules = @(Get-ProcessModuleRows $process)
            if ($modules.Count -eq 0) {
                throw 'Liste des modules vide ou indisponible.'
            }
            foreach ($module in $modules) {
                if (-not $module.PSObject.Properties['ModuleName'] -or [string]::IsNullOrWhiteSpace($module.ModuleName)) {
                    throw 'Module inexploitable.'
                }
                if ($module.ModuleName -ine 'platform_experience_helper.dll') {
                    continue
                }
                if (-not $module.PSObject.Properties['FileName'] -or [string]::IsNullOrWhiteSpace($module.FileName)) {
                    throw 'Chemin du module indisponible.'
                }
                $evidence = Get-DllHashEvidence $module.FileName
                $strong = $evidence.Known -or (Test-KnownChromeDllPath $module.FileName)
                Add-Finding 'DLL homonyme chargée dans un processus : vérifier le chemin et l empreinte' "PID $processNumber — $($process.ProcessName) — $($module.FileName)" $strong 'Observation' @{
                    Area = 'Modules'
                    Path = $module.FileName
                    ProcessId = $processNumber
                    ProcessName = $process.ProcessName
                    Sha256 = $evidence.Hash
                    KnownDllHash = $evidence.Known
                }
            }
        } catch {
            $number = if ($process.PSObject.Properties['Id']) {
                [string]$process.Id
            } else {
                '?'
            }
            $name = 'nom indisponible'
            try {
                if ($process.PSObject.Properties['ProcessName'] -and $process.ProcessName) {
                    $name = [string]$process.ProcessName
                }
            } catch {}
            $unreadable.Add("PID $number — $name")
        }
    }
    if ($unreadable.Count -gt 0) {
        Add-Issue "Programmes en cours : $($unreadable.Count) programme(s) non inspecté(s). Cette limite ne signifie pas qu un virus a été trouvé."
        Write-Detail 'Causes possibles : droits Windows, programme protégé, architecture différente ou programme arrêté pendant le contrôle.'
        foreach ($entry in $unreadable) {
            Write-Detail "Détail technique — programme non inspecté : $entry"
        }
    }
    Write-Detail 'Modules : session Windows courante seulement ; processus protégés ou disparus signalés comme non vérifiables.'
}

function Get-LocalTcpRows {
    Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetTCPConnection' -OperationTimeoutSec 10 -ErrorAction Stop
}

function Test-TcpConnections {
    foreach ($row in @(Get-LocalTcpRows)) {
        foreach ($property in @('RemoteAddress', 'RemotePort', 'State', 'OwningProcess')) {
            if ($null -eq $row -or -not $row.PSObject.Properties[$property]) {
                throw 'Réponse TCP inexploitable.'
            }
        }
        $address = [Net.IPAddress]::Parse([string]$row.RemoteAddress)
        $state = [int]$row.State
        if (($state -lt 1 -or $state -gt 12) -and $state -ne 100) {
            throw 'État TCP inexploitable.'
        }
        if ($address.IsIPv4MappedToIPv6) {
            $address = $address.MapToIPv4()
        }
        if ($address.ToString() -ne '89.127.233.127') {
            continue
        }
        $port = [int]$row.RemotePort
        $ownerNumber = [int]$row.OwningProcess
        $kind = if ($state -eq 11) {
            'Connexion TCP résiduelle TIME_WAIT vers l IP signalée'
        } else {
            'Connexion TCP vers l IP signalée : ne prouve pas une infection'
        }
        Add-Finding $kind "89.127.233.127:$port — PID $ownerNumber — TCP $state" $false 'Observation' @{
            Area = 'Réseau'
            Marker = '89.127.233.127'
            State = $state
            ProcessId = $ownerNumber
        }
    }
}

function Get-LocalDnsRows {
    Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_DNSClientCache' -OperationTimeoutSec 10 -ErrorAction Stop
}

function Test-ReportedDomain([string]$Name) {
    $nameValue = $Name.Trim().TrimEnd('.').ToLowerInvariant()
    return $nameValue -match '^(?:[a-z0-9-]+\.)*insightjs\.(?:com|org)$'
}

function Test-DnsCache {
    foreach ($row in @(Get-LocalDnsRows)) {
        foreach ($property in @('Entry', 'Name', 'Data')) {
            if ($null -eq $row -or -not $row.PSObject.Properties[$property]) {
                throw 'Réponse DNS inexploitable.'
            }
        }
        if ([string]::IsNullOrWhiteSpace($row.Entry) -and [string]::IsNullOrWhiteSpace($row.Name)) {
            throw 'Réponse DNS inexploitable.'
        }
        if ([string]$row.Data -in @('0.0.0.0', '127.0.0.1', '::', '::1')) {
            continue
        }
        $domainHit = @($row.Entry, $row.Name, $row.Data | Where-Object {
                Test-ReportedDomain ([string]$_)
            }).Count -gt 0
        $ipHit = [string]$row.Data -eq '89.127.233.127' -or [string]$row.Data -eq '::ffff:89.127.233.127'
        if ($domainHit -or $ipHit) {
            # Keep fixed markers only; unrelated browsing history is never written to the report.
            $marker = if ($domainHit) {
                'insightjs.com / insightjs.org'
            } else {
                '89.127.233.127'
            }
            Add-Finding 'Référence DNS locale : une consultation ou un blocage peut aussi la créer' $marker $false 'Observation' @{
                Area = 'DNS'
                Marker = $marker
            }
        }
    }
}

function Get-HostsFilePath {
    if (-not $env:SystemRoot) {
        throw 'Dossier Windows indisponible.'
    }
    Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
}

function Test-HostsFile {
    $path = Get-HostsFilePath
    Assert-NoReparsePoint $path
    $info = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($info.PSIsContainer -or $info.Length -gt 4MB) {
        throw 'Fichier hosts non vérifiable dans les limites de lecture.'
    }
    $lineNumber = 0
    foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction Stop)) {
        $lineNumber++
        $content = ($line -split '#', 2)[0].Trim()
        if (-not $content) {
            continue
        }
        $tokens = @($content -split '\s+')
        if ($tokens.Count -lt 2) {
            throw 'Ligne hosts inexploitable.'
        }
        $address = [Net.IPAddress]::Parse($tokens[0])
        foreach ($name in $tokens[1..($tokens.Count - 1)]) {
            if (-not (Test-ReportedDomain $name)) {
                continue
            }
            $blocking = $address.ToString() -in @('0.0.0.0', '127.0.0.1', '::', '::1')
            $kind = if ($blocking) {
                'Domaine signalé bloqué dans hosts : ce blocage ne prouve pas une infection'
            } else {
                'Domaine signalé redirigé dans hosts : à examiner'
            }
            if ($blocking) {
                Write-Detail "Domaine déjà bloqué dans hosts : $name"
                continue
            }
            Add-Finding $kind "$path (ligne $lineNumber)" $false 'Observation' @{
                Area = 'Hosts'
                Marker = $name
                Blocking = $false
            }
        }
    }
}

function Show-ExtendedChecks($Snapshot) {
    Write-Report 'CONTRÔLES COMPLÉMENTAIRES — OBSERVATIONS LOCALES' Cyan
    foreach ($pair in @(@('Modules', 'Programmes en cours*'), @('Réseau', 'Connexions TCP*'), @('DNS', 'Cache DNS*'), @('Hosts', 'Fichier hosts*'))) {
        $rows = @($Snapshot.Findings | Where-Object {
                $_.Target.ContainsKey('Area') -and $_.Target.Area -eq $pair[0]
            })
        $label = if ($pair[0] -eq 'Modules') {
            'Programmes en cours'
        } else {
            $pair[0]
        }
        $reason = if ($pair[0] -eq 'Modules') {
            'vérification partielle ; cette limite seule ne signale pas un virus — détails dans le rapport'
        } else {
            ''
        }
        Write-AreaSummary $label $rows (Get-CheckComplete $Snapshot $pair[1]) $reason
    }
    Write-Report '  Réseau, DNS et hosts : un indice seul ne prouve pas une infection ; aucune connexion externe lancée.'
}


function Start-ScanFeedback([int]$Total = $(if ($Mode -in @('Verifier', 'SansJeu')) {
            9
        } else {
            8
        })) {
    $script:ScanFeedback = $null
    if ($NoPrompt) {
        return
    }
    $state = [hashtable]::Synchronized(@{
            Phase = ''; Started = [datetime]::UtcNow
        })
    $stop = [Threading.ManualResetEventSlim]::new($false)
    $worker = [PowerShell]::Create()
    try {
        [void]$worker.AddScript({
                param($State, $Stop, $Waiting, $Delayed)
                while (-not $Stop.Wait(10000)) {
                    $phase = $State.Phase
                    if (-not $phase) {
                        continue
                    }
                    $seconds = [int]([datetime]::UtcNow - $State.Started).TotalSeconds
                    [Console]::WriteLine(($Waiting -f $phase, $seconds))
                    if ($seconds -ge 60) {
                        [Console]::WriteLine($Delayed)
                    }
                }
            }).AddArgument($state).AddArgument($stop).AddArgument((Convert-UiText '  Toujours en attente : {0} ({1} s).')).AddArgument((Convert-UiText '  Attente prolongée. Ctrl+C permet d interrompre ; un contrôle interrompu ne confirme aucun résultat.'))
        $handle = $worker.BeginInvoke()
        $script:ScanFeedback = @{
            State = $state
            Stop = $stop
            Worker = $worker
            Handle = $handle
            Step = 0
            Total = $Total
        }
    } catch {
        $worker.Dispose()
        $stop.Dispose()
        Write-Host 'Le rappel périodique est indisponible ; les étapes restent affichées.' -ForegroundColor Yellow
    }
}

function Stop-ScanFeedback {
    if ($null -eq $script:ScanFeedback) {
        return
    }
    $feedback = $script:ScanFeedback
    $script:ScanFeedback = $null
    try {
        $feedback.Stop.Set()
        $feedback.Worker.EndInvoke($feedback.Handle) | Out-Null
    } finally {
        $feedback.Worker.Dispose()
        $feedback.Stop.Dispose()
    }
}

function Invoke-IndependentCheck([string]$Name, [scriptblock]$Action) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $label = $Name
    if ($null -ne $script:ScanFeedback) {
        $labels = @{
            'Journaux NIKKE disponibles' = 'Anciens journaux NIKKE'
            'Fichiers des navigateurs sélectionnés' = 'Dossiers des navigateurs'
            'Registre HKCU/HKLM, vues 32/64 bits' = 'Références de démarrage connues'
            'Fichiers temporaires signalés' = 'Fichiers temporaires signalés'
            'Cache NIKKE et profil CEF : traces connues' = 'Données temporaires du lanceur'
            'Programmes en cours (DLL chargées)' = 'Traces dans les applications ouvertes'
            'Connexions TCP actuelles' = 'Connexions locales vers l adresse signalée'
            'Cache DNS local' = 'Références locales aux sites signalés'
            'Fichier hosts Windows' = 'Blocages des sites déjà présents'
        }
        if ($labels.ContainsKey($Name)) {
            $label = $labels[$Name]
        }
        $script:ScanFeedback.Step++
        $script:ScanFeedback.State.Started = [datetime]::UtcNow
        $script:ScanFeedback.State.Phase = Convert-UiText $label
        Write-Host ('[{0}/{1}] {2}...' -f $script:ScanFeedback.Step, $script:ScanFeedback.Total, (Convert-UiText $label)) -ForegroundColor Cyan
    }
    Write-Detail ('Début du contrôle : {0}' -f $Name)
    if ($null -ne $script:ScanFeedback) {
        Save-Report
    }
    $beforeIssues = $script:Issues.Count
    try {
        & $Action | Out-Null
    }
    catch {
        Add-Issue "$Name : contrôle interrompu ($($_.Exception.Message)). Les autres contrôles continuent."
    }
    $state = if ($script:Issues.Count -gt $beforeIssues) {
        'Partiel'
    } else {
        'Effectué'
    }
    $watch.Stop()
    $seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 1)
    if ($null -ne $script:ScanFeedback) {
        $script:ScanFeedback.State.Phase = ''
        if ($state -eq 'Partiel') {
            Write-Host ('  Contrôle terminé avec une limite ({0} s) ; détail dans le rapport.' -f $seconds) -ForegroundColor Yellow
        } else {
            Write-Host ('  Contrôle terminé ({0} s).' -f $seconds)
        }
    }
    Write-Report "[CONTRÔLE] $Name : $state"
    Write-Detail ('Durée du contrôle : {0} — {1} s' -f $Name, $seconds)
    if ($null -ne $script:ScanFeedback) {
        Save-Report
    }
    return [pscustomobject]@{
        Name = $Name
        State = $state
        DurationSeconds = $seconds
        Reasons = @($script:Issues.ToArray() | Select-Object -Skip $beforeIssues)
    }
}

function Invoke-TraceScan {
    $script:CurrentSnapshot = $null
    $script:Findings = New-Object 'System.Collections.Generic.List[object]'
    $script:SeenFindings = @{}
    $script:BrowserCheckMap = @{}
    $script:Issues = New-Object 'System.Collections.Generic.List[string]'
    $script:SeenLogs = @{}
    $script:DllHashCache = @{}
    $script:LogsRead = 0
    $script:BrowserRoots = 0
    $script:BrowserNames = New-Object 'System.Collections.Generic.List[string]'
    $script:QuietScan = $true
    try {
        Start-ScanFeedback
        Write-Report "--- Contrôle du $(Get-Date -Format 'HH:mm:ss') ---"
        $checks = New-Object 'System.Collections.Generic.List[object]'
        if ($Mode -in @('Verifier', 'SansJeu')) {
            $checks.Add((Invoke-IndependentCheck 'Journaux NIKKE disponibles' {
                        foreach ($issue in $script:DiscoveryIssues) {
                            Add-Issue $issue
                        }
                        foreach ($path in $script:ScanPaths) {
                            try {
                                Test-NikkePath $path
                            }
                            catch {
                                Add-Issue "Journal ou dossier non vérifiable : $path"
                            }
                        }
                        if ($script:LogsRead -eq 0) {
                            Add-Issue 'Aucun journal NIKKE lisible : exposition passée indéterminée, même après désinstallation.'
                        }
                    }))
        } else {
            $checks.Add([pscustomobject]@{
                    Name = 'Journaux NIKKE disponibles'; State = 'Non demandé dans ce mode'
                })
        }
        $checks.Add((Invoke-IndependentCheck 'Fichiers des navigateurs sélectionnés' {
                    Test-BrowserFiles
                    if ($script:BrowserRoots -eq 0) {
                        Add-Issue 'Aucun profil habituel trouvé pour les navigateurs sélectionnés ; profils personnalisés non couverts.'
                    }
                }))
        $checks.Add((Invoke-IndependentCheck 'Registre HKCU/HKLM, vues 32/64 bits' {
                    Test-Persistence
                }))
        $checks.Add((Invoke-IndependentCheck 'Fichiers temporaires signalés' {
                    Test-TemporaryFiles
                }))
        $checks.Add((Invoke-IndependentCheck 'Cache NIKKE et profil CEF : traces connues' {
                    Test-LauncherCache
                }))
        $checks.Add((Invoke-IndependentCheck 'Programmes en cours (DLL chargées)' {
                    Test-LoadedModules
                }))
        $checks.Add((Invoke-IndependentCheck 'Connexions TCP actuelles' {
                    Test-TcpConnections
                }))
        $checks.Add((Invoke-IndependentCheck 'Cache DNS local' {
                    Test-DnsCache
                }))
        $checks.Add((Invoke-IndependentCheck 'Fichier hosts Windows' {
                    Test-HostsFile
                }))
        if (@($script:Findings | Where-Object {
                    $_.Type -eq 'Historique' -and $_.Strong
                }).Count -gt 0) {
            $script:HistoricalExposure = $true
            $script:SessionExposure = $true
        }
        return [pscustomobject]@{
            Findings = @($script:Findings.ToArray())
            Issues = @($script:Issues.ToArray())
            LogsRead = $script:LogsRead
            BrowserRoots = $script:BrowserRoots
            HistoryStatus = $(if ($Mode -eq 'Navigateurs') {
                    'NonRecherche'
                } elseif ($script:LogsRead -eq 0) {
                    'Indetermine'
                } else {
                    'Verifie'
                })
            GameRemoved = ($Mode -eq 'SansJeu')
            Checks = @($checks.ToArray())
            ScopeMode = $Mode
            ScopeBrowser = $Navigateur
            CheckedBrowsers = @($script:BrowserNames.ToArray())
            BrowserChecks = @($script:BrowserCheckMap.Values | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Name; State = $_.State; Paths = @($_.Paths.ToArray()); Reasons = @($_.Reasons.ToArray()); Attempted = @($_.Attempted.ToArray())
                    }
                })
        }
    } finally {
        Stop-ScanFeedback
        $script:QuietScan = $false
    }
}

function Read-RegistryArtifact([hashtable]$Target) {
    $base = $null
    $key = $null
    try {
        $hive = [Microsoft.Win32.RegistryHive][Enum]::Parse([Microsoft.Win32.RegistryHive], $Target.Hive)
        $view = [Microsoft.Win32.RegistryView][Enum]::Parse([Microsoft.Win32.RegistryView], $Target.View)
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
        $key = $base.OpenSubKey($Target.SubKey, $false)
        if ($Target.ContainsKey('EmptyClsid') -and $Target.EmptyClsid) {
            if ($null -eq $key) {
                return 'Absent'
            }
            if ($key.GetValueNames().Count -eq 0 -and $key.GetSubKeyNames().Count -eq 0) {
                return 'Present'
            }
            return 'Modifie'
        }
        if ($null -eq $key -or $Target.Name -notin $key.GetValueNames()) {
            return 'Absent'
        }
        $fingerprint = Get-ValueFingerprint ([string]$key.GetValue($Target.Name))
        if ($fingerprint -eq $Target.Fingerprint) {
            return 'Present'
        }
        return 'Modifie'
    } catch {
        return 'Inconnu'
    }
    finally {
        if ($null -ne $key) {
            $key.Dispose()
        }
        if ($null -ne $base) {
            $base.Dispose()
        }
    }
}

function Get-ArtifactState($Finding) {
    if ($Finding.Target.ContainsKey('Storage') -and $Finding.Target.Storage) {
        try {
            if (-not [IO.Directory]::Exists([IO.Path]::GetPathRoot($Finding.Target.Path))) {
                return 'Inconnu'
            }
            $item = Get-Item -LiteralPath $Finding.Target.Path -Force -ErrorAction Stop
            if ($item.PSIsContainer) {
                return 'Inconnu'
            }
            $evidence = Read-CacheEvidence $item.FullName
            if ($Finding.Target.Marker -in $evidence.Markers) {
                return 'Present'
            }
            if (-not $evidence.Complete) {
                return 'Inconnu'
            }
            return 'Absent'
        } catch [System.Management.Automation.ItemNotFoundException] {
            return 'Absent'
        }
        catch {
            return 'Inconnu'
        }
    }

    if ($Finding.Type -eq 'Registre') {
        return Read-RegistryArtifact $Finding.Target
    }
    if ($Finding.Type -ne 'Fichier') {
        return 'Inconnu'
    }
    try {
        $root = [IO.Path]::GetPathRoot($Finding.Target.Path)
        if (-not [IO.Directory]::Exists($root)) {
            return 'Inconnu'
        }
        $item = Get-Item -LiteralPath $Finding.Target.Path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            return 'Inconnu'
        }
        return 'Present'
    } catch [System.Management.Automation.ItemNotFoundException] {
        return 'Absent'
    }
    catch {
        return 'Inconnu'
    }
}

function Compare-TraceSnapshots($Before, $After) {
    $results = New-Object 'System.Collections.Generic.List[object]'
    $previous = @{}
    $current = @{}
    foreach ($f in $After.Findings) {
        if (($f.Type -in @('Fichier', 'Registre') -or ($f.Target.ContainsKey('Storage') -and $f.Target.Storage))) {
            $current[$f.Id] = $true
        }
    }
    foreach ($f in $Before.Findings) {
        if (-not ($f.Type -in @('Fichier', 'Registre') -or ($f.Target.ContainsKey('Storage') -and $f.Target.Storage))) {
            continue
        }
        $previous[$f.Id] = $true
        # Recheck the artifact directly before reporting its removal.
        $state = Get-ArtifactState $f
        $results.Add([pscustomobject]@{
                State = $state; Finding = $f
            })
        if ($state -eq 'Absent') {
            # Prefer the more recent targeted check if another program removed the artifact.
            $After.Findings = @($After.Findings | Where-Object {
                    $_.Id -ne $f.Id
                })
        }
        if ($state -in @('Present', 'Modifie') -and -not $current.ContainsKey($f.Id)) {
            $After.Findings = @($After.Findings) + @($f)
        }
        if ($state -eq 'Inconnu') {
            $After.Issues = @($After.Issues) + @("Trace antérieure non vérifiable : $($f.Location)")
            if (-not $current.ContainsKey($f.Id)) {
                $retained = $f.PSObject.Copy()
                $retained.Target = $f.Target.Clone()
                $retained.Target['Unverified'] = $true
                $After.Findings = @($After.Findings) + @($retained)
            }
        }
    }
    foreach ($f in $After.Findings) {
        if (($f.Type -in @('Fichier', 'Registre') -or ($f.Target.ContainsKey('Storage') -and $f.Target.Storage)) -and -not $previous.ContainsKey($f.Id)) {
            $results.Add([pscustomobject]@{
                    State = 'Nouveau'; Finding = $f
                })
        }
    }
    return $results.ToArray()
}

function Get-FindingArea($Finding) {
    if ($Finding.Target.ContainsKey('SharedCache') -and $Finding.Target.SharedCache) {
        return 'CEF'
    }
    if ($Finding.Type -eq 'Historique') {
        return 'NIKKE'
    }
    if ($Finding.PSObject.Properties['Target']) {
        $target = $Finding.Target
        if ($target.ContainsKey('Area')) {
            return [string]$target.Area
        }
        if ($target.ContainsKey('PayloadHash')) {
            return 'NIKKE'
        }
        if ($target.ContainsKey('Browser')) {
            return [string]$target.Browser
        }
        if ($target.ContainsKey('SubKey') -and $target.SubKey -eq 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32') {
            return 'Chrome'
        }
    }
    return 'Windows'
}

function Get-FindingLabel($Finding) {
    if ($Finding.Target.ContainsKey('Area') -and $Finding.Target.Area -eq 'Modules' -and $Finding.Target.ContainsKey('ProcessName')) {
        switch ($Finding.Target.ProcessName) {
            'steamwebhelper' { return 'Fichier suspect utilisé par Steam' }
            'runeapps.alt1' { return 'Fichier suspect utilisé par Alt1' }
        }
    }
    if ($Finding.Type -eq 'Historique') {
        if ($Finding.Target.ContainsKey('Marker')) {
            $marker = if ($Finding.Target.ContainsKey('Evidence')) {
                $Finding.Target.Evidence
            } else {
                $Finding.Target.Marker
            }
            return 'Trace historique liée à cet incident'
        }
        return 'Marqueur signalé dans un ancien journal'
    }
    if ($Finding.Type -eq 'Registre') {
        if ((Get-FindingArea $Finding) -eq 'Chrome') {
            return 'Élément de démarrage lié à cet incident'
        }
        return 'Élément de démarrage lié à cet incident'
    }
    if ($Finding.Type -eq 'Fichier' -and $Finding.Target.ContainsKey('Path')) {
        return 'Fichier suspect lié à cet incident'
    }
    return $Finding.Kind
}

function Get-CheckComplete($Snapshot, [string]$Pattern) {
    $checks = @($Snapshot.Checks | Where-Object {
            $_.Name -like $Pattern
        })
    return $checks.Count -gt 0 -and @($checks | Where-Object {
            $_.State -ne 'Effectué'
        }).Count -eq 0
}

function Write-AreaSummary([string]$Label, [object[]]$Rows, [bool]$Verified, [string]$Reason = '') {
    if ($Rows.Count -gt 0) {
        $color = if (@($Rows | Where-Object {
                    $_.Strong
                }).Count -gt 0) {
            'Red'
        } else {
            'Yellow'
        }
        Write-Report "  $Label : $($Rows.Count) trace(s) à examiner" $color
        foreach ($finding in @($Rows | Select-Object -First 3)) {
            Write-Report "    - $(Get-FindingLabel $finding)" $color
            Write-Report "      Où : $($finding.Location)"
        }
        if ($Rows.Count -gt 3) {
            Write-Report "    - $($Rows.Count - 3) autre(s) élément(s) dans les détails"
        }
        if (-not $Verified -and $Reason) {
            Write-Report "    Limite : $Reason" Yellow
        }
    } elseif ($Verified) {
        Write-Report "  $Label : aucun marqueur connu trouvé" Green
    } else {
        if (-not $Reason) {
            $Reason = 'contrôle incomplet — D pour les détails'
        }
        Write-Report "  $Label : $Reason" Yellow
    }
}

# Close requests only: no process termination, elevation or background-process shutdown.
function Get-BrowserProcessNames {
    return @{
        Chrome = 'chrome'
        Edge = 'msedge'
        Firefox = 'firefox'
        Brave = 'brave'
        Opera = 'opera'
        Vivaldi = 'vivaldi'
    }
}

function Get-OpenBrowserWindows([string]$Scope = 'Tous') {
    $names = Get-BrowserProcessNames
    if ($Scope -ne 'Tous' -and -not $names.ContainsKey($Scope)) {
        throw 'Navigateur non pris en charge.'
    }
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    foreach ($process in @(Get-Process -ErrorAction Stop)) {
        try {
            $browser = @($names.Keys | Where-Object {
                    $names[$_] -ieq $process.ProcessName
                })
            if ($browser.Count -eq 0 -or $process.SessionId -ne $session) {
                continue
            }
            if ($Scope -ne 'Tous' -and $browser[0] -ne $Scope) {
                continue
            }
            $handle = $process.MainWindowHandle.ToInt64()
            if ($handle -eq 0) {
                continue
            }
            [pscustomobject]@{
                Browser = [string]$browser[0]
                ProcessName = [string]$process.ProcessName
                Id = [int]$process.Id
                SessionId = [int]$process.SessionId
                Started = $process.StartTime.ToUniversalTime().Ticks
                Handle = $handle
            }
        } catch {
            Write-Detail 'Fermeture facultative : une fenêtre de navigateur n a pas pu être identifiée.'
        }
        finally {
            if ($process -is [Diagnostics.Process]) {
                $process.Dispose()
            }
        }
    }
}

function Get-BrowserProcessById([int]$ProcessNumber) {
    [Diagnostics.Process]::GetProcessById($ProcessNumber)
}

function Request-BrowserWindowClose($Window) {
    $names = Get-BrowserProcessNames
    if (-not $names.ContainsKey([string]$Window.Browser) -or $names[$Window.Browser] -ine $Window.ProcessName) {
        return $false
    }
    if ($Window.Id -le 0 -or $Window.Started -le 0 -or $Window.Handle -eq 0) {
        return $false
    }
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($Window.SessionId -ne $session) {
        return $false
    }
    $process = $null
    try {
        $process = Get-BrowserProcessById $Window.Id
        $process.Refresh()
        # Recheck identity after consent: never act on a reused PID or a different window.
        if ($process.Id -ne $Window.Id -or $process.ProcessName -ine $Window.ProcessName -or $process.SessionId -ne $Window.SessionId -or
            $process.StartTime.ToUniversalTime().Ticks -ne $Window.Started -or $process.MainWindowHandle.ToInt64() -ne $Window.Handle) {
            return $false
        }
        # One ordinary close request; do not retry through a confirmation dialog or force termination.
        return [bool]$process.CloseMainWindow()
    } catch {
        return $false
    }
    finally {
        if ($null -ne $process) {
            try {
                $process.Dispose()
            } catch {}
        }
    }
}

function Offer-BrowserClosure([string]$Scope = 'Tous') {
    if ($NoPrompt) {
        return
    }
    try {
        $windows = @(Get-OpenBrowserWindows $Scope)
    }
    catch {
        Write-Detail 'La proposition de fermeture des navigateurs n était pas disponible. La recherche continue.'
        return
    }
    if ($windows.Count -eq 0) {
        return
    }
    $labels = (@($windows | ForEach-Object {
                $_.Browser
            } | Sort-Object -Unique) -join ', ')
    Write-Host ''
    Write-Host "Navigateurs ouverts : $labels" -ForegroundColor Cyan
    Write-Host 'Vous pouvez demander leur fermeture normale pour faciliter le contrôle et le nettoyage.'
    Write-Host 'Enregistrez vos travaux et formulaires avant d accepter ; les téléchargements peuvent être interrompus.'
    Write-Host 'Le navigateur peut demander confirmation. Aucun arrêt forcé ne sera effectué.'
    if (-not (Confirm-Action 'Demander la fermeture de ces navigateurs ?')) {
        Write-Report 'Navigateurs laissés ouverts à votre demande. La recherche peut continuer.'
        return
    }
    $requested = 0
    foreach ($window in $windows) {
        try {
            if (Request-BrowserWindowClose $window) {
                $requested++
            }
        }
        catch {
            Write-Detail 'Fermeture facultative non confirmée ; la recherche peut continuer.'
        }
    }
    if ($requested -gt 0) {
        Write-Report 'Demande de fermeture envoyée. La vérification continue ; validez toute confirmation dans le navigateur.'
    }
    else {
        Write-Report 'La demande de fermeture n a pas été confirmée. La vérification continue.'
    }
}


function Get-ResultCounts($Snapshot) {
    $checks = @($Snapshot.Checks | Where-Object {
            $_.State -notlike 'Non demand*'
        })
    $rows = @($Snapshot.Findings)
    [pscustomobject]@{
        Completed = @($checks | Where-Object {
                $_.State -eq 'Effectué'
            }).Count
        Incomplete = @($checks | Where-Object {
                $_.State -ne 'Effectué'
            }).Count
        Current = @($rows | Where-Object {
                $_.Type -ne 'Historique' -and $_.Strong -and -not $_.Target.ContainsKey('Unverified')
            }).Count
        Historical = @($rows | Where-Object {
                $_.Type -eq 'Historique'
            }).Count
        Review = @($rows | Where-Object {
                $_.Type -ne 'Historique' -and -not $_.Strong
            }).Count
        Unconfirmed = @($rows | Where-Object {
                $_.Target.ContainsKey('Unverified')
            }).Count
    }
}

function Get-SnapshotConclusion($Snapshot) {
    $counts = Get-ResultCounts $Snapshot
    if ($script:CleanupNeedsRestart) {
        return [pscustomobject]@{
            Text = 'NETTOYAGE EN ATTENTE DU REDÉMARRAGE'
            Color = 'Yellow'
        }
    }
    if ($counts.Current -gt 0) {
        return [pscustomobject]@{
            Text = 'TRACES ACTUELLES À TRAITER'
            Color = 'Red'
        }
    }
    if ($counts.Unconfirmed -gt 0) {
        return [pscustomobject]@{
            Text = 'RETRAIT NON CONFIRMÉ — VÉRIFICATIONS NÉCESSAIRES'
            Color = 'Yellow'
        }
    }
    if (@($script:CleanupOutcomes | Where-Object {
                $_.Outcome -eq 'Failed'
            }).Count -gt 0) {
        return [pscustomobject]@{
            Text = 'NETTOYAGE PARTIEL OU NON CONFIRMÉ'
            Color = 'Yellow'
        }
    }
    if ($counts.Historical -gt 0) {
        return [pscustomobject]@{
            Text = 'TRACES HISTORIQUES — EXPOSITION PASSÉE À EXAMINER'
            Color = 'Yellow'
        }
    }
    if ($counts.Review -gt 0) {
        return [pscustomobject]@{
            Text = 'ÉLÉMENTS À EXAMINER'
            Color = 'Yellow'
        }
    }
    if ($counts.Completed -eq 0) {
        return [pscustomobject]@{
            Text = 'VÉRIFICATION NON RÉALISÉE'
            Color = 'Gray'
        }
    }
    if ($counts.Incomplete -gt 0 -or $Snapshot.Issues.Count -gt 0) {
        return [pscustomobject]@{
            Text = 'VÉRIFICATION PARTIELLE — AUCUNE TRACE TROUVÉE DANS LES ÉLÉMENTS LUS'
            Color = 'Yellow'
        }
    }
    return [pscustomobject]@{
        Text = 'AUCUNE TRACE CONNUE TROUVÉE'
        Color = 'Green'
    }
}

function Get-PlayerSummary($Snapshot) {
    $counts = Get-ResultCounts $Snapshot
    $conclusion = Get-SnapshotConclusion $Snapshot
    'RÉSULTAT DE LA VÉRIFICATION'
    'BILAN : ' + $conclusion.Text
    ('Contrôles terminés : {0} ; incomplets : {1}.' -f $counts.Completed, $counts.Incomplete)
    ('Traces actuelles : {0} ; historiques : {1} ; autres éléments à examiner : {2}.' -f $counts.Current, $counts.Historical, $counts.Review)
    ('Actions confirmées : {0} ; actions échouées ou partielles : {1}.' -f @($script:CleanupOutcomes | Where-Object {
                $_.Outcome -eq 'Done'
            }).Count, @($script:CleanupOutcomes | Where-Object {
                $_.Outcome -eq 'Failed'
            }).Count)
    if ($counts.Completed -eq 0) {
        'Les contrôles disponibles ne permettent pas de conclure.'
    }
    elseif ($counts.Current -eq 0) {
        'Aucune trace actuelle trouvée dans les éléments vérifiés. Cela ne prouve pas qu aucun programme malveillant ne s est exécuté.'
    }
    if ($counts.Historical -gt 0) {
        'Une trace historique renseigne sur une exposition passée ; elle ne démontre pas à elle seule une activité actuelle.'
    }
    if ($counts.Incomplete -gt 0 -or $counts.Unconfirmed -gt 0) {
        'Une vérification incomplète ne permet pas de conclure à l absence de trace dans la zone concernée.'
    }
    if ($counts.Current -eq 0 -and $counts.Historical -eq 0 -and $counts.Review -eq 0) {
        'Ce résultat concerne les traces connues et le périmètre vérifié, sans certification de sécurité du PC.'
    }
    if ($script:HistoricalExposure) {
        'Une exposition passée a été relevée pendant cette session ; un nettoyage ne peut pas annuler un éventuel vol d identifiants.'
    }
    if (@($script:CleanupOutcomes | Where-Object {
                $_.Outcome -eq 'Done'
            }).Count -gt 0) {
        'Le nettoyage ne peut pas annuler un éventuel vol d identifiants : sécurisez vos comptes même après le retrait des traces.'
    }
    'ACTIONS RECOMMANDÉES'
    if ($script:CleanupNeedsRestart) {
        'Redémarrez Windows puis relancez le même fichier pour terminer le nettoyage.'
    }
    elseif ($counts.Current -gt 0) {
        'Restez hors ligne, gardez le lanceur fermé et suivez le nettoyage guidé. Effectuez ensuite une analyse antivirus complète et hors connexion.'
    }
    elseif ($counts.Historical -gt 0 -or $counts.Review -gt 0) {
        'Consultez le détail des traces et effectuez une analyse antivirus complète et hors connexion.'
    }
    if ($counts.Incomplete -gt 0 -or $counts.Unconfirmed -gt 0) {
        if (@($Snapshot.Checks | Where-Object {
                    $_.State -eq 'Partiel' -and $_.Name -match 'Journaux'
                }).Count -gt 0) {
            'Un ancien journal peut manquer après désinstallation ; les autres contrôles restent utiles. Ne réinstallez pas le jeu pour récupérer ce journal.'
        }
        if (@($Snapshot.Checks | Where-Object {
                    $_.State -eq 'Partiel' -and $_.Name -match 'navigateurs|Cache NIKKE'
                }).Count -gt 0) {
            'Fermez les navigateurs et le lanceur puis réessayez. Si un fichier reste verrouillé, redémarrez Windows avant de relancer le contrôle.'
        }
        'Consultez le rapport si un contrôle reste incomplet ; cela ne signifie pas à lui seul une infection.'
    }
    'Sécurisez vos comptes depuis un appareil sain : mots de passe enregistrés ou utilisés sur ce PC, sessions ouvertes et clés ou jetons exposés.'
}

function Show-Snapshot($Snapshot) {
    Write-Report ''
    Write-Report 'RÉSULTAT DE LA VÉRIFICATION' Cyan
    $counts = Get-ResultCounts $Snapshot
    $conclusion = Get-SnapshotConclusion $Snapshot
    if ($script:CleanupNeedsRestart -or $counts.Current -gt 0 -or $counts.Unconfirmed -gt 0 -or @($script:CleanupOutcomes | Where-Object {
                $_.Outcome -eq 'Failed'
            }).Count -gt 0) {
        Write-Report $conclusion.Text $conclusion.Color
    } elseif ($counts.Completed -eq 0) {
        Write-Report 'La vérification n a pas pu être effectuée.' Yellow
    } elseif ($counts.Incomplete -gt 0 -or $Snapshot.Issues.Count -gt 0) {
        Write-Report 'La vérification est incomplète.' Yellow
    } elseif ($counts.Historical -gt 0 -or $counts.Review -gt 0) {
        Write-Report 'Des indices ont été trouvés ; ils ne confirment pas une infection.' Yellow
    } else {
        Write-Report 'Aucune trace connue trouvée.' Green
    }
    if ($counts.Current -eq 0 -and $counts.Completed -gt 0 -and ($counts.Incomplete -gt 0 -or $counts.Historical -gt 0 -or $counts.Review -gt 0)) {
        Write-Report 'Aucune trace actuelle détectée dans les éléments vérifiés.'
    }
    Write-Report ('Contrôles effectués : {0} sur {1}.' -f $counts.Completed, ($counts.Completed + $counts.Incomplete))
    foreach ($check in @($Snapshot.Checks | Where-Object {
                $_.State -eq 'Partiel'
            })) {
        if ($check.Name -match 'Journaux' -and $check.PSObject.Properties['Reasons'] -and @($check.Reasons).Count -eq 1 -and $check.Reasons[0] -like 'Aucun journal NIKKE lisible*') {
            Write-Report 'Ancien journal absent : l historique ne peut plus être vérifié, notamment après désinstallation.'
        } else {
            $area = switch -Wildcard ($check.Name) {
                '*Journaux*' {
                    'Anciens journaux NIKKE'
                    break
                }
                '*navigateurs*' {
                    'Dossiers des navigateurs'
                    break
                }
                '*Registre*' {
                    'Références de démarrage connues'
                    break
                }
                '*Cache NIKKE*' {
                    'Données temporaires du lanceur'
                    break
                }
                '*Programmes*' {
                    'Traces dans les applications ouvertes'
                    break
                }
                '*TCP*' {
                    'Connexions locales vers l adresse signalée'
                    break
                }
                '*DNS*' {
                    'Références locales aux sites signalés'
                    break
                }
                '*hosts*' {
                    'Blocages des sites déjà présents'
                    break
                }
                default {
                    $check.Name
                }
            }
            Write-Report ('À vérifier : {0} — contrôle incomplet, raison dans le rapport [R].' -f (Convert-UiText $area))
        }
    }
    $dns = @($Snapshot.Findings | Where-Object {
            $_.Target.ContainsKey('Area') -and $_.Target.Area -eq 'DNS'
        })
    if ($dns.Count -gt 0) {
        Write-Report 'Information : une référence locale à un site signalé a été trouvée. Une consultation du site peut suffire à la créer.'
    }
    if ($counts.Historical -gt 0) {
        Write-Report 'Des traces anciennes ont été trouvées. Elles ne prouvent pas une activité malveillante actuelle.'
    }
    if (@($Snapshot.Findings | Where-Object { $_.Target.ContainsKey('LegacySource') -or ($_.Target.ContainsKey('Area') -and $_.Target.Area -eq 'Anciennes copies') }).Count -gt 0) {
        Write-Report 'Des anciennes copies créées par NikkeTrace restent présentes. Leur présence ne prouve pas une infection active.'
    }
    if ($script:HistoricalExposure -and $counts.Historical -eq 0) {
        Write-Report 'Une exposition passée a été relevée pendant cette session ; un nettoyage ne peut pas annuler un éventuel vol d identifiants.'
    }
    if ($counts.Review -gt $dns.Count -or $counts.Current -gt 0) {
        Write-Report 'Les éléments trouvés sont décrits dans [D] Détails et [R] Rapport.'
    }
    $done = @($script:CleanupOutcomes | Where-Object {
            $_.Outcome -eq 'Done'
        }).Count
    $failed = @($script:CleanupOutcomes | Where-Object {
            $_.Outcome -eq 'Failed'
        }).Count
    if ($done -gt 0 -or $failed -gt 0) {
        Write-Report ('Nettoyage : {0} action(s) confirmée(s), {1} non terminée(s).' -f $done, $failed)
    }
    Write-Report ''
    if ($script:CleanupNeedsRestart) {
        Write-Report 'À faire : redémarrez Windows, puis relancez ce fichier pour poursuivre le nettoyage.' Yellow
    } elseif ($counts.Current -gt 0) {
        Write-Report 'À faire : restez hors ligne et examinez le nettoyage proposé. Une analyse antivirus reste recommandée.'
    } elseif ($counts.Incomplete -gt 0) {
        Write-Report 'À faire : consultez les raisons dans [R] Rapport avant de relancer la vérification. Une limite ne signifie pas une infection.'
    } elseif ($counts.Historical -gt 0 -or $counts.Review -gt 0) {
        Write-Report 'À faire : consultez [D] Détails. En cas de doute, effectuez une analyse antivirus.'
    }
    Write-Report 'Par précaution, changez vos mots de passe depuis un appareil sain et déconnectez les sessions ouvertes. Aide : [S].'
    Write-Report 'Ce contrôle ciblé ne certifie pas la sécurité du PC.'
    foreach ($finding in $Snapshot.Findings) {
        Write-Detail "Trace : $(Get-FindingLabel $finding) — $($finding.Location)"
    }
    foreach ($check in $Snapshot.Checks) {
        Write-Detail "Contrôle : $($check.Name) — $($check.State)"
    }
    foreach ($issue in $Snapshot.Issues) {
        Write-Detail "Limite du contrôle : $issue"
    }
}


function Show-ResultDetails {
    Write-Host ''
    Write-Host 'DÉTAILS DES TRACES TROUVÉES' -ForegroundColor Cyan
    if ($script:CurrentSnapshot.Findings.Count -eq 0) {
        $conclusion = Get-SnapshotConclusion $script:CurrentSnapshot
        Write-Host $conclusion.Text -ForegroundColor $conclusion.Color
    }
    foreach ($finding in $script:CurrentSnapshot.Findings) {
        Write-Host "  $(Get-FindingArea $finding) — $(Get-FindingLabel $finding)" -ForegroundColor Yellow
        Write-Host "    $($finding.Location)"
    }
    Write-Host 'Les détails techniques et les limites de lecture sont conservés dans le rapport privé.'
    Write-Host "Rapport privé complet : $script:ReportPath"
}


function Show-AccountPriority {
    Write-Report ''
    Write-Report 'IMPORTANT — CHANGEZ VOS MOTS DE PASSE' Yellow
    Write-Report 'Par précaution, depuis un appareil sain : changez vos mots de passe enregistrés ou utilisés sur ce PC, ainsi que ceux réutilisés ailleurs.'
    Write-Report 'Révoquez aussi les sessions et accès suspects : retirer les fichiers ne sécurise pas les comptes déjà exposés.'
}

function Show-PasswordAdvice {
    Show-AccountPriority
    Write-Report 'Cette rubrique affiche des conseils ; NikkeTrace ne modifie aucun compte ni mot de passe.'
    Write-Report 'Commencez par votre messagerie, puis Google/Microsoft, Discord, NIKKE et vos comptes importants.'
    Write-Report 'Effectuez ces changements sur les sites officiels, depuis un téléphone ou un autre appareil sain.'
    Write-Report 'Activez la double authentification. Si un coffre de mots de passe était déverrouillé, remplacez aussi les mots de passe qu il contenait.'
}

function Invoke-PostCleanupCheck([switch]$OfferBrowserClose) {
    if ($OfferBrowserClose -and -not $NoPrompt) {
        Offer-BrowserClosure -Scope $Navigateur
    }
    Write-Report ''
    Write-Report 'REVÉRIFICATION AUTOMATIQUE — merci de patienter...'
    $before = $script:CurrentSnapshot
    try {
        $after = Invoke-TraceScan
        $changes = @(Compare-TraceSnapshots $before $after)
        Write-Report ''
        Write-Report 'BILAN AVANT / APRÈS'
        foreach ($row in $changes) {
            $label = switch ($row.State) {
                'Absent' {
                    'DISPARU'
                }
                'Present' {
                    'TOUJOURS PRÉSENT'
                }
                'Modifie' {
                    'MODIFIÉ — à examiner'
                }
                'Nouveau' {
                    'NOUVEAU — à examiner'
                }
                default {
                    'NON VÉRIFIABLE'
                }
            }
            $color = if ($row.State -eq 'Absent') {
                'Green'
            } elseif ($row.State -in @('Present', 'Nouveau') -and $row.Finding.Strong) {
                'Red'
            } else {
                'Yellow'
            }
            Write-Report "  [$label] $(Get-FindingLabel $row.Finding)" $color
            Write-Detail "    Emplacement : $($row.Finding.Location)"
        }
        if ($changes.Count -eq 0) {
            Write-Report '  Aucun élément suspect à comparer ; les anciennes traces restent détaillées dans le rapport.'
        }
        $removed = @($changes | Where-Object {
                $_.State -eq 'Absent'
            }).Count
        $remaining = @($changes | Where-Object {
                $_.State -in @('Present', 'Modifie', 'Nouveau')
            }).Count
        $unknown = @($changes | Where-Object {
                $_.State -eq 'Inconnu'
            }).Count
        Write-Report "  Résumé : $removed disparu(s), $remaining encore à examiner, $unknown non vérifiable(s)."
        Write-Report '  Disparu signifie absent au contrôle. Seules les actions marquées CONFIRMÉES attestent ce que cet outil a effectivement traité.'
        $script:CurrentSnapshot = $after
        Show-Snapshot $after
    } catch {
        Add-CleanupOutcome 'Failed' 'Revérification non confirmée' 'Recheck'
        $script:CurrentSnapshot.Checks = @($script:CurrentSnapshot.Checks) + @([pscustomobject]@{
                Name = 'Revérification après nettoyage'; State = 'Partiel'; Reasons = @($_.Exception.Message)
            })
        Write-Report '  ÉCHEC de la revérification : aucun nettoyage ne peut être confirmé. Consulter Sécurité Windows.'
        Write-Detail $_.Exception.Message
        Save-Report
        return $false
    }
    Save-Report
    return $true
}

function Test-KnownChromeDllPath([string]$Path) {
    try {
        $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"')))
        $root = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\PlatformExperienceHelper')).TrimEnd('\') + '\'
        return $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -and $full.Substring($root.Length) -match '^[0-9a-fA-F]{64}\\platform_experience_helper\.dll$'
    } catch {
        return $false
    }
}

function Assert-NoReparsePoint([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Un lien ou une jonction empêche un nettoyage sûr.'
        }
        $parent = [IO.Path]::GetDirectoryName($current.TrimEnd('\'))
        if ($parent -eq $current) {
            break
        }
        $current = $parent
    }
}

function Test-OfficialPayloadPath([string]$Path) {
    try {
        $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($file.PSIsContainer -or $file.Length -ne 205135 -or $file.Name -notmatch '^tinyget\.[0-9][0-9._-]+\.log$') {
            return $false
        }
        $tinyget = $file.Directory
        if ($tinyget.Name -ine 'tinyget' -or $tinyget.Parent.Name -ine 'log' -or $tinyget.Parent.Parent.Name -ine 'Launcher') {
            return $false
        }
        [void](Get-ConfirmedNikkeFolder $tinyget.Parent.Parent.Parent.FullName)
        Assert-NoReparsePoint $file.FullName
        return $true
    } catch {
        return $false
    }
}

function Test-LegacyChromePath([string]$Path) {
    try {
        $full = [IO.Path]::GetFullPath($Path)
        if ([IO.Path]::GetFileName($full) -notin @('platform_experience_helper.dll', 'platform_experience_helper.dll.old', 'old-clsid.txt', 'service_util.dll')) {
            return $false
        }
        foreach ($root in @(Get-AdditionalChromeRoots)) {
            $prefix = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
            if ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    } catch {}
    return $false
}

function Get-CleanupPlan($Snapshot) {
    foreach ($f in $Snapshot.Findings) {
        if ($f.Type -eq 'Fichier') {
            $path = $f.Target.Path
            $tempMatch = Test-AgentTempPath $path
            $chromeSafe = (Test-KnownChromeDllPath $path) -and $f.Target.ContainsKey('Sha256') -and $f.Target.Sha256 -match '^[0-9a-fA-F]{64}$'
            $legacySafe = $f.Target.ContainsKey('LegacySource') -and $f.Target.ContainsKey('Sha256') -and (Test-LegacyCopyPath $path $f.Target.LegacySource $f.Target.Sha256)
            $oldDllSafe = $f.Target.ContainsKey('Sha256') -and $f.Target.Sha256 -ieq '931747D56B9639829AECD5540991D53DF336FF4E93B30C7DB0C8DF7A6038942E' -and (Test-LegacyChromePath $path)
            $officialPayload = $f.Target.ContainsKey('OfficialPayload') -and $f.Target.OfficialPayload -and $f.Target.ContainsKey('Sha256') -and $f.Target.Sha256 -match '^[a-fA-F0-9]{64}$' -and (Test-OfficialPayloadPath $path)
            if ($chromeSafe -or $tempMatch -or $legacySafe -or $oldDllSafe -or $officialPayload -or $f.Target.ContainsKey('PayloadHash')) {
                [pscustomobject]@{
                    Action = 'Suppression'
                    Finding = $f
                }
            }
        } elseif ($f.Type -eq 'Registre') {
            $t = $f.Target
            if ($t.ContainsKey('EmptyClsid') -and $t.EmptyClsid -and $t.Hive -eq 'CurrentUser' -and $t.SubKey -eq 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}') {
                [pscustomobject]@{
                    Action = 'Registre'
                    Finding = $f
                }
                continue
            }
            if ($t.ContainsKey('KnownChromeOverride') -and $t.KnownChromeOverride -and $t.Hive -eq 'CurrentUser' -and
                $t.SubKey -eq 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32' -and $t.Name -eq '') {
                [pscustomobject]@{
                    Action = 'Registre'
                    Finding = $f
                }
            }
        }
    }
}

function New-RecoveryFolder {
    $folder = Join-Path $env:LOCALAPPDATA ('NIKKE-Assistance\Sauvegardes\' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($folder)
    Assert-NoReparsePoint $folder
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner($sid)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($sid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        [void]$security.AddAccessRule($rule)
    }
    [IO.Directory]::SetAccessControl($folder, $security)
    return $folder
}

function Remove-ConfirmedFile($Finding) {
    $authorized = @(Get-CleanupPlan ([pscustomobject]@{
                Findings = @($Finding)
            }) | Where-Object {
            $_.Action -eq 'Suppression'
        })
    if ($authorized.Count -ne 1) {
        throw 'Ce fichier ne fait pas partie du nettoyage ciblé autorisé.'
    }
    $path = $Finding.Target.Path
    Assert-NoReparsePoint $path
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer) {
        throw 'Ce chemin est un dossier ; aucune suppression récursive autorisée.'
    }
    $expectedHash = ''
    if ($Finding.Target.ContainsKey('PayloadHash')) {
        $expectedHash = $Finding.Target.PayloadHash
    } elseif ($Finding.Target.ContainsKey('Sha256')) {
        $expectedHash = $Finding.Target.Sha256
    }
    if (($Finding.Target.ContainsKey('PayloadHash') -or $Finding.Target.ContainsKey('Sha256')) -and $expectedHash -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Empreinte manquante ou invalide : suppression annulée.'
    }
    Initialize-CacheReader
    [NikkeTrace.CacheDelete27]::DeleteArtifact($item.FullName, $expectedHash)
    if (Test-Path -LiteralPath $path -ErrorAction Stop) {
        throw 'La suppression du fichier ne peut pas être confirmée.'
    }
}

function Remove-KnownRegistryOverride([hashtable]$Target, [string]$BackupPath) {
    if ($Target.ContainsKey('EmptyClsid') -and $Target.EmptyClsid) {
        return Remove-EmptyUserClsid $Target $BackupPath
    }
    $expected = 'Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32'
    if ($Target.Hive -ne 'CurrentUser' -or $Target.SubKey -ne $expected -or $Target.Name -ne '') {
        throw 'Cette référence de registre ne fait pas partie du nettoyage ciblé.'
    }
    $base = $null
    $key = $null
    try {
        $view = [Microsoft.Win32.RegistryView][Enum]::Parse([Microsoft.Win32.RegistryView], $Target.View)
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)
        $key = $base.OpenSubKey($expected, $false)
        if ($null -eq $key) {
            return $false
        }
        $value = [string]$key.GetValue('')
        if ((Get-ValueFingerprint $value) -ne $Target.Fingerprint -or -not (Test-KnownChromeDllPath $value)) {
            throw 'Valeur modifiée ou chemin non documenté : entrée laissée en place.'
        }
        if ($key.GetSubKeyNames().Count -gt 0 -or @($key.GetValueNames() | Where-Object {
                    $_ -notin @('', 'ThreadingModel')
                }).Count -gt 0) {
            throw 'La clé contient des éléments supplémentaires non reconnus : laissée en place.'
        }
        $values = foreach ($name in $key.GetValueNames()) {
            [pscustomobject]@{
                Name = $name
                Kind = [string]$key.GetValueKind($name)
                Value = $key.GetValue($name)
            }
        }
        [pscustomobject]@{
            Hive = 'CurrentUser'
            View = $Target.View
            SubKey = $expected
            Values = @($values)
        } |
        Export-Clixml -LiteralPath $BackupPath -Encoding UTF8 -ErrorAction Stop
        # Back up before the only allowed mutation; never open HKLM for writing.
        if ((Get-ValueFingerprint ([string]$key.GetValue(''))) -ne $Target.Fingerprint) {
            throw 'La valeur a changé pendant la sauvegarde : opération annulée.'
        }
        $key.Dispose()
        $key = $null
        $base.DeleteSubKey($expected, $false)
        # Remove the parent only when no values or child keys remain.
        $parentPath = [IO.Path]::GetDirectoryName($expected)
        $parent = $base.OpenSubKey($parentPath, $false)
        try {
            $empty = $null -ne $parent -and $parent.GetValueNames().Count -eq 0 -and $parent.GetSubKeyNames().Count -eq 0
        }
        finally {
            if ($null -ne $parent) {
                $parent.Dispose()
            }
        }
        if ($empty) {
            $base.DeleteSubKey($parentPath, $false)
        }
        return $true
    } finally {
        if ($null -ne $key) {
            $key.Dispose()
        }
        if ($null -ne $base) {
            $base.Dispose()
        }
    }
}


function Get-ConfirmedNikkeFolder([string]$Path) {
    $value = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($value -notmatch '^[A-Za-z]:[\\/]') {
        throw 'Un dossier local absolu est nécessaire.'
    }
    $full = [IO.Path]::GetFullPath($value).TrimEnd('\')
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        throw 'Choisissez le dossier NIKKE ou Launcher, pas un fichier.'
    }
    if ($item.Name -eq 'intl_service') {
        $full = [IO.Path]::GetDirectoryName($full)
    }
    if ([IO.Path]::GetFileName($full) -eq 'Launcher') {
        $full = [IO.Path]::GetDirectoryName($full)
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -eq [IO.DriveType]::Network) {
        throw 'Le retrait sur un lecteur réseau n est pas pris en charge.'
    }
    foreach ($root in @([IO.Path]::GetPathRoot($full), $env:USERPROFILE, $env:WINDIR, $env:LOCALAPPDATA, $env:APPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($root -and $full.TrimEnd('\') -ieq $root.TrimEnd('\')) {
            throw 'Ce dossier système ou personnel ne peut pas être retiré.'
        }
    }
    if ([IO.Path]::GetFileName($full) -notmatch '(?i)NIKKE') {
        throw 'Le nom du dossier ne permet pas de confirmer une installation NIKKE.'
    }
    $hasLauncher = $false
    foreach ($name in @('nikke_launcher.exe', 'nikke_launcher_hmt.exe', 'nikke_launcher_google.exe')) {
        if ((Test-Path -LiteralPath (Join-Path $full "Launcher\$name") -PathType Leaf) -or (Test-Path -LiteralPath (Join-Path $full $name) -PathType Leaf)) {
            $hasLauncher = $true
        }
    }
    $hasService = Test-Path -LiteralPath (Join-Path $full 'Launcher\intl_service') -PathType Container
    if (-not $hasLauncher -or -not $hasService) {
        throw 'Installation NIKKE non confirmée : aucun retrait automatique de ce dossier.'
    }
    Assert-NoReparsePoint $full
    return $full
}

function Get-NikkeRemovalCandidates {
    $paths = @($script:ScanPaths) + $NikkePath
    try {
        $paths += @(Get-NikkeInstallPaths)
    } catch {}
    $found = @{}
    foreach ($path in $paths) {
        if (-not $path) {
            continue
        }
        try {
            $confirmed = Get-ConfirmedNikkeFolder $path
            if (-not $found.ContainsKey($confirmed)) {
                $found[$confirmed] = $true
                $confirmed
            }
        } catch {}
    }
}

function Offer-NikkeUninstall([string[]]$Paths) {
    Write-Report ''
    Write-Report 'DÉSINSTALLATION DE NIKKE (FACULTATIF)' Cyan
    Write-Report 'La désinstallation se fait dans les paramètres de Windows. Aucun dossier du jeu ne sera renommé ou effacé par NikkeTrace.'
    Write-Report 'Dans la liste des applications, cherchez NIKKE et son lanceur, puis choisissez Désinstaller.'
    Write-Report 'Pour une installation Google Play Games, retirez uniquement NIKKE depuis sa bibliothèque ; conservez les autres jeux.'
    foreach ($path in $Paths) {
        Write-Detail "Installation proposée à la désinstallation : $path"
    }
    if (-not (Confirm-Action 'Ouvrir les applications installées de Windows ?')) {
        Write-Report 'Ouverture refusée : aucune désinstallation lancée.'
        return 'Declined'
    }
    try {
        Assert-LauncherClosed
        Start-Process -FilePath 'ms-settings:appsfeatures' -ErrorAction Stop | Out-Null
        Add-CleanupOutcome 'Information' 'Interface Windows ouverte ; désinstallation non confirmée' 'Windows'
        Write-Report 'Terminez la désinstallation dans Windows, puis choisissez Revérifier dans NikkeTrace.'
        return 'Opened'
    } catch {
        Add-CleanupOutcome 'Failed' 'Ouverture de la désinstallation Windows non confirmée' 'Windows'
        Write-Report 'Ouverture impossible. Utilisez Paramètres > Applications > Applications installées.' Yellow
        Write-Detail $_.Exception.Message
        return 'Failed'
    }
}


function Offer-OfflineScanHelp {
    Write-Host ''
    Write-Host 'ANALYSE MICROSOFT DEFENDER HORS CONNEXION' -ForegroundColor Cyan
    Write-Host 'Ce choix ouvre une aide et Sécurité Windows. Il ne lance pas une analyse.'
    Write-Host 'Si vous cliquez ensuite sur Analyser maintenant dans Windows :'
    Write-Host '  - le PC redémarrera et les applications seront fermées ; enregistrez vos travaux ;' -ForegroundColor Yellow
    Write-Host '  - vous ne pourrez pas utiliser Windows ou Internet pendant l analyse (environ 15 minutes) ;' -ForegroundColor Yellow
    Write-Host '  - Windows redémarrera ensuite ; cela ne désactive pas définitivement votre connexion.'
    Write-Host 'Si le disque est chiffré, préparez votre clé BitLocker avant toute analyse.'
    Write-Host 'Microsoft recommande de suspendre la protection BitLocker avant cette analyse : demandez de l aide si nécessaire.'
    Write-Host 'Defender doit être principal et actif, et WinRE disponible. Windows ARM n est pas pris en charge.'
    if (-not (Confirm-Action 'Ouvrir Sécurité Windows sans lancer l analyse ?')) {
        Write-Detail 'Aide hors connexion refusée : aucune ouverture, analyse ou relance Windows.'
        return
    }
    Write-Report 'Ouvrez Protection contre les virus et menaces > Options d analyse > Microsoft Defender (analyse hors connexion).'
    Write-Report 'Cliquez sur Analyser maintenant uniquement quand vous êtes prêt à redémarrer.'
    Write-Report 'Après le retour dans Windows : consulter Historique de protection et relancer cet outil pour revérifier les traces.'
    Write-Detail 'Aide hors connexion proposée. Aucun lancement antivirus, redémarrage ou changement réseau déclenché par cet outil.'
    Save-Report
    try {
        Start-Process -FilePath 'windowsdefender://threat/' -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Report 'Ouverture impossible : cherchez Sécurité Windows dans le menu Démarrer.' Yellow
    }
}

function Write-Advice([switch]$Detailed, [switch]$ReportOnly) {
    if ($script:AdviceShown -and -not $Detailed) {
        return
    }
    $start = $script:Report.Count
    Write-Detail ''
    Write-Detail 'PROTÉGER VOS COMPTES — MÊME SI LES TRACES ONT DISPARU'
    Write-Detail 'Depuis un téléphone ou autre appareil sain, sans attendre la fin des analyses :'
    Write-Detail '  1. Changez les mots de passe enregistrés/utilisés sur le PC potentiellement exposé et ceux réutilisés ailleurs.'
    Write-Detail '     Commencez par la messagerie et le gestionnaire de mots de passe, puis comptes importants, Discord et NIKKE.'
    Write-Detail '  2. Déconnectez toutes les sessions, retirez les appareils et accès suspects, puis activez la double authentification.'
    Write-Detail '     Changer le mot de passe ne révoque pas toujours une session déjà volée.'
    Write-Detail '  3. Si un coffre était déverrouillé, son contenu peut être exposé : changer seulement son mot de passe maître ne suffit pas.'
    Write-Detail '     Remplacez aussi les jetons API et clés SSH concernés. Ne communiquez jamais vos secrets à un dépanneur Discord.'
    Write-Detail 'Pour compléter : faites ensuite une analyse antivirus, notamment Microsoft Defender hors connexion.'
    Write-Detail 'Sécurité Windows > Protection contre les virus et menaces > Options d analyse > analyse hors connexion.'
    Write-Detail 'Enregistrez vos travaux : elle redémarrera le PC. Si le disque est chiffré, préparez votre clé BitLocker.'
    Write-Detail 'Consultez les prérequis Microsoft (Defender principal, WinRE ; Windows ARM non pris en charge) ou demandez de l aide.'
    Write-Detail 'Cet outil ne lance aucun antivirus et ne déclenche aucun redémarrage.'
    Write-Detail 'Si une compromission est probable, privilégiez une réinstallation propre de Windows avec une personne compétente.'
    Write-Detail 'Une analyse négative et la disparition des traces ne prouvent pas que le PC est sain.'
    Write-Detail 'Avant toute reprise du jeu : attendre les consignes officielles et réinitialiser le cache du lanceur avec aide si nécessaire.'
    Write-Detail 'Un correctif côté serveur ne nettoie pas un PC déjà exposé ; le cache peut conserver un ancien fichier.'
    if ($Detailed) {
        foreach ($line in $script:Report.GetRange($start, $script:Report.Count - $start)) {
            Write-Host $line
        }
    } elseif (-not $ReportOnly) {
        Write-Host 'À FAIRE PAR PRÉCAUTION DEPUIS UN APPAREIL SAIN :' -ForegroundColor Cyan
        Write-Host '  Changez vos mots de passe enregistrés ou utilisés sur ce PC, déconnectez les sessions et activez la double authentification.'
        Write-Host '  Une analyse antivirus hors connexion reste conseillée ; cet outil ne la lance pas.'
        Write-Host '  Le menu propose aussi un blocage facultatif des domaines signalés.'
    }
    $script:AdviceShown = $true
}

function Show-Help {
    Write-Host ''
    Write-Host 'Le choix 1 recherche les traces connues, affiche un bilan puis propose un nettoyage après confirmation.'
    Write-Host 'Le blocage des sites signalés est proposé ensuite, avec une confirmation séparée. Il reste aussi accessible dans les options avancées.'
    Write-Host 'Cet outil communautaire recherche des traces connues ; il n est ni officiel ni un antivirus.'
    Write-Host 'Un seul fichier sert à vérifier le jeu, les navigateurs et le registre, puis à proposer un nettoyage ciblé avec accord.'
    Write-Host 'Jeu déjà supprimé ? Le mode dédié vérifie encore les navigateurs, le registre, les temporaires et les journaux résiduels connus.'
    Write-Host 'Les caches NIKKE et le profil CEF sont vérifiés même sans le jeu : stockage local, scripts et traces réseau.'
    Write-Host 'Sans preuve conservée, une exécution passée reste indéterminée. Ne réinstallez pas le jeu pour cette vérification.'
    Write-Host 'PlatformExperienceHelper seul et onominan.tmp ne sont pas des indicateurs de cette attaque.'
    Write-Host 'Seule la DLL Chrome dans un sous-dossier de 64 caractères hexadécimaux est admise au nettoyage automatique.'
    Write-Host 'Aucune lecture des mots de passe, cookies ou jetons. Les rapports restent sur le PC.'
    Write-Host 'En cas de traces : coupez Ethernet/Wi-Fi, ne relancez pas le jeu, ne saisissez pas de secrets sur ce PC.'
    Write-Host 'Les journaux signalent une activité passée ; les fichiers/entrées de registre indiquent des traces actuelles à examiner.'
    Write-Host 'Les autres comptes Windows, profils personnalisés non indiqués et variantes inconnues ne sont pas couverts.'
    Write-Host 'Après un nettoyage, la revérification est automatique. Après un redémarrage hors connexion, relancez ce même fichier.'
}

function Select-Browser {
    $names = @('Tous', 'Chrome', 'Edge', 'Firefox', 'Brave', 'Opera', 'Vivaldi')
    do {
        Write-Host '1 Tous les navigateurs (recommandé) | 2 Chrome | 3 Edge | 4 Firefox | 5 Brave | 6 Opera | 7 Vivaldi'
        Write-Host '0 Retour au menu principal'
        $choice = (Read-Host 'Votre choix [Entrée = Tous]').Trim().ToLowerInvariant()
        if ($choice -eq '') {
            return 'Tous'
        }
        if ($choice -in @('0', 'b')) {
            return 'Retour'
        }
        if ($choice -match '^[1-7]$') {
            return $names[([int]$choice - 1)]
        }
    } while ($true)
}

# Optional, fixed-domain hosts update. No IP firewall rules, no DNS flush, no scan elevation.
function Get-HostsBlockPath {
    Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\drivers\etc\hosts'
}

function Get-HostsRulesState([byte[]]$Bytes) {
    if ($null -eq $Bytes) {
        $Bytes = New-Object byte[] 0
    }
    if ([Array]::IndexOf($Bytes, [byte]0) -ge 0) {
        throw 'HOSTS_ENCODING'
    }
    $domains = @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org')
    $protected = @{}
    $conflicts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in ([Text.Encoding]::UTF8.GetString($Bytes) -split '\r?\n')) {
        $content = ($line -split '#', 2)[0].Trim().TrimStart([char]0xFEFF)
        if (-not $content) {
            continue
        }
        $parts = @($content -split '\s+')
        if ($parts.Count -lt 2) {
            continue
        }
        foreach ($domain in $parts[1..($parts.Count - 1)]) {
            $name = $domain.TrimEnd('.').ToLowerInvariant()
            if ($name -notin $domains) {
                continue
            }
            $address = $null
            if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$address) -or $address.ToString() -notin @('0.0.0.0', '127.0.0.1', '::', '::1')) {
                if (-not $conflicts.Contains($name)) {
                    $conflicts.Add($name)
                }
                continue
            }
            $family = if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                '4'
            } else {
                '6'
            }
            $protected["$name|$family"] = $true
        }
    }
    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($domain in $domains) {
        if (-not $protected.ContainsKey("$domain|4")) {
            $missing.Add("0.0.0.0 $domain")
        }
        if (-not $protected.ContainsKey("$domain|6")) {
            $missing.Add("::1 $domain")
        }
    }
    return [pscustomobject]@{
        Complete = ($missing.Count -eq 0 -and $conflicts.Count -eq 0)
        MissingLines = @($missing.ToArray())
        Conflicts = @($conflicts.ToArray())
    }
}

function Read-HostsBlockState([string]$Path) {
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
        if ($stream.Length -gt 4MB) {
            throw 'HOSTS_SIZE'
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) {
                throw 'HOSTS_READ'
            }
            $offset += $read
        }
        return Get-HostsRulesState $bytes
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Test-HostsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HostsFailureCode($Failure) {
    $message = [string]$Failure.Exception.Message
    if ($message -match 'HOSTS_CONFLICT|conflit') {
        return 12
    }
    if ($message -match 'HOSTS_ENCODING|Encodage') {
        return 13
    }
    if ($message -match 'lien') {
        return 14
    }
    $errorValue = $Failure.Exception.GetBaseException()
    if ($errorValue -is [OperationCanceledException] -or ($errorValue -is [ComponentModel.Win32Exception] -and $errorValue.NativeErrorCode -eq 1223)) {
        return 1223
    }
    if ($errorValue -is [UnauthorizedAccessException]) {
        return 11
    }
    if ($errorValue -is [IO.IOException]) {
        return 10
    }
    return 19
}

function Get-HostsFailureText([int]$Code) {
    switch ($Code) {
        1223 {
            'La demande administrateur a été annulée. Le blocage n a pas été confirmé.'
        }
        11 {
            'Windows a refusé l accès au fichier hosts ou à sa sauvegarde. Le blocage n a pas été confirmé.'
        }
        10 {
            'Le fichier hosts ou sa sauvegarde est inaccessible ou utilisé par un autre programme. Le blocage n a pas été confirmé.'
        }
        12 {
            'Une règle existante entre en conflit avec un domaine signalé. Aucune entrée existante ne sera remplacée.'
        }
        13 {
            'Le format du fichier hosts n est pas pris en charge. Aucune réécriture automatique ne sera effectuée.'
        }
        14 {
            'Le chemin hosts est redirigé. L outil refuse de le modifier automatiquement.'
        }
        default {
            'Les règles attendues n ont pas été confirmées dans hosts. Le rapport contient le détail de l opération.'
        }
    }
}


function Add-KnownHostsBlocks([string]$Path, [string]$Token) {
    if ($Token -notmatch '^[a-fA-F0-9]{32}$') {
        throw 'Identifiant de sauvegarde invalide.'
    }
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        $attributes = [IO.File]::GetAttributes($current)
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Un lien empêche la modification sûre de hosts.'
        }
        $parent = [IO.Path]::GetDirectoryName($current.TrimEnd('\'))
        if ($parent -eq $current) {
            break
        }
        $current = $parent
    }
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
        if ($stream.Length -gt 4MB) {
            throw 'Fichier hosts trop volumineux : aucune modification.'
        }
        $original = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $original.Length) {
            $read = $stream.Read($original, $offset, $original.Length - $offset)
            if ($read -eq 0) {
                throw 'Lecture de hosts incomplète : aucune modification.'
            }
            $offset += $read
        }
        $state = Get-HostsRulesState $original
        if ($state.Conflicts.Count -gt 0) {
            throw 'HOSTS_CONFLICT'
        }
        $lines = $state.MissingLines
        if ($lines.Count -eq 0) {
            return [pscustomobject]@{
                Changed = $false
                Backup = ''
            }
        }
        $backup = $Path + '.NIKKE-backup-' + $Token
        $backupStream = [IO.File]::Open($backup, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            [IO.File]::SetAccessControl($backup, [IO.File]::GetAccessControl($Path))
            $backupStream.Write($original, 0, $original.Length)
            $backupStream.Flush($true)
        }
        finally {
            $backupStream.Dispose()
        }
        $suffix = [Text.Encoding]::ASCII.GetBytes("`r`n# NIKKE-Assistance : domaines signales`r`n" + ($lines -join "`r`n") + "`r`n")
        try {
            [void]$stream.Seek(0, [IO.SeekOrigin]::End)
            $stream.Write($suffix, 0, $suffix.Length)
            $stream.Flush($true)
            if ($stream.Length -ne ($original.Length + $suffix.Length)) {
                throw 'Écriture hosts non confirmée.'
            }
            [void]$stream.Seek($original.Length, [IO.SeekOrigin]::Begin)
            $verification = New-Object byte[] $suffix.Length
            $offset = 0
            while ($offset -lt $verification.Length) {
                $read = $stream.Read($verification, $offset, $verification.Length - $offset)
                if ($read -eq 0) {
                    throw 'Relecture hosts incomplète.'
                }
                $offset += $read
            }
            if ([Convert]::ToBase64String($verification) -cne [Convert]::ToBase64String($suffix)) {
                throw 'Relecture hosts différente.'
            }
        } catch {
            # Only the appended suffix can have changed; restore the original length on failure.
            $stream.SetLength($original.Length)
            $stream.Flush($true)
            throw
        }
        return [pscustomobject]@{
            Changed = $true
            Backup = $backup
        }
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Start-HostsBlockOperation([string]$Token) {
    if ($Token -notmatch '^[a-fA-F0-9]{32}$') {
        throw 'Identifiant de sauvegarde invalide.'
    }
    if (Test-HostsAdmin) {
        try {
            [void](Add-KnownHostsBlocks (Get-HostsBlockPath) $Token)
            return 0
        }
        catch {
            return Get-HostsFailureCode $_
        }
    }
    $parser = ${function:Get-HostsRulesState}.ToString()
    $body = ${function:Add-KnownHostsBlocks}.ToString()
    $errors = ${function:Get-HostsFailureCode}.ToString()
    # Elevate fixed code only; never execute an editable temporary script as administrator.
    $code = "`$ErrorActionPreference='Stop'; function Get-HostsRulesState {`n" + $parser + "`n}; function Add-KnownHostsBlocks {`n" + $body + "`n}; function Get-HostsFailureCode {`n" + $errors + "`n}; try { `$path=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\drivers\etc\hosts'; [void](Add-KnownHostsBlocks `$path '$Token'); exit 0 } catch { `$result=Get-HostsFailureCode `$_; exit `$result }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $executable = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $executable -Verb RunAs -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
    try {
        if ($null -eq $process) {
            return -1
        }
        $process.Refresh()
        if (-not $process.HasExited -or $null -eq $process.ExitCode) {
            return -1
        }
        return [int]$process.ExitCode
    } catch {
        return -1
    }
    finally {
        if ($null -ne $process) {
            try {
                $process.Dispose()
            } catch {}
        }
    }
}

function Offer-HostsBlock([switch]$Guided) {
    Write-Host ''
    if ($Guided) {
        Write-Host 'BLOQUER LES SITES SIGNALÉS (FACULTATIF)' -ForegroundColor Cyan
        Write-Host 'Vous pouvez ajouter un blocage local pour les sites suivants :'
    } else {
        Write-Host 'BLOCAGE FACULTATIF DES DOMAINES SIGNALÉS' -ForegroundColor Cyan
        Write-Host 'Cette option ajoute uniquement ces domaines dans hosts :'
    }
    foreach ($domain in @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org')) {
        Write-Host "  - $domain"
    }
    $hostsPath = Get-HostsBlockPath
    if ($Guided) {
        Write-Detail "Fichier concerné : $hostsPath"
    } else {
        Write-Host "Fichier concerné : $hostsPath"
    }
    try {
        $state = Read-HostsBlockState $hostsPath
    }
    catch {
        Write-Report (Get-HostsFailureText (Get-HostsFailureCode $_)) Yellow
        Write-Detail "Échec de lecture hosts : $($_.Exception.Message)"
        Save-Report
        return
    }
    if ($state.Complete) {
        if ($Guided) {
            Write-Report 'Ces sites sont déjà bloqués ; aucune modification nécessaire.' Green
        } else {
            Write-Report 'DOMAINES DÉJÀ BLOQUÉS DANS HOSTS — aucune modification ni demande administrateur nécessaire.' Green
        }
        Write-Report 'Les règles ont été relues dans le fichier. Cela ne certifie pas que le PC est sain.'
        Save-Report
        return
    }
    if ($state.Conflicts.Count -gt 0) {
        Write-Report (Get-HostsFailureText 12) Yellow
        Write-Detail ('Domaines en conflit : ' + ($state.Conflicts -join ', '))
        Save-Report
        return
    }
    if (-not $Guided) {
        Write-Host 'Règles prévues (seules les lignes manquantes seront ajoutées) :'
    }
    foreach ($line in $state.MissingLines) {
        if ($Guided) {
            Write-Detail "  $line"
        } else {
            Write-Host "  $line"
        }
    }
    if ($Guided) {
        Write-Host 'Seuls les blocages manquants seront ajoutés. Une sauvegarde sera conservée et les autres réglages resteront inchangés.'
        Write-Host 'Ce blocage est limité aux noms ci-dessus ; il ne supprime pas une infection.'
        Write-Detail 'Ce blocage ne supprime pas une infection et ne bloque pas les connexions directes vers les IP signalées.'
    } else {
        Write-Host 'Ces règles bloquent localement les noms indiqués, pour IPv4 et IPv6. Aucun autre domaine ne sera ajouté.'
        Write-Host 'Une sauvegarde sera créée à côté de hosts. Les autres entrées seront conservées ; un conflit annulera la modification.'
        Write-Host 'Ce blocage ne supprime pas une infection et ne bloque pas les connexions directes vers les IP signalées.'
    }
    Write-Host 'Windows demandera les droits administrateur si nécessaire, après votre accord.'
    $question = if ($Guided) {
        'Bloquer ces sites maintenant ?'
    } else {
        'Ajouter ce blocage des domaines ?'
    }
    if (-not (Confirm-Action $question)) {
        Write-Report 'Blocage des domaines refusé : aucune modification.'
        return
    }
    $token = [guid]::NewGuid().ToString('N')
    $exitCode = -1
    try {
        $returned = Start-HostsBlockOperation $token
        if ($returned -is [int]) {
            $exitCode = $returned
        }
    } catch {
        $exitCode = Get-HostsFailureCode $_
        Write-Detail "Échec de l opération hosts : $($_.Exception.Message)"
    }
    # File contents are authoritative, even if Windows did not return a usable child exit code.
    try {
        $after = Read-HostsBlockState $hostsPath
        if ($after.Complete) {
            if ($Guided) {
                Write-Report 'Blocage des sites confirmé par vérification.' Green
            } else {
                Write-Report 'DOMAINES SIGNALÉS BLOQUÉS DANS HOSTS — confirmé par relecture du fichier.' Green
            }
            $backup = $hostsPath + '.NIKKE-backup-' + $token
            if (Test-Path -LiteralPath $backup) {
                if ($Guided) {
                    Write-Detail "Sauvegarde hosts : $backup"
                } else {
                    Write-Report "Sauvegarde hosts : $backup"
                }
            }
            Write-Report 'Les connexions déjà ouvertes peuvent continuer. Fermez puis rouvrez vos navigateurs ; ne relancez pas un launcher suspect.'
        } else {
            Write-Report (Get-HostsFailureText $exitCode) Yellow
        }
        Write-Detail "Résultat technique hosts : code $exitCode ; lignes manquantes $($after.MissingLines.Count) ; conflits $($after.Conflicts.Count)."
    } catch {
        Write-Report 'Impossible de relire hosts après l opération. Le blocage ne peut pas être confirmé.' Yellow
        Write-Detail "Échec de relecture hosts : $($_.Exception.Message)"
    }
    Save-Report
}


function Import-LauncherBrowserFirewallModule {
    Import-Module (Join-Path $PSHOME 'Modules\NetSecurity\NetSecurity.psd1') -ErrorAction Stop
}

function Get-LauncherBrowserRuleName([string]$Program) {
    if ($Program.Length -gt 1024 -or $Program -notmatch '^[A-Za-z]:[\\/]' -or $Program -match '[*?\r\n]' -or [IO.Path]::GetFileName($Program) -ine 'tbs_browser.exe') {
        throw 'Invalid launcher browser path.'
    }
    $full = [IO.Path]::GetFullPath($Program)
    if ($full -ine $Program -or $full -notmatch '(?i)\\Launcher\\intl_service\\tbs_browser\.exe$') {
        throw 'Unexpected launcher browser location.'
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return 'NikkeTrace-LauncherBrowser-' + [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($full.ToUpperInvariant()))).Replace('-', '')
    } finally {
        $hash.Dispose()
    }
}

function Get-LauncherBrowserProgram([string]$Install) {
    $root = Get-ConfirmedNikkeFolder $Install
    $program = Join-Path $root 'Launcher\intl_service\tbs_browser.exe'
    [void](Get-LauncherBrowserRuleName $program)
    $item = Get-Item -LiteralPath $program -Force -ErrorAction Stop
    if ($item.PSIsContainer) {
        throw 'Launcher browser executable not found.'
    }
    Assert-NoReparsePoint $program
    return $program
}

function Get-LauncherBrowserFirewallRules([string]$Store = 'PersistentStore') {
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop | Where-Object { $_.Name -like 'NikkeTrace-LauncherBrowser-*' })) {
        $apps = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        if ($apps.Count -ne 1 -or $rule.Group -cne 'NikkeTrace Launcher Browser' -or $rule.Description -cne 'NikkeTrace optional outbound block for the NIKKE launcher browser.' -or $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block' -or $rule.Profile -ne 'Any' -or $rule.Name -cne (Get-LauncherBrowserRuleName ([string]$apps[0].Program))) {
            throw 'Conflicting NikkeTrace firewall rule; no automatic change.'
        }
        $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $addresses = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        if ($ports.Count -ne 1 -or $addresses.Count -ne 1 -or $ports[0].Protocol -ne 'Any' -or (@($ports[0].LocalPort) -join ',') -ne 'Any' -or (@($ports[0].RemotePort) -join ',') -ne 'Any' -or (@($addresses[0].LocalAddress) -join ',') -ne 'Any' -or (@($addresses[0].RemoteAddress) -join ',') -ne 'Any') {
            throw 'Modified NikkeTrace firewall scope; no automatic change.'
        }
        [pscustomobject]@{ Name = $rule.Name; Program = [string]$apps[0].Program; Enabled = ([string]$rule.Enabled -eq 'True') }
    }
}

function Set-LauncherBrowserFirewall([string]$Program, [ValidateSet('Block', 'Remove')][string]$Action) {
    $name = Get-LauncherBrowserRuleName $Program
    $rules = @(Get-LauncherBrowserFirewallRules | Where-Object { $_.Name -ceq $name })
    if ($Action -eq 'Remove') {
        if ($rules.Count -eq 1) {
            Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
        }
        return
    }
    if ((Get-LauncherBrowserProgram ([IO.Path]::GetDirectoryName($Program))) -ine $Program) {
        throw 'Launcher browser location changed.'
    }
    if ($rules.Count -gt 0) {
        if (-not $rules[0].Enabled) {
            throw 'Existing NikkeTrace rule is disabled; remove it before retrying.'
        }
        return
    }
    New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName 'NikkeTrace - NIKKE launcher browser (outbound block)' -Description 'NikkeTrace optional outbound block for the NIKKE launcher browser.' -Group 'NikkeTrace Launcher Browser' -Program $Program -Direction Outbound -Action Block -Profile Any -Enabled True -Protocol Any -LocalAddress Any -RemoteAddress Any -ErrorAction Stop | Out-Null
}

function Get-LauncherBrowserFirewallCommand([string[]]$Programs, [ValidateSet('Block', 'Remove')][string]$Action) {
    if ($Programs.Count -eq 0 -or $Programs.Count -gt 16) {
        throw 'Unexpected number of launcher browsers.'
    }
    foreach ($program in $Programs) {
        [void](Get-LauncherBrowserRuleName $program)
    }
    $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($Programs) -Compress)))
    $code = "`$ErrorActionPreference='Stop'; Set-StrictMode -Version 2.0;"
    foreach ($function in @('Import-LauncherBrowserFirewallModule', 'Get-LauncherBrowserRuleName', 'Get-ConfirmedNikkeFolder', 'Assert-NoReparsePoint', 'Get-LauncherBrowserProgram', 'Get-LauncherBrowserFirewallRules', 'Set-LauncherBrowserFirewall')) {
        $code += "function $function {`n" + (Get-Item -LiteralPath "Function:\$function").ScriptBlock.ToString() + "`n};"
    }
    $code += "try { Import-LauncherBrowserFirewallModule; `$programs=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$data'))); foreach (`$program in `$programs) { Set-LauncherBrowserFirewall `$program '$Action' }; exit 0 } catch { exit 1 }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    if ($encoded.Length -gt 30000) {
        throw 'Firewall command exceeds the safe Windows command length.'
    }
    return $encoded
}

function Start-LauncherBrowserFirewallOperation([string[]]$Programs, [ValidateSet('Block', 'Remove')][string]$Action) {
    if (Test-HostsAdmin) {
        foreach ($program in $Programs) {
            Set-LauncherBrowserFirewall $program $Action
        }
        return
    }
    $encoded = Get-LauncherBrowserFirewallCommand $Programs $Action
    $executable = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process -FilePath $executable -Verb RunAs -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
    try {
        if ($null -eq $process) { throw 'Administrator operation not confirmed.' }
        $process.Refresh()
        if (-not $process.HasExited -or $null -eq $process.ExitCode -or $process.ExitCode -ne 0) {
            throw 'Administrator operation failed or was incomplete.'
        }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Offer-LauncherBrowserFirewall([ValidateSet('Block', 'Remove')][string]$Action) {
    if ($NoPrompt) { return }
    Write-Report ''
    Write-Report 'ACCÈS INTERNET DU NAVIGATEUR DU LANCEUR (FACULTATIF)' Cyan
    Write-Report 'Cela concerne uniquement tbs_browser.exe dans le lanceur NIKKE, pas Chrome, Edge ou Firefox.'
    Write-Report 'Le blocage peut empêcher la connexion au compte et le chargement des pages du lanceur.' Yellow
    Write-Report 'Il ne supprime aucune infection et ne garantit ni une protection future ni une baisse de la consommation de ressources.'
    Write-Report 'Le programme reste installé. NikkeTrace ne le ferme pas et ne modifie pas les réglages généraux du pare-feu.'
    try {
        Import-LauncherBrowserFirewallModule
        $before = @(Get-LauncherBrowserFirewallRules)
        if ($Action -eq 'Remove') {
            $programs = @($before | ForEach-Object { $_.Program } | Sort-Object -Unique)
            if ($programs.Count -eq 0) {
                Write-Report 'Aucun blocage du navigateur créé par NikkeTrace à retirer.'
                return
            }
            Write-Report 'Seules les règles créées par cette option seront retirées. Les autres blocages seront conservés.'
        } else {
            $programs = @()
            foreach ($install in @(Get-NikkeRemovalCandidates)) {
                try { $programs += Get-LauncherBrowserProgram $install } catch { Write-Detail $_.Exception.Message }
            }
            $programs = @($programs | Sort-Object -Unique)
            if ($programs.Count -eq 0) {
                Write-Host 'Navigateur du lanceur non trouvé automatiquement. Vous pouvez indiquer le dossier du jeu.'
                $path = Read-Host 'Dossier NIKKE ou Launcher [Entrée = annuler]'
                if (-not $path) { return }
                $programs = @(Get-LauncherBrowserProgram $path)
            }
            Write-Report 'Windows bloquera les connexions sortantes de ces programmes, pour tous les profils réseau :'
        }
        foreach ($program in $programs) { Write-Report $program }
        Write-Report 'Windows demandera les droits administrateur si nécessaire, après votre accord.'
        $question = if ($Action -eq 'Block') { 'Bloquer cet accès Internet ?' } else { 'Retirer ces blocages NikkeTrace ?' }
        if (-not (Confirm-Action $question)) {
            Write-Report 'Opération refusée : aucune règle modifiée.'
            return
        }
        try { Start-LauncherBrowserFirewallOperation $programs $Action } catch { Write-Detail $_.Exception.Message }
        $after = @(Get-LauncherBrowserFirewallRules)
        if ($Action -eq 'Remove') {
            if (@($after | Where-Object { $_.Program -in $programs }).Count -gt 0) {
                throw 'Some NikkeTrace firewall rules are still present.'
            }
            Write-Report 'Blocage NikkeTrace retiré ; absence des règles confirmée. Les autres règles sont conservées.' Green
        } else {
            $active = @(Get-LauncherBrowserFirewallRules 'ActiveStore')
            foreach ($program in $programs) {
                if (@($after | Where-Object { $_.Program -ieq $program -and $_.Enabled }).Count -ne 1 -or @($active | Where-Object { $_.Program -ieq $program -and $_.Enabled }).Count -ne 1) {
                    throw 'A requested rule is missing, disabled or inactive.'
                }
            }
            $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
            if ($profiles.Count -ne 3 -or @($profiles | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.AllowLocalFirewallRules -eq 'False' }).Count -gt 0) {
                throw 'Windows Firewall is disabled or local rules are restricted.'
            }
            Write-Report 'Règles de blocage installées et relues dans la configuration active de Windows.' Green
            Write-Report 'Cette vérification ne teste pas les connexions réelles. Une mise à jour qui change le chemin du programme peut nécessiter un nouveau blocage.'
        }
        Write-Report 'Pour revenir en arrière : Options avancées > Accès Internet du navigateur du lanceur > Retirer le blocage.'
    } catch {
        Write-Report 'Opération non confirmée ou partielle. Consultez le rapport ; aucun résultat de protection ne peut être garanti.' Yellow
        Write-Detail $_.Exception.Message
        Write-Report 'Des règles peuvent déjà être présentes. Vous pouvez demander leur retrait dans les options avancées.'
    } finally {
        Save-Report
    }
}


function Show-LauncherBrowserFirewallMenu {
    do {
        Write-Host ''
        Write-Host 'NAVIGATEUR DU LANCEUR — ACCÈS INTERNET' -ForegroundColor Cyan
        Write-Host '1  Bloquer les connexions du navigateur du lanceur'
        Write-Host '2  Retirer le blocage du navigateur du lanceur créé par NikkeTrace'
        Write-Host 'B  Retour'
        $choice = (Read-Host 'Votre choix').Trim().ToLowerInvariant()
        switch ($choice) {
            '1' { Offer-LauncherBrowserFirewall 'Block' }
            '2' { Offer-LauncherBrowserFirewall 'Remove' }
            { $_ -in @('b', '') } { return }
        }
    } while ($true)
}

function Open-PlayerReport {
    Save-Report
    if ($script:ReportPath -and [IO.File]::Exists($script:ReportPath)) {
        Write-Host "Rapport privé : $script:ReportPath"
        try {
            Start-Process -FilePath (Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\notepad.exe') -ArgumentList ('"' + $script:ReportPath + '"') -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host 'Ouvrez ce fichier dans le Bloc-notes pour lire le rapport.'
        }
    }
}

function Show-AdvancedOptions {
    do {
        Write-Host ''
        Write-Host 'OPTIONS AVANCÉES'
        Write-Host '1  Vérifier un navigateur au choix'
        Write-Host '2  Indiquer le dossier du jeu ou de debug.log'
        Write-Host '3  Indiquer un profil de navigateur personnalisé'
        Write-Host '4  Bloquer les sites signalés'
        Write-Host '5  Aide pour une analyse antivirus hors connexion'
        Write-Host '6  Accès Internet du navigateur du lanceur (blocage facultatif)'
        Write-Host 'B  Retour'
        $choice = (Read-Host 'Votre choix').Trim().ToLowerInvariant()
        switch ($choice) {
            '1' {
                $selected = Select-Browser
                if ($selected -ne 'Retour') {
                    return $selected
                }
            }
            '2' {
                $path = Read-Host 'Dossier du jeu ou de debug.log [Entrée = annuler]'
                if ($path) {
                    $script:ExtraNikkePath += $path
                    return 'Tous'
                }
            }
            '3' {
                [void](Offer-CustomBrowserRoot)
            }
            '4' {
                Offer-HostsBlock
            }
            '5' {
                Offer-OfflineScanHelp
            }
            '6' {
                Show-LauncherBrowserFirewallMenu
            }
            {
                $_ -in @('b', '')
            } {
                return 'Retour'
            }
        }
    } while ($true)
}

function Test-CleanupAvailable {
    if ($script:CleanupNeedsRestart -or (Test-Path -LiteralPath (Get-CleanupStatePath))) {
        return $true
    }
    if ($null -ne $script:CurrentSnapshot -and @(Get-CleanupPlan $script:CurrentSnapshot).Count -gt 0) {
        return $true
    }
    foreach ($root in @(Get-LauncherCacheRoots)) {
        if ($null -ne (Get-LocalItem $root)) {
            return $true
        }
    }
    return (@(Get-NikkeRemovalCandidates).Count -gt 0)
}

function Show-Actions {
    do {
        Write-Host ''
        $canClean = Test-CleanupAvailable
        if ($canClean) {
            Write-Host '[C] Voir le nettoyage proposé'
        }
        Write-Host '[V] Revérifier   [D] Détails   [Q] Quitter'
        Write-Host '[R] Rapport technique   [S] Conseils pour vos comptes   [H] Aide   [A] Options avancées'
        $choice = (Read-Host 'Votre choix [Entrée = Quitter]').Trim().ToLowerInvariant()
        switch ($choice) {
            'c' {
                if (-not $canClean) {
                    continue
                }
                if ((Invoke-GuidedCleanup) -eq 'RestartRequired') {
                    return 'RestartRequired'
                }
            }
            'v' {
                return 'Recheck'
            }
            'r' {
                Open-PlayerReport
            }
            'd' {
                Show-ResultDetails
            }
            's' {
                Show-PasswordAdvice
            }
            'h' {
                Show-Help
            }
            'a' {
                $selected = Show-AdvancedOptions
                if ($selected -ne 'Retour') {
                    $script:NextBrowser = $selected
                    return 'Recheck'
                }
            }
            'b' {
                return 'Retour'
            }
            {
                $_ -in @('', 'q', '0')
            } {
                return 'Quitter'
            }
            default {
                Write-Host 'Choisissez une lettre de la liste.'
            }
        }
    } while ($true)
}


function Get-ReadableReport {
    Convert-UiText 'NIKKETRACE 3.2 — RAPPORT PRIVÉ'
    if ($null -ne $script:CurrentSnapshot -and $null -ne $script:CurrentSnapshot.PSObject.Properties['Checks']) {
        foreach ($line in @(Get-PlayerSummary $script:CurrentSnapshot)) {
            Convert-UiText $line
        }
        foreach ($check in $script:CurrentSnapshot.Checks) {
            if ($check.State -eq 'Partiel') {
                Convert-UiText ('Contrôle incomplet : ' + $check.Name)
                if ($null -ne $check.PSObject.Properties['Reasons']) {
                    foreach ($reason in $check.Reasons) {
                        Convert-UiText ('  Raison : ' + $reason)
                    }
                }
                if ($check.Name -match 'Journaux' -and $check.PSObject.Properties['Reasons'] -and @($check.Reasons).Count -eq 1 -and $check.Reasons[0] -like 'Aucun journal NIKKE lisible*') {
                    Convert-UiText '  Conseil : un journal supprimé ne peut pas être relu. Ne réinstallez pas le jeu ; les autres contrôles restent utiles.'
                } else {
                    Convert-UiText '  Conseil : cette zone reste non vérifiée. Si la limite persiste, demandez une assistance avec ce rapport.'
                }
            }
        }
    }
    ''
    Convert-UiText 'DÉTAILS TECHNIQUES ET HISTORIQUE DES ACTIONS'
    foreach ($line in $script:Report) {
        $line
    }
    foreach ($action in $script:CleanupOutcomes) {
        Convert-UiText ("$($action.Outcome) — $($action.Label) : $($action.Location)")
    }
}

function Save-Report {
    param([switch]$Required)
    if (-not $script:ReportPath) {
        $filename = 'Bilan-NIKKE-{0}-{1}.txt' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 6))
        $script:ReportPath = Join-Path (Join-Path $env:LOCALAPPDATA 'NIKKE-Assistance\Reports') $filename
    }
    try {
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($script:ReportPath))
        Get-ReadableReport | Set-Content -LiteralPath $script:ReportPath -Encoding UTF8 -ErrorAction Stop
    } catch {
        try {
            $script:ReportPath = Join-Path $env:TEMP ([IO.Path]::GetFileName($script:ReportPath))
            Get-ReadableReport | Set-Content -LiteralPath $script:ReportPath -Encoding UTF8 -ErrorAction Stop
        } catch {
            if ($Required) {
                throw 'La sauvegarde du rapport a échoué.'
            }
            Write-Host 'Bilan non enregistré : gardez cette fenêtre ouverte pour lire le résultat.'
            return
        }
    }
}

function Invoke-NikkeCheck {
    Initialize-Report
    $offerDomainBlock = $false
    $script:HistoricalExposure = $script:SessionExposure
    Write-Host ''
    Write-Host 'NIKKETRACE — VERSION 3.2 — WINDOWS' -ForegroundColor Cyan
    Write-Host 'Vérification des traces connues de cet incident, sans diagnostic antivirus complet.'
    Write-Host 'Avant de commencer : déconnectez ce PC d Internet, fermez NIKKE, son lanceur et les navigateurs. Vérifiez aussi les icônes près de l horloge.'
    Write-Host 'Le contrôle reste possible si le jeu a déjà été désinstallé. Ne le réinstallez pas pour cette vérification.'
    if (-not $NoPrompt) {
        do {
            Write-Host ''
            Write-Host '1  Vérification complète et nettoyage guidé (recommandé)'
            Write-Host 'S  Conseils pour vos comptes'
            Write-Host 'H  Aide'
            Write-Host 'A  Options avancées'
            Write-Host '0  Quitter'
            $choice = (Read-Host 'Votre choix [Entrée = 1]').Trim().ToLowerInvariant()
            $offerDomainBlock = $choice -in @('', '1')
            if ($choice -in @('0', 'q')) {
                return 'Quitter'
            }
            if ($choice -eq 's') {
                Show-PasswordAdvice
            }
            if ($choice -eq 'h') {
                Show-Help
            }
            if ($choice -eq 'a') {
                $selected = Show-AdvancedOptions
                if ($selected -ne 'Retour') {
                    $script:NextBrowser = $selected
                    $choice = '1'
                }
            }
        } while ($choice -notin @('', '1'))
        $Mode = 'Verifier'
        $Navigateur = 'Tous'
    }
    do {
        if ($script:NextBrowser) {
            $Navigateur = $script:NextBrowser
            $Mode = if ($Navigateur -eq 'Tous') {
                'Verifier'
            } else {
                'Navigateurs'
            }
            $script:NextBrowser = $null
        }
        Write-Detail "NikkeTrace 3.2 — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz') — Mode : $Mode / $Navigateur"
        if ($Mode -ne 'Navigateurs') {
            $script:QuietScan = $true
            try {
                $locations = @(Get-NikkeResidualPaths) + $NikkePath + $script:ExtraNikkePath
                try {
                    $locations += @(Get-NikkeInstallPaths)
                }
                catch {
                    Add-Issue 'Installation non localisée : les autres contrôles continuent.'
                }
                $script:ScanPaths = @($locations | Where-Object {
                        $_
                    } | Sort-Object -Unique)
                $script:DiscoveryIssues = @($script:Issues.ToArray())
            } finally {
                $script:QuietScan = $false
            }
        }
        if (-not $NoPrompt) {
            Offer-BrowserClosure -Scope $Navigateur
        }
        Write-Host 'Recherche des traces connues. Aucun changement pendant la vérification ; chaque intervention nécessite votre accord.'
        $script:CurrentSnapshot = Invoke-TraceScan
        Show-Snapshot $script:CurrentSnapshot
        Save-Report
        $cleanupResult = 'NoAction'
        if (-not $NoPrompt -and (Test-CleanupAvailable)) {
            $cleanupResult = Invoke-GuidedCleanup
            if ($cleanupResult -eq 'Failed') {
                Show-Snapshot $script:CurrentSnapshot
            }
        }
        if (-not $NoPrompt -and $offerDomainBlock) {
            $offerDomainBlock = $false
            Offer-HostsBlock -Guided
        }
        if ($cleanupResult -eq 'RestartRequired') {
            Show-Snapshot $script:CurrentSnapshot
            Write-Advice -ReportOnly
            Save-Report
            Write-Host "Rapport privé : $script:ReportPath"
            [void](Read-Host 'Appuyez sur Entrée pour fermer, puis redémarrez Windows')
            return 'Quitter'
        }
        Write-Advice -ReportOnly
        Save-Report
        if ($NoPrompt) {
            return 'Quitter'
        }
        $navigation = Show-Actions
        if ($navigation -eq 'RestartRequired') {
            [void](Read-Host 'Appuyez sur Entrée pour fermer, puis redémarrez Windows')
            return 'Quitter'
        }
        if ($navigation -eq 'Retour') {
            Save-Report
            return 'Retour'
        }
    } while ($navigation -eq 'Recheck')
    Save-Report
    Write-Host "Rapport privé : $script:ReportPath"
    Write-Host 'Avant de partager ce rapport, masquez les informations personnelles dans les chemins.'
    return 'Quitter'
}


if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ($env:OS -ne 'Windows_NT') {
            throw 'Cet outil nécessite Windows.'
        }
        if (-not $NoPrompt -and -not $PSBoundParameters.ContainsKey('Language')) {
            Select-UiLanguage
        }
        do {
            $navigation = Invoke-NikkeCheck
        } while ($navigation -eq 'Retour')
    } catch {
        Write-Host "ACTION NON TERMINÉE : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Aucun nettoyage ne peut être confirmé. Utilisez Sécurité Windows ou demandez une assistance.'
        if (-not $NoPrompt) {
            [void](Read-Host 'Entrée pour fermer')
        }
        exit 1
    }
}
