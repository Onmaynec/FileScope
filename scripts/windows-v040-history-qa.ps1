[CmdletBinding()]
param(
    [ValidateSet('SelfTest', 'Inspect', 'AssertCurrentUser', 'AssertForeignUserRejected', 'AssertPortable', 'Snapshot', 'AssertRestartStable', 'AssertCleared')]
    [string]$Mode = 'Inspect',
    [string]$AppDataRoot,
    [string]$HistoryDirectory,
    [string]$GenerationPath,
    [string]$PortableExecutable,
    [string]$SnapshotPath,
    [string]$BaselinePath,
    [string]$ExpectedSourceUser,
    [string[]]$PlaintextMarker = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Identifier = 'com.filescope.desktop'
$script:HistoryStorageVersion = 2
$script:ReportSchemaVersion = 1
$script:DpapiMagic = [System.Text.Encoding]::ASCII.GetBytes('FSDPAPI1')

function Fail([string]$Message) {
    throw "FileScope v0.4.0 Windows QA: $Message"
}

function Resolve-AppDataRoot {
    if ($AppDataRoot) {
        return [System.IO.Path]::GetFullPath($AppDataRoot)
    }
    if (-not $env:APPDATA) {
        Fail 'APPDATA не определён. Передайте -AppDataRoot явно.'
    }
    return [System.IO.Path]::GetFullPath((Join-Path $env:APPDATA $script:Identifier))
}

function Resolve-HistoryDirectory {
    if ($HistoryDirectory) {
        return [System.IO.Path]::GetFullPath($HistoryDirectory)
    }
    return Join-Path (Resolve-AppDataRoot) 'history'
}

function Get-HistoryFiles([string]$Directory) {
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return @()
    }
    return @(
        Get-ChildItem -LiteralPath $Directory -File -Force |
            Where-Object {
                $_.Name.StartsWith('reports-v2-', [System.StringComparison]::Ordinal) -and
                ($_.Name.EndsWith('.bin', [System.StringComparison]::OrdinalIgnoreCase) -or
                 $_.Name.EndsWith('.json', [System.StringComparison]::OrdinalIgnoreCase) -or
                 $_.Name.EndsWith('.tmp', [System.StringComparison]::OrdinalIgnoreCase))
            } |
            Sort-Object Name
    )
}

function Test-StartsWithBytes([byte[]]$Value, [byte[]]$Prefix) {
    if ($Value.Length -lt $Prefix.Length) { return $false }
    for ($index = 0; $index -lt $Prefix.Length; $index++) {
        if ($Value[$index] -ne $Prefix[$index]) { return $false }
    }
    return $true
}

function Test-ContainsBytes([byte[]]$Value, [byte[]]$Needle) {
    if ($Needle.Length -eq 0) { return $true }
    if ($Value.Length -lt $Needle.Length) { return $false }
    for ($start = 0; $start -le $Value.Length - $Needle.Length; $start++) {
        $matches = $true
        for ($offset = 0; $offset -lt $Needle.Length; $offset++) {
            if ($Value[$start + $offset] -ne $Needle[$offset]) {
                $matches = $false
                break
            }
        }
        if ($matches) { return $true }
    }
    return $false
}

function Unprotect-Generation([byte[]]$Stored) {
    if (-not (Test-StartsWithBytes $Stored $script:DpapiMagic)) {
        Fail 'generation не имеет wrapper FSDPAPI1 и не может считаться DPAPI current-user payload.'
    }
    $cipherLength = $Stored.Length - $script:DpapiMagic.Length
    $cipher = [byte[]]::new($cipherLength)
    [Array]::Copy($Stored, $script:DpapiMagic.Length, $cipher, 0, $cipherLength)
    return [System.Security.Cryptography.ProtectedData]::Unprotect(
        $cipher,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
}

function Protect-ForSelfTest([byte[]]$Plaintext) {
    $cipher = [System.Security.Cryptography.ProtectedData]::Protect(
        $Plaintext,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $wrapped = [byte[]]::new($script:DpapiMagic.Length + $cipher.Length)
    [Array]::Copy($script:DpapiMagic, 0, $wrapped, 0, $script:DpapiMagic.Length)
    [Array]::Copy($cipher, 0, $wrapped, $script:DpapiMagic.Length, $cipher.Length)
    return $wrapped
}

function Get-ProtectionLabel([System.IO.FileInfo]$File) {
    if ($File.Name.EndsWith('.tmp', [System.StringComparison]::OrdinalIgnoreCase)) {
        return 'temporary'
    }
    $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
    if (Test-StartsWithBytes $bytes $script:DpapiMagic) { return 'dpapiCurrentUser' }
    return 'plaintextOrUnknown'
}

function Get-State([string]$Directory) {
    $files = @(Get-HistoryFiles $Directory)
    $items = foreach ($file in $files) {
        [ordered]@{
            name = $file.Name
            length = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            protection = Get-ProtectionLabel $file
            lastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
        }
    }
    return [ordered]@{
        schema = 'filescope-v040-windows-history-qa-v1'
        machine = $env:COMPUTERNAME
        user = $env:USERNAME
        identifier = $script:Identifier
        appDataRoot = (Resolve-AppDataRoot)
        historyDirectory = $Directory
        files = @($items)
    }
}

function Assert-CurrentUserState([string]$Directory, [string[]]$Markers) {
    $files = @(Get-HistoryFiles $Directory)
    $temp = @($files | Where-Object { $_.Name.EndsWith('.tmp', [System.StringComparison]::OrdinalIgnoreCase) })
    if ($temp.Count -gt 0) {
        Fail "обнаружены orphan temp-файлы: $($temp.Name -join ', ')"
    }

    $plaintext = @($files | Where-Object { $_.Name.EndsWith('.json', [System.StringComparison]::OrdinalIgnoreCase) })
    if ($plaintext.Count -gt 0) {
        Fail "обнаружены plaintext/legacy generations в healthy DPAPI-проверке: $($plaintext.Name -join ', ')"
    }

    $bins = @($files | Where-Object { $_.Name.EndsWith('.bin', [System.StringComparison]::OrdinalIgnoreCase) })
    if ($bins.Count -eq 0) {
        Fail "в $Directory нет reports-v2-*.bin; сначала сохраните минимум один report в v0.4.0."
    }

    $validated = 0
    foreach ($file in $bins) {
        $stored = [System.IO.File]::ReadAllBytes($file.FullName)
        if (-not (Test-StartsWithBytes $stored $script:DpapiMagic)) {
            Fail "$($file.Name) не начинается с FSDPAPI1."
        }
        foreach ($marker in $Markers) {
            if ([string]::IsNullOrEmpty($marker)) { continue }
            $markerBytes = [System.Text.Encoding]::UTF8.GetBytes($marker)
            if (Test-ContainsBytes $stored $markerBytes) {
                Fail "$($file.Name) содержит контрольный plaintext marker '$marker'."
            }
        }

        try {
            $plain = Unprotect-Generation $stored
        } catch {
            Fail "$($file.Name) не расшифровывается DPAPI current-user: $($_.Exception.Message)"
        }
        $jsonText = [System.Text.Encoding]::UTF8.GetString($plain)
        try {
            $envelope = $jsonText | ConvertFrom-Json -Depth 100
        } catch {
            Fail "$($file.Name) после DPAPI decrypt не содержит валидный JSON envelope: $($_.Exception.Message)"
        }
        if ([int]$envelope.storageVersion -ne $script:HistoryStorageVersion) {
            Fail "$($file.Name): storageVersion=$($envelope.storageVersion), ожидалось $script:HistoryStorageVersion."
        }
        if ([int]$envelope.reportSchemaVersion -ne $script:ReportSchemaVersion) {
            Fail "$($file.Name): reportSchemaVersion=$($envelope.reportSchemaVersion), ожидалось $script:ReportSchemaVersion."
        }
        if ($null -eq $envelope.reports) {
            Fail "$($file.Name): JSON envelope не содержит reports."
        }
        $validated++
    }

    Write-Host "PASS: $validated DPAPI generation(s) расшифровываются только в current-user контексте harness'а; wrapper/schema валидны."
}

function Assert-ForeignUserRejected([string]$Path, [string]$SourceUser) {
    if (-not $Path) { Fail 'для AssertForeignUserRejected обязателен -GenerationPath.' }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        Fail "generation не найдена: $resolved"
    }
    if ($SourceUser -and $env:USERNAME -eq $SourceUser) {
        Fail "тест запущен тем же Windows user '$SourceUser'. Выполните команду из другого профиля."
    }

    $before = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    $stored = [System.IO.File]::ReadAllBytes($resolved)
    if (-not (Test-StartsWithBytes $stored $script:DpapiMagic)) {
        Fail 'foreign-user fixture не является FSDPAPI1 generation.'
    }

    $decryptSucceeded = $false
    try {
        $null = Unprotect-Generation $stored
        $decryptSucceeded = $true
    } catch {
        Write-Host "Ожидаемый DPAPI reject: $($_.Exception.Message)"
    }
    if ($decryptSucceeded) {
        Fail 'DPAPI generation неожиданно расшифровалась в текущем user profile.'
    }
    $after = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    if ($before -ne $after) {
        Fail 'foreign-user test изменил исходную generation.'
    }
    Write-Host 'PASS: другой Windows user не расшифровал generation; файл остался byte-for-byte неизменным.'
}

function Assert-PortableLayout([string]$Executable) {
    if (-not $Executable) { Fail 'для AssertPortable обязателен -PortableExecutable.' }
    $resolved = [System.IO.Path]::GetFullPath($Executable)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        Fail "portable EXE не найден: $resolved"
    }
    $exeDirectory = Split-Path -Parent $resolved
    $adjacentHistory = Join-Path $exeDirectory 'history'
    if (Test-Path -LiteralPath $adjacentHistory) {
        Fail "рядом с portable EXE появился history directory: $adjacentHistory"
    }
    $adjacentPayload = @(
        Get-ChildItem -LiteralPath $exeDirectory -File -Force |
            Where-Object { $_.Name.StartsWith('reports-v2-', [System.StringComparison]::Ordinal) }
    )
    if ($adjacentPayload.Count -gt 0) {
        Fail "рядом с portable EXE найдены history payload: $($adjacentPayload.Name -join ', ')"
    }

    $appData = Resolve-AppDataRoot
    $appDataFull = [System.IO.Path]::GetFullPath($appData).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $exeFull = [System.IO.Path]::GetFullPath($exeDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($appDataFull.StartsWith($exeFull + [IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
        $appDataFull -eq $exeFull) {
        Fail 'app-data root находится внутри portable directory, что нарушает portable policy.'
    }
    Write-Host "PASS: portable directory не содержит history payload; expected per-user app-data: $appData"
}

function Write-StateSnapshot([string]$Directory, [string]$Path) {
    if (-not $Path) { Fail 'для Snapshot обязателен -SnapshotPath.' }
    $state = Get-State $Directory
    $json = $state | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    Write-Host "PASS: snapshot сохранён: $Path"
}

function Assert-RestartStable([string]$Directory, [string]$Path) {
    if (-not $Path) { Fail 'для AssertRestartStable обязателен -BaselinePath.' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "baseline не найден: $Path" }
    $baseline = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
    $current = Get-State $Directory
    $baselinePairs = @($baseline.files | ForEach-Object { "$($_.name):$($_.sha256)" } | Sort-Object)
    $currentPairs = @($current.files | ForEach-Object { "$($_.name):$($_.sha256)" } | Sort-Object)
    if (($baselinePairs -join "`n") -ne ($currentPairs -join "`n")) {
        Fail 'history generations изменились между snapshot и restart без ожидаемой history write. Проверьте diff вручную.'
    }
    Write-Host 'PASS: после restart набор generation names + SHA-256 остался неизменным.'
}

function Assert-ClearedState([string]$Directory) {
    $files = @(Get-HistoryFiles $Directory)
    if ($files.Count -gt 0) {
        Fail "после full clear остались history payload: $($files.Name -join ', ')"
    }
    Write-Host 'PASS: history directory отсутствует или не содержит известных report generations/temp payload.'
}

function Invoke-SelfTest {
    if (-not $IsWindows) { Fail 'SelfTest предназначен только для Windows.' }
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("filescope-v040-qa-" + [guid]::NewGuid().ToString('N'))
    $history = Join-Path $root 'appdata\history'
    $portableDir = Join-Path $root 'portable'
    New-Item -ItemType Directory -Path $history -Force | Out-Null
    New-Item -ItemType Directory -Path $portableDir -Force | Out-Null
    try {
        $marker = 'FileScope-v040-QA-secret-' + [guid]::NewGuid().ToString('N')
        $envelope = [ordered]@{
            storageVersion = $script:HistoryStorageVersion
            reportSchemaVersion = $script:ReportSchemaVersion
            savedAt = [DateTime]::UtcNow.ToString('o')
            reports = @([ordered]@{ schemaVersion = 1; id = $marker })
        }
        $plain = [System.Text.Encoding]::UTF8.GetBytes(($envelope | ConvertTo-Json -Depth 10 -Compress))
        $wrapped = Protect-ForSelfTest $plain
        $generation = Join-Path $history 'reports-v2-00000000000000000001-selftest.bin'
        [System.IO.File]::WriteAllBytes($generation, $wrapped)

        $script:AppDataRoot = Join-Path $root 'appdata'
        $script:HistoryDirectory = $history
        Assert-CurrentUserState $history @($marker)

        $snapshot = Join-Path $root 'before-restart.json'
        Write-StateSnapshot $history $snapshot
        Assert-RestartStable $history $snapshot

        $portable = Join-Path $portableDir 'filescope.exe'
        [System.IO.File]::WriteAllBytes($portable, [byte[]](0x4d, 0x5a))
        Assert-PortableLayout $portable

        Remove-Item -LiteralPath $generation -Force
        Assert-ClearedState $history
        Write-Host 'PASS: Windows v0.4.0 history QA harness self-test complete.'
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    if (-not $IsWindows) {
        Fail 'этот harness должен выполняться на Windows.'
    }

    $directory = Resolve-HistoryDirectory
    switch ($Mode) {
        'SelfTest' { Invoke-SelfTest }
        'Inspect' { Get-State $directory | ConvertTo-Json -Depth 8 }
        'AssertCurrentUser' { Assert-CurrentUserState $directory $PlaintextMarker }
        'AssertForeignUserRejected' { Assert-ForeignUserRejected $GenerationPath $ExpectedSourceUser }
        'AssertPortable' { Assert-PortableLayout $PortableExecutable }
        'Snapshot' { Write-StateSnapshot $directory $SnapshotPath }
        'AssertRestartStable' { Assert-RestartStable $directory $BaselinePath }
        'AssertCleared' { Assert-ClearedState $directory }
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
