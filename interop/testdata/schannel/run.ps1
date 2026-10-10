# run.ps1: Windows SChannel interop tests (S1-S7). Runs the Go peer
# (gopeer.exe, built with the overlay) against the .NET SslStream peer
# (SChannelPeer, SChannel underneath) with client authentication, for the
# identities bp256, bp384 and bp512 of the test PKI, and checks each
# result against its expectation:
#
#   S1, S2  TLS 1.2, Go server and Go client: success on a Brainpool group
#           (26-28); the Go side verifies the peer's Brainpool signature.
#   S3, S4  TLS 1.3 only: SChannel offers the Brainpool groups with their
#           TLS 1.2 code points 26-28 and none of RFC 8734's 31-33 or its
#           signature schemes 0x081A-0x081C, so no handshake with ivory
#           succeeds. A success means SChannel changed: update this.
#   S5      SChannel client with the system's protocols (TLS 1.2 and 1.3)
#           against a Go server for TLS 1.2 and 1.3: fails without
#           tlsutil.TLS12Fallback; with it, TLS 1.2 succeeds.
#   S6      Go client for TLS 1.2 and 1.3 against an SChannel server with
#           the system's protocols: fails. SChannel picks TLS 1.3 and has
#           no algorithm for its Brainpool certificate there; it doesn't
#           fall back to TLS 1.2 (protocol_version alert).
#   S7      Go client for TLS 1.2 only against the same server: TLS 1.2.
#           A client must be configured for TLS 1.2 towards Windows
#           servers with Brainpool identities.
#
# -Informational prints the results and always exits with 0, for
# experiments such as gopeer's -tls13-legacy-groups (passed with
# -GoFlags): with it, the Go server gets past the key exchange but finds
# no signature scheme that SChannel offers for a Brainpool certificate
# in TLS 1.3, and the SChannel server still finds no common algorithm
# (2026-10-10).
#
# Usage: run.ps1 -GoPeer gopeer.exe -NetPeer SChannelPeer.exe -Pki testdata\pki
# The Brainpool groups must be enabled in SChannel first
# (enable-brainpool.ps1; they are off by default).
param(
    [Parameter(Mandatory)][string]$GoPeer,
    [Parameter(Mandatory)][string]$NetPeer,
    [Parameter(Mandatory)][string]$Pki,
    [string[]]$Only = @(),
    [string[]]$GoFlags = @(),
    [switch]$Informational
)
$ErrorActionPreference = 'Stop'
$script:port = 15000
$scratch = Join-Path ([IO.Path]::GetTempPath()) "ivory-schannel-$PID"
New-Item -ItemType Directory -Force $scratch | Out-Null

# Expect: tls12 (success with TLS 1.2 on groups 26-28), tls12-fallback (the
# same, and the Go server's fallback chose it), tls13-legacy (the TLS 1.3
# failure of S3, S4), fail (any failure).
$scenarios = @(
    @{ Id = 'S1'; GoRole = 'server'; Go = '1.2'; Net = '1.2'; Flags = @(); Expect = 'tls12' }
    @{ Id = 'S2'; GoRole = 'client'; Go = '1.2'; Net = '1.2'; Flags = @(); Expect = 'tls12' }
    @{ Id = 'S3'; GoRole = 'server'; Go = '1.3'; Net = '1.3'; Flags = @(); Expect = 'tls13-legacy' }
    @{ Id = 'S4'; GoRole = 'client'; Go = '1.3'; Net = '1.3'; Flags = @(); Expect = 'tls13-legacy' }
    @{ Id = 'S5a'; GoRole = 'server'; Go = '1.2-1.3'; Net = 'default'; Flags = @(); Expect = 'fail' }
    @{ Id = 'S5'; GoRole = 'server'; Go = '1.2-1.3'; Net = 'default'; Flags = @('-tls12-fallback'); Expect = 'tls12-fallback' }
    @{ Id = 'S6'; GoRole = 'client'; Go = '1.2-1.3'; Net = 'default'; Flags = @(); Expect = 'fail' }
    @{ Id = 'S7'; GoRole = 'client'; Go = '1.2'; Net = 'default'; Flags = @(); Expect = 'tls12' }
)

# Start-Listener starts a peer in the background and waits until it
# listens; it returns the process and the files of its output.
function Start-Listener([string]$exe, [string[]]$argv, [string]$name) {
    $out = Join-Path $scratch "$name.out"
    $err = Join-Path $scratch "$name.err"
    $p = Start-Process -FilePath $exe -ArgumentList $argv -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    for ($i = 0; $i -lt 100; $i++) {
        if ((Test-Path $err) -and (Get-Content -Raw $err) -match 'listening') { break }
        if ($p.HasExited) { break }
        Start-Sleep -Milliseconds 200
    }
    return @{ Process = $p; Out = $out; Err = $err }
}

function Read-Json([string]$text) {
    $line = ($text -split "`r?`n" | Where-Object { $_.StartsWith('{') } | Select-Object -Last 1)
    if (-not $line) { return $null }
    return $line | ConvertFrom-Json
}

# Test-Result returns the problems of a result against its expectation.
function Test-Result($s, $go, $net) {
    $problems = @()
    $ok = $go -and -not $go.error -and $net -and -not $net.error
    switch ($s.Expect) {
        { $_ -in 'tls12', 'tls12-fallback' } {
            if (-not $go -or $go.error) { $problems += 'Go side failed' }
            if (-not $net -or $net.error) { $problems += '.NET side failed' }
            if ($ok) {
                if ((26..28) -notcontains [int]$go.group) { $problems += "group $($go.group)" }
                if ($go.version -ne 'TLS 1.2') { $problems += "version $($go.version)" }
                if (-not $go.peer_schemes) { $problems += 'no peer signature checked by VerifyUnsupportedSignature' }
                if ($s.Expect -eq 'tls12-fallback' -and -not $go.fallback) { $problems += 'TLS12Fallback did not choose TLS 1.2' }
            }
        }
        'tls13-legacy' {
            if ($ok) {
                $problems += 'TLS 1.3 succeeded: SChannel changed, update the expectations'
            } elseif ($s.GoRole -eq 'server') {
                $offered = @($go.hello_groups | ForEach-Object { [int]$_ })
                if ($offered -notcontains 26 -or ($offered | Where-Object { $_ -ge 31 -and $_ -le 33 })) {
                    $problems += "SChannel offered groups $($offered -join ',')"
                }
            } elseif (-not $go -or $go.error -notmatch 'protocol version not supported') {
                $problems += "Go client error: $($go.error)"
            }
        }
        'fail' {
            if ($ok) { $problems += "succeeded with $($go.version), want a failure" }
        }
    }
    return $problems
}

$results = @()
foreach ($s in $scenarios) {
    if ($Only.Count -gt 0 -and $Only -notcontains $s.Id) { continue }
    foreach ($bits in '256', '384', '512') {
        $script:port++
        $addr = "127.0.0.1:$($script:port)"
        $ca = Join-Path $Pki "bp$bits-ca.pem"
        $goRole = $s.GoRole
        $netRole = if ($goRole -eq 'server') { 'client' } else { 'server' }
        $goArgs = $GoFlags + $s.Flags + @('-role', $goRole, '-addr', $addr, '-version', $s.Go,
            '-cert', (Join-Path $Pki "bp$bits-$goRole.pem"), '-key', (Join-Path $Pki "bp$bits-$goRole.key"), '-ca', $ca)
        $netArgs = @($netRole, '--addr', $addr, '--version', $s.Net,
            '--cert', (Join-Path $Pki "bp$bits-$netRole.pem"), '--key', (Join-Path $Pki "bp$bits-$netRole.key"), '--ca', $ca)
        $name = "$($s.Id)-bp$bits"
        if ($goRole -eq 'server') {
            $l = Start-Listener $GoPeer $goArgs "$name-go"
            $netText = (& $NetPeer @netArgs 2>$null) -join "`n"
            $l.Process.WaitForExit(90000) | Out-Null
            $goText = Get-Content -Raw $l.Out
        } else {
            $l = Start-Listener $NetPeer $netArgs "$name-net"
            $goText = (& $GoPeer @goArgs 2>$null) -join "`n"
            $l.Process.WaitForExit(90000) | Out-Null
            $netText = Get-Content -Raw $l.Out
        }
        $go = Read-Json $goText
        $net = Read-Json $netText
        Write-Host "== $name (Go $goRole $($s.Go) $($s.Flags -join ' '), .NET $netRole $($s.Net); expect $($s.Expect))"
        Write-Host "go:   $goText"
        Write-Host "net:  $netText"
        $problems = Test-Result $s $go $net
        $results += [pscustomobject]@{
            Test     = $name
            OK       = ($problems.Count -eq 0)
            Version  = $go.version
            Group    = $go.group
            Fallback = [bool]$go.fallback
            Schemes  = (($go.peer_schemes | ForEach-Object { '0x{0:X4}' -f [int]$_ }) -join ',')
            Offered  = (($go.hello_groups | ForEach-Object { $_ }) -join ',')
            Problem  = ($problems -join '; ')
        }
    }
}
$results | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
if ($Informational) { exit 0 }
if ($results | Where-Object { -not $_.OK }) { exit 1 }
exit 0
