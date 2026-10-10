# enable-brainpool.ps1: enable the Brainpool groups in SChannel (they are
# off by default) and print the resulting order. The GitHub Windows image
# sets the order by group policy (EccCurves under Policies: NistP384,
# NistP256), which overrides what Enable-TlsEccCurve writes, so the
# policy value is set directly. SChannel reads it for new credentials; no
# reboot is needed.
$ErrorActionPreference = 'Stop'
[Environment]::OSVersion.VersionString
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
Write-Host "before: $((Get-TlsEccCurve) -join ', ')"
if (-not (Test-Path $policy)) { New-Item -Path $policy -Force | Out-Null }
$curves = @('brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'curve25519', 'NistP256', 'NistP384')
Set-ItemProperty -Path $policy -Name EccCurves -Type MultiString -Value $curves
foreach ($c in 'brainpoolP512r1', 'brainpoolP384r1', 'brainpoolP256r1') { Enable-TlsEccCurve -Name $c -Position 0 }
Write-Host "after:  $((Get-TlsEccCurve) -join ', ')"
