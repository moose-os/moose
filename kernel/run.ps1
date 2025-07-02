param(
    [switch][Alias('d')]$debugging = $false,
    [switch][Alias('l')]$logs = $false,
    [switch][Alias('r')]$release = $false
)

$command = [System.Text.StringBuilder]::new()

[void]$command.Append('qemu-system-x86_64 ')

if ($debugging) {
    [void]$command.Append('-S -gdb tcp:0.0.0.0:1234 ')
}

if ($logs) {
    [void]$command.Append('-d int -D ./log.txt ')
}

[void]$command.Append('-no-reboot ')
[void]$command.Append('-cpu qemu64,apic,fsgsbase ')
[void]$command.Append('-smp 4 ')
[void]$command.Append('-m 256M ')

[void]$command.Append('-netdev tap,id=n1,ifname=tap ')
[void]$command.Append('-device rtl8139,netdev=n1 ')

[void]$command.Append('-drive file=moose.iso,format=raw,if=ide ')
[void]$command.Append('-drive file=fat.img,format=raw,if=ide ')
[void]$command.Append('-serial stdio ')

if ($release) {
    ./package.ps1 -r
}
else {
    ./package.ps1
}

Invoke-Expression $command.ToString()
