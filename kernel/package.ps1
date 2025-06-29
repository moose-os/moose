param(
    [switch][Alias('r')]$release = $false
)

function package_moose([string]$mode) {
    Copy-Item limine.conf -Destination iso_root/boot/limine/
    Copy-Item target/x86_64-moose/$mode/kernel -Destination iso_root/boot/

    wsl xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label iso_root -o moose.iso

    ./limine/limine.exe bios-install moose.iso
}

$mode = "debug"

if ($release) {
    $mode = "release"
}

if (-not (Test-Path -Path iso_root)) {
    New-Item -Path iso_root -ItemType Directory
    New-Item -Path iso_root/boot -ItemType Directory
    New-Item -Path iso_root/boot/limine -ItemType Directory
    New-Item -Path iso_root/EFI/BOOT -ItemType Directory
}

if (-not (Test-Path -Path limine)) {
    git clone https://github.com/limine-bootloader/limine.git --branch=v9.x-binary --depth=1

    Copy-Item limine/limine-bios.sys -Destination iso_root/boot/limine/
    Copy-Item limine/limine-bios-cd.bin -Destination iso_root/boot/limine/
    Copy-Item limine/limine-uefi-cd.bin -Destination iso_root/boot/limine/
    Copy-Item limine/BOOTX64.EFI -Destination iso_root/EFI/BOOT/
    Copy-Item limine/BOOTIA32.EFI -Destination iso_root/EFI/BOOT/
}

if ($release) {
    cargo build -r
}
else {
    cargo build
}

package_moose -mode $mode
