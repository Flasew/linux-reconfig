#!/bin/sh

sudo kexec -l /boot/vmlinuz-5.15.143+  --initrd=/boot/initrd.img-5.15.143+  --reuse-cmdline
echo "kexec set, reloading in 5 seconds"
sleep 5
sudo kexec -e
