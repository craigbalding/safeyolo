#!/bin/bash
# Install persistent udev rule for KVM ACL
echo 'KERNEL=="kvm", SUBSYSTEM=="misc", RUN+="/usr/bin/setfacl -m u:100000:rw /dev/kvm"' | \
  sudo tee /etc/udev/rules.d/99-safeyolo-kvm.rules

echo "=== rule ==="
cat /etc/udev/rules.d/99-safeyolo-kvm.rules

echo "=== reload ==="
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=misc
sleep 1

echo "=== acl ==="
getfacl /dev/kvm 2>&1
