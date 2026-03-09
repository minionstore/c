#!/bin/bash
# Script Installer UDP CUSTOM
# Dibuat oleh: Julak Bantur
# Last Update : 2026
# ---------------------------------- #

cd
rm -rf /etc/udp
mkdir -p /etc/udp

# change to time GMT+7
echo "change to time GMT+7"
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# install udp-custom
UDP="https://raw.githubusercontent.com/minionstore/c/main/"
echo downloading udp-custom
wget -O /etc/udp/udp-custom "${UDP}config/udp-custom-linux-amd64"
echo downloading default config
wget -O /etc/udp/config.json "${UDP}config/config.json"
chmod 777 /etc/udp/config.json
chmod +x /etc/udp/udp-custom

if [ -z "$1" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server -exclude $1
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
fi

echo start service udp-custom
systemctl start udp-custom &>/dev/null

echo enable service udp-custom
systemctl enable udp-custom &>/dev/null

echo restart service udp-custom
systemctl restart udp-custom &>/dev/null