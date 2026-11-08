#!/bin/bash
# Script Installer VPS
# Dibuat oleh: Julak Bantur
# Fixed & Updated by Naga VPN
###############
apt update
apt install curl -y
apt install wget -y
apt install jq -y
apt install shc -y
###############
NC='\033[0m'
rbg='\033[41;37m'
r='\033[1;91m'
g='\033[1;92m'
y='\033[1;93m'
u='\033[0;35m'
c='\033[0;96m'
w='\033[1;97m'
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
GRAY="\e[1;30m"
VC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
###############
if [ "${EUID}" -ne 0 ]; then
echo "${r}You need to run this script as root${NC}"
sleep 2
exit 0
fi

if [[ ! -f /root/.isp ]]; then
curl -sS ipinfo.io/org?token=7a814b6263b02c > /root/.isp
fi
if [[ ! -f /root/.city ]]; then
curl -sS ipinfo.io/city?token=7a814b6263b02c > /root/.city
fi
if [[ ! -f /root/.myip ]]; then
curl -sS ipv4.icanhazip.com > /root/.myip
fi

export IP=$(cat /root/.myip);
export ISP=$(cat /root/.isp);
export CITY=$(cat /root/.city);

# Repository Github
jamban="https://raw.githubusercontent.com/minionstore/c/main/"

source /etc/os-release

function lane_atas() {
echo -e "${c}┌──────────────────────────────────────────┐${NC}"
}
function lane_bawah() {
echo -e "${c}└──────────────────────────────────────────┘${NC}"
}

apt update

if [[ "$( uname -m | awk '{print $1}' )" == "x86_64" ]]; then
echo -ne
else
echo -e "${r} Your Architecture Is Not Supported ( ${y}$( uname -m )${NC} )"
exit 1
fi

if [[ ${ID} == "ubuntu" || ${ID} == "debian" ]]; then
echo -ne
else
echo -e " ${r}This Script only Support for OS"
echo -e ""
echo -e " - ${y}Ubuntu 18.04${NC}"
echo -e " - ${y}Ubuntu 20.04${NC}"
echo -e " - ${y}Ubuntu 22.04${NC}"
echo -e " - ${y}Ubuntu 24.04${NC}"
echo -e " - ${y}Ubuntu 25.10${NC}"
echo ""
echo -e " - ${y}Debian 10${NC}"
echo -e " - ${y}Debian 11${NC}"
echo -e " - ${y}Debian 12${NC}"
echo -e " - ${y}Debian 13${NC}"
exit 0
fi

if [[ ${VERSION_ID} == "10" || ${VERSION_ID} == "11" || ${VERSION_ID} == "12" || ${VERSION_ID} == "13" || \
      ${VERSION_ID} == "18.04" || ${VERSION_ID} == "20.04" || ${VERSION_ID} == "22.04" || ${VERSION_ID} == "24.04" || ${VERSION_ID} == "25.10" ]]; then
    echo -ne
else
    echo -e " ${r}This Script only Support for OS"
    echo -e ""
    echo -e " - ${y}Ubuntu 18.04${NC}"
    echo -e " - ${y}Ubuntu 20.04${NC}"
    echo -e " - ${y}Ubuntu 22.04${NC}"
    echo -e " - ${y}Ubuntu 24.04${NC}"
    echo -e " - ${y}Ubuntu 25.10${NC}"
    echo ""
    echo -e " - ${y}Debian 10${NC}"
    echo -e " - ${y}Debian 11${NC}"
    echo -e " - ${y}Debian 12${NC}"
    echo -e " - ${y}Debian 13${NC}"
    exit 0
fi

# Fungsi input domain
function add_domain() {
echo -e ""
clear
    echo -e "   .----------------------------------."
echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
echo -e "   '----------------------------------'"
echo -e "     \e[1;32m1)\e[0m Use your domain"
echo -e "     \e[1;32m2)\e[0m Use random domain "
echo -e "   ------------------------------------"
read -p "   Please select numbers 1-2 or Any Button(Random) : " host
echo ""
if [[ $host == "1" ]]; then
echo -e "   \e[1;32mPlease Enter Your Subdomain $NC"
read -p "   Subdomain: " host1
echo "IP=" >> /var/lib/julak/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
wget ${jamban}service/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
echo -e "Random Subdomain/Domain is Used"
wget ${jamban}service/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
    fi
}

function pasang_domain() {
    mkdir -p /etc/xray
    mkdir -p /var/lib/julak/ >/dev/null 2>&1
    echo "IP=" >> /var/lib/julak/ipvps.conf
    touch /etc/.{ssh,noobzvpns,vmess,vless,trojan,shadowsocks}.db
    mkdir -p /etc/{xray,bot,vmess,vless,trojan,shadowsocks,ssh,noobzvpns,limit,usr}
    touch /etc/noobzvpns/users.json
    mkdir -p /etc/xray/limit
    mkdir -p /etc/xray/limit/{ssh,vmess,vless,trojan,shadowsocks}
    mkdir -p /etc/julak/limit/vmess/ip
    mkdir -p /etc/julak/limit/vless/ip
    mkdir -p /etc/julak/limit/trojan/ip
    mkdir -p /etc/julak/limit/ssh/ip
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/ssh
    mkdir -p /opt/julak/data
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /opt/julak/data/ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/opt/julak/data/ssh.db

add_domain
}

function Dependencies() {
cd
echo "Process Install Dependencies"
sleep 1
apt update -y
apt install sudo -y
sudo apt-get clean all
apt install -y debconf-utils
apt install p7zip-full -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
apt-get autoremove -y
apt install at -y
apt install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install iptables iptables-persistent netfilter-persistent libxml-parser-perl squid screen curl jq bzip2 gzip coreutils rsyslog zip unzip net-tools sed bc apt-transport-https build-essential dirmngr libxml-parser-perl lsof openvpn easy-rsa fail2ban tmux squid dropbear socat cron bash-completion ntpdate xz-utils apt-transport-https chrony pkg-config bison make git speedtest-cli p7zip-full zlib1g-dev python-is-python3 python3-pip shc build-essential nodejs nginx php php-fpm php-cli php-mysql p7zip-full squid libcurl4-openssl-dev haproxy

sudo apt-get autoclean -y >/dev/null 2>&1
sudo apt-get -y --purge remove samba* >/dev/null 2>&1
sudo apt-get -y --purge remove bind9* >/dev/null 2>&1
sudo apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1

echo "Dependencies successfully installed..."
sleep 1.5

wget -q -O /etc/info.txt "${jamban}port.txt"

clear
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
}

function Installasi() {

inssh() {
apt install netfilter-persistent -y
apt-get remove --purge ufw firewalld -y
apt install -y screen curl jq bzip2 gzip vnstat coreutils rsyslog zip unzip git apt-transport-https build-essential -y

export DEBIAN_FRONTEND=noninteractive
MYIP2="s/xxxxxxxxx/$IP/g"
NET=$(ip -o -4 route show to default | awk '{print $5}')
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_NAME=$ID
    OS_VERSION=$VERSION_ID
    echo "Menemukan sistem operasi: $OS_NAME $OS_VERSION"
else
    echo "Tidak dapat menentukan sistem operasi."
    exit 1
fi

country=ID
state=Indonesia
locality=Jakarta
organization=none
organizationalunit=none
commonname=none
email=none

curl -sS ${jamban}service/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password

cd

cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
#!/bin/sh -e
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service

echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y

apt -y install jq shc wget curl figlet ruby
gem install lolcat

ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl git lsof

# Install Webserver
apt -y install nginx php php-fpm php-cli php-mysql libxml-parser-perl
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/default
curl ${jamban}config/nginx.conf > /etc/nginx/nginx.conf
mkdir -p /var/www/html
echo "<?php phpinfo() ?>" > /var/www/html/info.php
chown -R www-data:www-data /var/www/html
chmod -R g+rw /var/www/html

cat > /var/www/html/index.html <<-END
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<meta http-equiv="REFRESH" content="0;url=https://wa.me/6285786766603">
</head>
<body>
<p>Pengalihan URL</p>
</body>
</html>
END
/etc/init.d/nginx restart

# Setting Port SSH
cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 200' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config
/etc/init.d/ssh restart

# Install Dropbear
apt -y install dropbear
sudo dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key
sudo chmod 600 /etc/dropbear/dropbear_dss_host_key
wget -O /etc/default/dropbear "${jamban}service/dropbear"
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart


# ==========================================
# Install Core Xray & SSL (PERBAIKAN MISSING CORE)
# ==========================================
echo -e "${y}Memulai instalasi Core Xray dari XTLS...${NC}"
domain=$(cat /root/domain)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Menarik Config dasar Xray ke direktori /etc/xray
mkdir -p /etc/xray
wget -O /etc/xray/config.json "${jamban}config/xray.conf"

# Generate Sertifikat SSL/TLS menggunakan Acme.sh
apt install socat -y
# Matikan service bentrok port 80 sementara untuk standalone SSL
systemctl stop nginx >/dev/null 2>&1
systemctl stop haproxy >/dev/null 2>&1

curl https://get.acme.sh | sh
~/.acme.sh/acme.sh --register-account -m "admin@$domain"
~/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

systemctl start nginx >/dev/null 2>&1

# Sesuaikan kepemilikan file SSL
chown www-data:www-data /etc/xray/xray.crt
chown www-data:www-data /etc/xray/xray.key
# ==========================================


# Fix Certificate & Routing HAProxy & Xray (PERBAIKAN UTAMA)
mkdir -p /etc/haproxy
mkdir -p /usr/local/etc/xray
if [[ -f /etc/xray/xray.crt && -f /etc/xray/xray.key ]]; then
    cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem
    chmod 600 /etc/haproxy/hap.pem
    chmod 644 /etc/xray/xray.crt /etc/xray/xray.key
fi
ln -sf /etc/xray/config.json /usr/local/etc/xray/config.json
ln -sf /usr/local/bin/xray /usr/bin/xray

# Install WebSocket Service
mkdir -p /etc/websocket
wget -O /etc/websocket/ws.py "${jamban}service/ws.py"
chmod +x /etc/websocket/ws.py

cat > /etc/systemd/system/ws.service << END
[Unit]
Description=Python WebSocket Backend
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /etc/websocket/ws.py 10015
Restart=always

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable ws
systemctl restart ws

# Banner /etc/julak.txt
cat > /etc/julak.txt << END
<p style="text-align:center">
<i><u><br><font color="white"> >>>CONFIG BY </font><font color ="green"> NAGA VPN </font><br>
<b><font color='#800FFFF'> >>>SERVER PREMIUM<<< </font></b><br>
<b><font color='#00FF0A'> ORDER PREMIUM </font></b><br>
https://Wa.me/6285786766603<br>
<b><font color='#00FF0A'> Join Saluran WhatsApp</font></b><br>
https://whatsapp.com/channel/0029VafUuuLB4hdUHpip9K2M<br>
<b><font color='#00FF0A'> website config gratis </font></b><br>
https://nagavpn.blogspot.com<br>
<b><font color='#00FF0A'> Saluran telegram </font></b><br>
https://t.me/NagaVpnTunneling<br>
</p>
END

echo "Banner /etc/julak.txt" >> /etc/ssh/sshd_config

# Clean Cron Automatic Reboot (Mematikan Auto Reboot)
rm -f /etc/cron.d/reboot /etc/cron.d/auto-reboot /etc/cron.daily/reboot
(crontab -l 2>/dev/null | grep -v -E 'reboot|sbin/reboot|systemctl reboot') | crontab -

# Optimization BBR
wget -q ${jamban}service/bbr.sh && chmod +x bbr.sh && ./bbr.sh
rm -f bbr.sh

# Enable System Service
systemctl restart haproxy nginx xray dropbear ssh cron
systemctl enable haproxy nginx xray dropbear ssh cron

}
inssh
}

pasang_domain
Dependencies
Installasi
