#!/bin/bash

function get_external_address() {
	local addr=$( timeout 3 dig +short myip.opendns.com @resolver1.opendns.com || \
	timeout 3 curl -s http://whatismyip.akamai.com/ || \
	timeout 3 curl -s http://ifconfig.io/ip || \
	timeout 3 curl -s http://ipecho.net/plain || \
	timeout 3 curl -s http://ident.me/
	)
	[ $? -ne 0 ] && addr="<this server IP address>"
	echo "$addr"
}

# args: file port password
function generate_config() {
# "fast_open": true reduces connection latency. But it doesn't work on OpenVZ, on old kernels, and on kernels where this feature is disabled
cat > "$1" <<EOF
{
    "server":"0.0.0.0",
    "server_port":$2,
    "mode": "tcp_and_udp",
    "local_port":1080,
    "password":"$3",
    "timeout":300,
    "method":"aes-256-gcm",
    "fast_open": true,
    "plugin":"/etc/shadowsocks-libev/v2ray-plugin",
    "plugin_opts":"server",
    "nameserver":"1.1.1.1"

}
EOF
}

# args: method password
function generate_hash() {
	echo -n "$1":"$2" | base64
}

# args: port
function open_ufw_port() {
	# Open port in firewall if required
	if type ufw > /dev/null; then
	        ufw allow "$PORT"/tcp
	fi
}

# args: port
function open_firewalld_port() {
	# Open port in firewall if required
	if type firewall-cmd > /dev/null; then
		firewall-cmd --zone=public --permanent --add-port="$1"/tcp
		firewall-cmd --reload
	fi
}

# args: password port
function print_config() {
	red=`tput setaf 1`
        GREEN=`tput setaf 2`
        reset=`tput sgr0`
        echo
	echo "${red}Skopiruyte etot kod v klient:${reset}"
	echo "${GREEN}URL: ss://$( generate_hash aes-256-gcm $1 )@$( get_external_address ):$2/?plugin=v2ray-plugin_windows_amd64${reset}"
        echo
        echo "${red}>>>Ne zabud'te ustanovit' plagin V2Ray na klientskoe ustroystvo!${reset}"
}

IFACE=$(ip route get 1.1.1.1 | head -1 | cut -d' ' -f5)
USER=user

[ -z "$PORT" ] && export PORT=443
[ -z "$PASSWORD" ] && export PASSWORD=$( cat /dev/urandom | tr --delete --complement 'a-z0-9' | head --bytes=12 )

[ -e /etc/lsb-release ] && source /etc/lsb-release
[ -e /etc/os-release ] && source /etc/os-release


# Ubuntu 18.04 Bionic
if [ "$DISTRIB_ID $DISTRIB_CODENAME" = "Ubuntu bionic" ]; then

echo "===>>> OBNOVITES' DO Ubuntu 20.04 --- "

# Ubuntu 20.04 Focal
elif [ "$DISTRIB_ID $DISTRIB_CODENAME" = "Ubuntu focal" ]; then

	apt update
	apt install -y shadowsocks-libev

	mkdir -p /etc/shadowsocks-libev
	generate_config /etc/shadowsocks-libev/config.json "$PORT" "$PASSWORD"
        
        
        wget https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.3.1/v2ray-plugin-linux-amd64-v1.3.1.tar.gz
        tar -xf v2ray-plugin-linux-amd64-v1.3.1.tar.gz
        mv v2ray-plugin_linux_amd64 /etc/shadowsocks-libev/v2ray-plugin
        chmod +x  /etc/shadowsocks-libev/v2ray-plugin

        sudo setcap 'cap_net_bind_service=+ep' /usr/bin/ss-server

cd /etc/
    
cat << EOF >> sysctl.conf

# Accept IPv6 advertisements when forwarding is enabled
net.ipv6.conf.all.accept_ra = 2

kernel.sysrq=0
vm.swappiness=0
kernel.core_uses_pid=1
kernel.randomize_va_space=1
kernel.msgmnb=65536
kernel.msgmax=65536
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_syncookies=0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0

#options for ss

fs.file-max = 131072
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
net.core.optmem_max = 8388608
net.core.netdev_max_backlog = 131072
net.core.somaxconn = 131072
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 1048576 4194304
net.ipv4.tcp_wmem = 4096 1048576 4194304
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_keepalive_time = 150
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 720000
net.ipv4.tcp_mtu_probing = 1
EOF

sysctl -p 

cd

cd /etc/security/

cat << EOF >> limits.conf
* soft nofile 131072
* hard nofile 131072
EOF

cd

cd /etc/pam.d/

cat << EOF >> common-session
session required pam_limits.so
EOF

ulimit -n 131072

	systemctl enable shadowsocks-libev
	systemctl restart shadowsocks-libev

	print_config "$PASSWORD" "$PORT"

else

	echo "===>>> Skript podderjivaet tol'ko"
        echo "- Ubuntu 20.04 Focal"
	exit 1

fi
