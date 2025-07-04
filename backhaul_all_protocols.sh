#!/bin/bash

# Script Version
SCRIPT_VERSION="v0.2.0"

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   sleep 1
   exit 1
fi

# Define a function to colorize text
colorize() {
    local color="$1"
    local text="$2"
    local style="${3:-normal}"
    
    # Define ANSI color codes
    local red="\033[31m"
    local green="\033[32m"
    local yellow="\033[33m"
    local cyan="\033[36m"
    local magenta="\033[35m"
    local reset="\033[0m"
    
    # Define ANSI style codes
    local normal="\033[0m"
    local bold="\033[1m"
    
    # Select color code
    local color_code
    case $color in
        red) color_code=$red ;;
        green) color_code=$green ;;
        yellow) color_code=$yellow ;;
        cyan) color_code=$cyan ;;
        magenta) color_code=$magenta ;;
        *) color_code=$reset ;;
    esac
    
    # Select style code
    local style_code
    case $style in
        bold) style_code=$bold ;;
        normal | *) style_code=$normal ;;
    esac
    
    echo -e "${style_code}${color_code}${text}${reset}"
}

# Press key to continue
press_key() {
    read -p "Press any key to continue..."
}

# Function to install dependencies
install_dependencies() {
    for pkg in unzip jq; do
        if ! command -v "$pkg" &> /dev/null; then
            colorize yellow "$pkg is not installed. Installing..." bold
            sleep 1
            if command -v apt-get &> /dev/null; then
                apt-get update
                apt-get install -y "$pkg"
            else
                colorize red "Error: Unsupported package manager. Please install $pkg manually." bold
                press_key
                exit 1
            fi
        fi
    done
}

# Function to download and extract Backhaul Core
download_and_extract_backhaul() {
    local config_dir="/root/backhaul-core"
    local ARCH=$(uname -m)
    local DOWNLOAD_URL=""
    
    case "$ARCH" in
        x86_64)
            DOWNLOAD_URL="https://raw.githubusercontent.com/wafflenoodle/zenith-stash/refs/heads/main/backhaul_amd64.tar.gz"
            ;;
        arm64|aarch64)
            DOWNLOAD_URL="https://raw.githubusercontent.com/wafflenoodle/zenith-stash/refs/heads/main/backhaul_arm64.tar.gz"
            ;;
        *)
            colorize red "Unsupported architecture: $ARCH." bold
            sleep 1
            exit 1
            ;;
    esac
    
    if [[ -f "${config_dir}/backhaul_premium" ]]; then
        colorize yellow "Backhaul Core already installed. Skipping download." bold
        return 0
    fi
    
    colorize cyan "Downloading Backhaul Core..." bold
    sleep 1
    local DOWNLOAD_DIR=$(mktemp -d)
    curl -sSL -o "$DOWNLOAD_DIR/backhaul.tar.gz" "$DOWNLOAD_URL" || {
        colorize red "Failed to download Backhaul Core." bold
        press_key
        exit 1
    }
    
    colorize cyan "Extracting Backhaul Core..." bold
    sleep 1
    mkdir -p "$config_dir"
    tar -xzf "$DOWNLOAD_DIR/backhaul.tar.gz" -C "$config_dir" || {
        colorize red "Failed to extract Backhaul Core." bold
        press_key
        exit 1
    }
    
    chmod u+x "${config_dir}/backhaul_premium"
    rm -rf "$DOWNLOAD_DIR" "${config_dir}/LICENSE" "${config_dir}/README.md"
    colorize green "Backhaul Core installed successfully." bold
}

# Function to check if a port is in use
check_port() {
    local port=$1
    if ss -tlnp "sport = :$port" | grep -q "$port"; then
        return 0
    else
        return 1
    fi
}

# Function to generate a random token
generate_token() {
    openssl rand -hex 16
}

# MTU Fixer Function
mtu_fixer() {
    clear
    colorize cyan "MTU Fixer: Optimizing MTU, BBR, and FQ-Codel" bold
    echo
    
    # Detect network interface
    INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n 1)
    if [[ -z "$INTERFACE" ]]; then
        colorize red "No network interface found." bold
        press_key
        return 1
    fi
    
    # Test MTU values (common range: 1280-1500)
    colorize yellow "Testing MTU values for $INTERFACE..." bold
    local BEST_MTU=1500
    local MIN_MTU=1280
    local MAX_MTU=1500
    local STEP=10
    local BEST_PING=9999
    
    for mtu in $(seq $MAX_MTU -"$STEP" $MIN_MTU); do
        ip link set dev "$INTERFACE" mtu "$mtu"
        PING_RESULT=$(ping -c 4 -s $((mtu - 28)) 8.8.8.8 | grep 'avg' | awk -F'/' '{print $5}')
        if [[ -n "$PING_RESULT" && $(echo "$PING_RESULT < $BEST_PING" | bc -l) -eq 1 ]]; then
            BEST_PING=$PING_RESULT
            BEST_MTU=$mtu
        fi
    done
    
    colorize green "Best MTU for $INTERFACE: $BEST_MTU (Ping: $BEST_PING ms)" bold
    
    # Set MTU permanently
    echo "interface $INTERFACE mtu $BEST_MTU" >> /etc/network/interfaces.d/mtu.conf
    ip link set dev "$INTERFACE" mtu "$BEST_MTU"
    
    # Enable BBR and FQ-Codel
    cat << EOF >> /etc/sysctl.conf
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl -p
    
    # Optimize network settings
    cat << EOF >> /etc/sysctl.conf
net.core.somaxconn = 65536
net.ipv4.tcp_max_syn_backlog = 20480
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_rmem = 16384 1048576 33554432
net.ipv4.tcp_wmem = 16384 1048576 33554432
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 32768
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
vm.swappiness = 10
vm.min_free_kbytes = 65536
EOF
    sysctl -p
    
    # Set Ulimits
    cat << EOF >> /etc/security/limits.conf
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65536
* hard nproc 65536
EOF
    echo "ulimit -n 1048576" >> /etc/profile
    source /etc/profile
    
    colorize green "MTU, BBR, FQ-Codel, and system optimizations applied successfully." bold
    echo "MTU set to $BEST_MTU for $INTERFACE and saved permanently."
    press_key
}

# Function to remove MTU Fixer settings
remove_mtu_fixer() {
    clear
    colorize cyan "Removing MTU Fixer Settings" bold
    echo
    
    # Reset MTU to default (1500)
    INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n 1)
    if [[ -n "$INTERFACE" ]]; then
        ip link set dev "$INTERFACE" mtu 1500
        colorize green "MTU reset to 1500 for $INTERFACE." bold
    fi
    
    # Remove MTU configuration
    rm -f /etc/network/interfaces.d/mtu.conf
    
    # Remove sysctl settings
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
    sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_notsent_lowat/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_window_scaling/d' /etc/sysctl.conf
    sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
    sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
    sed -i '/vm.swappiness/d' /etc/sysctl.conf
    sed -i '/vm.min_free_kbytes/d' /etc/sysctl.conf
    sysctl -p
    
    # Remove Ulimits
    sed -i '/nofile 1048576/d' /etc/security/limits.conf
    sed -i '/nproc 65536/d' /etc/security/limits.conf
    sed -i '/ulimit -n 1048576/d' /etc/profile
    source /etc/profile
    
    colorize green "MTU Fixer settings removed successfully." bold
    press_key
}

# Function to configure Iran server
configure_iran_server() {
    clear
    colorize cyan "Configuring Iran Server" bold
    echo
    
    # Tunnel port
    local tunnel_port=""
    while true; do
        echo -ne "[*] Tunnel port (23-65535): "
        read -r tunnel_port
        if [[ "$tunnel_port" =~ ^[0-9]+$ ]] && [ "$tunnel_port" -gt 22 ] && [ "$tunnel_port" -le 65535 ]; then
            if check_port "$tunnel_port"; then
                colorize red "Port $tunnel_port is in use." bold
            else
                break
            fi
        else
            colorize red "Please enter a valid port number between 23 and 65535." bold
            echo
        fi
    done
    
    # Transport type
    local transport=""
    while [[ ! "$transport" =~ ^(tcp|tcpmux|utcpmux|ws|wsmux|uwsmux|udp|tcptun|faketcptun|kcp|quic)$ ]]; do
        echo -ne "[*] Transport type (tcp/tcpmux/utcpmux/ws/wsmux/uwsmux/udp/tcptun/faketcptun/kcp/quic): "
        read -r transport
        if [[ ! "$transport" =~ ^(tcp|tcpmux|utcpmux|ws|wsmux|uwsmux|udp|tcptun|faketcptun|kcp|quic)$ ]]; then
            colorize red "Invalid transport type." bold
            echo
        fi
    done
    
    # TUN settings for tcptun/faketcptun
    local tun_name="backhaul"
    local tun_subnet="10.10.10.0/24"
    local mtu="1500"
    if [[ "$transport" == "tcptun" || "$transport" == "faketcptun" ]]; then
        echo -ne "[-] TUN Device Name (default backhaul): "
        read -r tun_name
        tun_name="${tun_name:-backhaul}"
        
        while true; do
            echo -ne "[-] TUN Subnet (default 10.10.10.0/24): "
            read -r tun_subnet
            tun_subnet="${tun_subnet:-10.10.10.0/24}"
            if [[ "$tun_subnet" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
                break
            else
                colorize red "Please enter a valid subnet in CIDR notation." bold
                echo
            fi
        done
        
        while true; do
            echo -ne "[-] TUN MTU (576-9000, default 1500): "
            read -r mtu
            mtu="${mtu:-1500}"
            if [[ "$mtu" =~ ^[0-9]+$ ]] && [ "$mtu" -ge 576 ] && [ "$mtu" -le 9000 ]; then
                break
            else
                colorize red "Please enter a valid MTU value between 576 and 9000." bold
                echo
            fi
        done
    fi
    
    # Security Token
    local token=""
    echo -ne "[-] Security Token (press enter for random): "
    read -r token
    token="${token:-$(generate_token)}"
    
    # Channel Size
    local channel_size="2048"
    if [[ "$transport" != "tcptun" && "$transport" != "faketcptun" ]]; then
        while true; do
            echo -ne "[-] Channel Size (64-8192, default 2048): "
            read -r channel_size
            channel_size="${channel_size:-2048}"
            if [[ "$channel_size" =~ ^[0-9]+$ ]] && [ "$channel_size" -gt 64 ] && [ "$channel_size" -le 8192 ]; then
                break
            else
                colorize red "Please enter a valid channel size between 64 and 8192." bold
                echo
            fi
        done
    fi
    
    # Heartbeat
    local heartbeat="10"
    if [[ "$transport" != "tcptun" && "$transport" != "faketcptun" ]]; then
        while true; do
            echo -ne "[-] Heartbeat (1-240 seconds, default 10): "
            read -r heartbeat
            heartbeat="${heartbeat:-10}"
            if [[ "$heartbeat" =~ ^[0-9]+$ ]] && [ "$heartbeat" -gt 1 ] && [ "$heartbeat" -le 240 ]; then
                break
            else
                colorize red "Please enter a valid heartbeat between 1 and 240." bold
                echo
            fi
        done
    fi
    
    # Mux Concurrency
    local mux_con="4"
    if [[ "$transport" =~ ^(tcpmux|wsmux|uwsmux|utcpmux)$ ]]; then
        while true; do
            echo -ne "[-] Mux Concurrency (1-1000, default 4): "
            read -r mux_con
            mux_con="${mux_con:-4}"
            if [[ "$mux_con" =~ ^[0-9]+$ ]] && [ "$mux_con" -gt 0 ] && [ "$mux_con" -le 1000 ]; then
                break
            else
                colorize red "Please enter a valid concurrency between 1 and 1000." bold
                echo
            fi
        done
    fi
    
    # Mux Version
    local mux_version="2"
    if [[ "$transport" =~ ^(tcpmux|wsmux|uwsmux|utcpmux)$ ]]; then
        while true; do
            echo -ne "[-] Mux Version (1 or 2, default 2): "
            read -r mux_version
            mux_version="${mux_version:-2}"
            if [[ "$mux_version" =~ ^[0-9]+$ ]] && [ "$mux_version" -ge 1 ] && [ "$mux_version" -le 2 ]; then
                break
            else
                colorize red "Please enter a valid mux version: 1 or 2." bold
                echo
            fi
        done
    fi
    
    # Enable Sniffer
    local sniffer=""
    while [[ "$sniffer" != "true" && "$sniffer" != "false" ]]; do
        echo -ne "[-] Enable Sniffer (true/false, default false): "
        read -r sniffer
        sniffer="${sniffer:-false}"
        if [[ "$sniffer" == "true" || "$sniffer" == "false" ]]; then
            break
        else
            colorize red "Please enter 'true' or 'false'." bold
            echo
        fi
    done
    
    # Web Port
    local web_port=""
    while true; do
        echo -ne "[-] Web Port (23-65535, 0 to disable, default 0): "
        read -r web_port
        web_port="${web_port:-0}"
        if [[ "$web_port" == "0" ]]; then
            break
        elif [[ "$web_port" =~ ^[0-9]+$ ]] && [ "$web_port" -ge 23 ] && [ "$web_port" -le 65535 ]; then
            if check_port "$web_port"; then
                colorize red "Port $web_port is in use." bold
            else
                break
            fi
        else
            colorize red "Please enter a valid port between 23 and 65535, or 0 to disable." bold
            echo
        fi
    done
    
    # Proxy Protocol
    local proxy_protocol=""
    if [[ ! "$transport" =~ ^(ws|udp|tcptun|faketcptun|kcp|quic)$ ]]; then
        while [[ "$proxy_protocol" != "true" && "$proxy_protocol" != "false" ]]; do
            echo -ne "[-] Enable Proxy Protocol (true/false, default false): "
            read -r proxy_protocol
            proxy_protocol="${proxy_protocol:-false}"
            if [[ "$proxy_protocol" == "true" || "$proxy_protocol" == "false" ]]; then
                break
            else
                colorize red "Please enter 'true' or 'false'." bold
                echo
            fi
        done
    else
        proxy_protocol="false"
    fi
    
    # Ports for forwarding
    colorize green "[*] Supported Port Formats:" bold
    echo "1. 443-600                  - Listen on all ports in the range 443 to 600."
    echo "2. 443-600:5201             - Listen on range 443-600 and forward to 5201."
    echo "3. 443-600=1.1.1.1:5201     - Listen on range 443-600 and forward to 1.1.1.1:5201."
    echo "4. 443                      - Listen on local port 443."
    echo "5. 4000=5000                - Listen on 4000 and forward to 5000."
    echo "6. 127.0.0.2:443=5201       - Bind to 127.0.0.2:443 and forward to 5201."
    echo "7. 443=1.1.1.1:5201         - Listen on 443 and forward to 1.1.1.1:5201."
    echo -ne "[*] Enter ports (comma-separated): "
    read -r input_ports
    input_ports=$(echo "$input_ports" | tr -d ' ')
    IFS=',' read -r -a ports <<< "$input_ports"
    
    # Generate configuration
    local config_dir="/root/backhaul-core"
    cat << EOF > "${config_dir}/iran${tunnel_port}.toml"
[server]
bind_addr = ":${tunnel_port}"
transport = "${transport}"
accept_udp = false
token = "${token}"
keepalive_period = 60
nodelay = true
channel_size = ${channel_size}
heartbeat = ${heartbeat}
mux_con = ${mux_con}
mux_version = ${mux_version}
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 2000000
sniffer = ${sniffer}
web_port = ${web_port}
sniffer_log = "/root/log.json"
log_level = "info"
proxy_protocol = ${proxy_protocol}
tun_name = "${tun_name}"
tun_subnet = "${tun_subnet}"
mtu = ${mtu}

ports = [
EOF
    
    for port in "${ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+-[0-9]+$ || "$port" =~ ^[0-9]+-[0-9]+:[0-9]+$ || "$port" =~ ^[0-9]+-[0-9]+=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[0-9]+$ || "$port" =~ ^[0-9]+$ || "$port" =~ ^[0-9]+=[0-9]+$ || "$port" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[0-9]+=[0-9]+$ || "$port" =~ ^[0-9]+=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
            echo "    \"$port\"," >> "${config_dir}/iran${tunnel_port}.toml"
        else
            colorize red "[ERROR] Invalid port mapping: $port. Skipping." bold
        fi
    done
    echo "]" >> "${config_dir}/iran${tunnel_port}.toml"
    
    # Create systemd service
    local service_dir="/etc/systemd/system"
    cat << EOF > "${service_dir}/backhaul-iran${tunnel_port}.service"
[Unit]
Description=Backhaul Iran Server (Port ${tunnel_port})
After=network.target

[Service]
Type=simple
ExecStart=${config_dir}/backhaul_premium -c ${config_dir}/iran${tunnel_port}.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    if systemctl enable --now "backhaul-iran${tunnel_port}.service"; then
        colorize green "Iran server service (port $tunnel_port) started and enabled." bold
    else
        colorize red "Failed to start Iran server service." bold
        press_key
        exit 1
    fi
    
    colorize green "Iran server configured successfully." bold
    echo "Configuration file: ${config_dir}/iran${tunnel_port}.toml"
    echo "Token: $token"
    press_key
}

# Function to configure Kharej server
configure_kharej_server() {
    clear
    colorize cyan "Configuring Kharej Server" bold
    echo
    
    # Iran server address
    local server_addr=""
    while true; do
        echo -ne "[*] Iran server IP address (IPv4/IPv6): "
        read -r server_addr
        if [[ -n "$server_addr" ]]; then
            break
        else
            colorize red "Server address cannot be empty." bold
            echo
        fi
    done
    
    # Tunnel port
    local tunnel_port=""
    while true; do
        echo -ne "[*] Tunnel port (23-65535): "
        read -r tunnel_port
        if [[ "$tunnel_port" =~ ^[0-9]+$ ]] && [ "$tunnel_port" -gt 22 ] && [ "$tunnel_port" -le 65535 ]; then
            break
        else
            colorize red "Please enter a valid port number between 23 and 65535." bold
            echo
        fi
    done
    
    # Transport type
    local transport=""
    while [[ ! "$transport" =~ ^(tcp|tcpmux|utcpmux|ws|wsmux|uwsmux|udp|tcptun|faketcptun|kcp|quic)$ ]]; do
        echo -ne "[*] Transport type (tcp/tcpmux/utcpmux/ws/wsmux/uwsmux/udp/tcptun/faketcptun/kcp/quic): "
        read -r transport
        if [[ ! "$transport" =~ ^(tcp|tcpmux|utcpmux|ws|wsmux|uwsmux|udp|tcptun|faketcptun|kcp|quic)$ ]]; then
            colorize red "Invalid transport type." bold
            echo
        fi
    done
    
    # TUN settings for tcptun/faketcptun
    local tun_name="backhaul"
    local tun_subnet="10.10.10.0/24"
    local mtu="1500"
    if [[ "$transport" == "tcptun" || "$transport" == "faketcptun" ]]; then
        echo -ne "[-] TUN Device Name (default backhaul): "
        read -r tun_name
        tun_name="${tun_name:-backhaul}"
        
        while true; do
            echo -ne "[-] TUN Subnet (default 10.10.10.0/24): "
            read -r tun_subnet
            tun_subnet="${tun_subnet:-10.10.10.0/24}"
            if [[ "$tun_subnet" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
                break
            else
                colorize red "Please enter a valid subnet in CIDR notation." bold
                echo
            fi
        done
        
        while true; do
            echo -ne "[-] TUN MTU (576-9000, default 1500): "
            read -r mtu
            mtu="${mtu:-1500}"
            if [[ "$mtu" =~ ^[0-9]+$ ]] && [ "$mtu" -ge 576 ] && [ "$mtu" -le 9000 ]; then
                break
            else
                colorize red "Please enter a valid MTU value between 576 and 9000." bold
                echo
            fi
        done
    fi
    
    # Edge IP
    local edge_ip=""
    if [[ "$transport" =~ ^(ws|wsmux|uwsmux)$ ]]; then
        echo -ne "[-] Edge IP/Domain (optional, press enter to disable): "
        read -r edge_ip
        if [[ -z "$edge_ip" ]]; then
            edge_ip="#edge_ip = \"188.114.96.0\""
        else
            edge_ip="edge_ip = \"$edge_ip\""
        fi
    else
        edge_ip="#edge_ip = \"188.114.96.0\""
    fi
    
    # Security Token
    local token=""
    echo -ne "[-] Security Token (press enter for random): "
    read -r token
    token="${token:-$(generate_token)}"
    
    # Connection Pool
    local connection_pool="4"
    if [[ "$transport" != "tcptun" && "$transport" != "faketcptun" ]]; then
        while true; do
            echo -ne "[-] Connection Pool (1-1024, default 4): "
            read -r connection_pool
            connection_pool="${connection_pool:-4}"
            if [[ "$connection_pool" =~ ^[0-9]+$ ]] && [ "$connection_pool" -gt 1 ] && [ "$connection_pool" -le 1024 ]; then
                break
            else
                colorize red "Please enter a valid connection pool between 1 and 1024." bold
                echo
            fi
        done
    fi
    
    # Mux Version
    local mux_version="2"
    if [[ "$transport" =~ ^(tcpmux|wsmux|uwsmux|utcpmux)$ ]]; then
        while true; do
            echo -ne "[-] Mux Version (1 or 2, default 2): "
            read -r mux_version
            mux_version="${mux_version:-2}"
            if [[ "$mux_version" =~ ^[0-9]+$ ]] && [ "$mux_version" -ge 1 ] && [ "$mux_version" -le 2 ]; then
                break
            else
                colorize red "Please enter a valid mux version: 1 or 2." bold
                echo
            fi
        done
    fi
    
    # Enable Sniffer
    local sniffer=""
    while [[ "$sniffer" != "true" && "$sniffer" != "false" ]]; do
        echo -ne "[-] Enable Sniffer (true/false, default false): "
        read -r sniffer
        sniffer="${sniffer:-false}"
        if [[ "$sniffer" == "true" || "$sniffer" == "false" ]]; then
            break
        else
            colorize red "Please enter 'true' or 'false'." bold
            echo
        fi
    done
    
    # Web Port
    local web_port=""
    while true; do
        echo -ne "[-] Web Port (23-65535, 0 to disable, default 0): "
        read -r web_port
        web_port="${web_port:-0}"
        if [[ "$web_port" == "0" ]]; then
            break
        elif [[ "$web_port" =~ ^[0-9]+$ ]] && [ "$web_port" -ge 23 ] && [ "$web_port" -le 65535 ]; then
            if check_port "$web_port"; then
                colorize red "Port $web_port is in use." bold
            else
                break
            fi
        else
            colorize red "Please enter a valid port between 23 and 65535, or 0 to disable." bold
            echo
        fi
    done
    
    # IP Limit
    local ip_limit=""
    if [[ ! "$transport" =~ ^(ws|udp|tcptun|faketcptun|kcp|quic)$ ]]; then
        while [[ "$ip_limit" != "true" && "$ip_limit" != "false" ]]; do
            echo -ne "[-] Enable IP Limit for X-UI Panel (true/false, default false): "
            read -r ip_limit
            ip_limit="${ip_limit:-false}"
            if [[ "$ip_limit" == "true" || "$ip_limit" == "false" ]]; then
                break
            else
                colorize red "Please enter 'true' or 'false'." bold
                echo
            fi
        done
    else
        ip_limit="false"
    fi
    
    # Generate configuration
    local config_dir="/root/backhaul-core"
    cat << EOF > "${config_dir}/kharej${tunnel_port}.toml"
[client]
remote_addr = "${server_addr}:${tunnel_port}"
${edge_ip}
transport = "${transport}"
token = "${token}"
connection_pool = ${connection_pool}
aggressive_pool = false
keepalive_period = 60
nodelay = true
retry_interval = 1
dial_timeout = 5
mux_version = ${mux_version}
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 2000000
sniffer = ${sniffer}
web_port = ${web_port}
sniffer_log = "/root/log.json"
log_level = "info"
ip_limit = ${ip_limit}
tun_name = "${tun_name}"
tun_subnet = "${tun_subnet}"
mtu = ${mtu}
EOF
    
    # Create systemd service
    local service_dir="/etc/systemd/system"
    cat << EOF > "${service_dir}/backhaul-kharej${tunnel_port}.service"
[Unit]
Description=Backhaul Kharej Client (Port ${tunnel_port})
After=network.target

[Service]
Type=simple
ExecStart=${config_dir}/backhaul_premium -c ${config_dir}/kharej${tunnel_port}.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    if systemctl enable --now "backhaul-kharej${tunnel_port}.service"; then
        colorize green "Kharej client service (port $tunnel_port) started and enabled." bold
    else
        colorize red "Failed to start Kharej client service." bold
        press_key
        exit 1
    fi
    
    colorize green "Kharej server configured successfully." bold
    echo "Configuration file: ${config_dir}/kharej${tunnel_port}.toml"
    echo "Token: $token"
    press_key
}

# Cron Job Setup
setup_cron_job() {
    clear
    colorize cyan "Setting up Cron Job for Backhaul" bold
    echo
    
    # Ask for service names
    echo -ne "[*] Enter Backhaul service names (space-separated, e.g., backhaul-iran12345.service): "
    read -r services
    
    # Create monitor script
    cat << EOF > /usr/local/bin/backhaul_monitor.sh
#!/bin/bash

# Backhaul Monitor Script
# Monitors RAM/CPU usage and Backhaul service status, restarts if necessary

SERVICES="$services"
RAM_THRESHOLD=80
CPU_THRESHOLD=90
LOG_FILE="/var/log/backhaul_monitor.log"

log_message() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG_FILE"
}

RAM_USAGE=\$(free | awk '/Mem:/ {printf("%.0f"), \$3/\$2 * 100.0}')
CPU_USAGE=\$(top -bn1 | head -n 3 | grep "Cpu(s)" | awk '{print \$2 + \$4}')

for SERVICE_NAME in \$SERVICES; do
    if ! systemctl is-active --quiet "\$SERVICE_NAME"; then
        log_message "Service \$SERVICE_NAME is not running. Restarting..."
        systemctl restart "\$SERVICE_NAME"
        log_message "Service \$SERVICE_NAME restarted."
        continue
    fi

    if [ "\$RAM_USAGE" -gt "\$RAM_THRESHOLD" ] || [ \$(echo "\$CPU_USAGE > \$CPU_THRESHOLD" | bc -l) -eq 1 ]; then
        log_message "RAM usage (\$RAM_USAGE%) or CPU usage (\$CPU_USAGE%) exceeds threshold. Restarting \$SERVICE_NAME..."
        systemctl restart "\$SERVICE_NAME"
        log_message "Service \$SERVICE_NAME restarted due to high RAM/CPU usage."
    else
        log_message "RAM usage (\$RAM_USAGE%) and CPU usage (\$CPU_USAGE%) are below thresholds for \$SERVICE_NAME."
    fi

    if ! pgrep -f "backhaul_premium.*\$SERVICE_NAME" > /dev/null; then
        log_message "Backhaul core for \$SERVICE_NAME is not running. Restarting..."
        systemctl restart "\$SERVICE_NAME"
        log_message "Service \$SERVICE_NAME restarted due to core crash."
    fi
done
EOF
    
    chmod +x /usr/local/bin/backhaul_monitor.sh
    
    # Setup cron job (every 5 minutes and daily at 4 AM)
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/backhaul_monitor.sh") | crontab -
    for service in $services; do
        (crontab -l 2>/dev/null; echo "0 4 * * * systemctl restart $service") | crontab -
    done
    
    colorize green "Cron Job set up successfully." bold
    echo "Monitor script: /usr/local/bin/backhaul_monitor.sh"
    echo "Log file: /var/log/backhaul_monitor.log"
    press_key
}

# Function to remove Cron Job
remove_cron_job() {
    clear
    colorize cyan "Removing Cron Job for Backhaul" bold
    echo
    
    # Remove monitor script
    rm -f /usr/local/bin/backhaul_monitor.sh
    
    # Remove cron jobs
    crontab -l | grep -v "backhaul_monitor.sh" | crontab -
    crontab -l | grep -v "systemctl restart backhaul-" | crontab -
    
    # Remove log file
    rm -f /var/log/backhaul_monitor.log
    
    colorize green "Cron Job and monitor script removed successfully." bold
    press_key
}

# Function to display menu
display_menu() {
    clear
    colorize cyan "Backhaul Configuration Script ($SCRIPT_VERSION)" bold
    echo
    colorize green "1. Configure Iran Server" bold
    colorize magenta "2. Configure Kharej Server" bold
    colorize yellow "3. Run MTU Fixer" bold
    colorize red "4. Remove MTU Fixer Settings" bold
    colorize green "5. Setup Cron Job" bold
    colorize red "6. Remove Cron Job" bold
    colorize red "7. Exit" bold
    echo
}

# Main script
install_dependencies
download_and_extract_backhaul

while true; do
    display_menu
    read -p "Enter your choice [1-7]: " choice
    case $choice in
        1) configure_iran_server ;;
        2) configure_kharej_server ;;
        3) mtu_fixer ;;
        4) remove_mtu_fixer ;;
        5) setup_cron_job ;;
        6) remove_cron_job ;;
        7) colorize yellow "Exiting..." bold; exit 0 ;;
        *) colorize red "Invalid option!" bold; sleep 1 ;;
    esac
done