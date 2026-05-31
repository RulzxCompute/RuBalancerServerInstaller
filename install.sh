#!/usr/bin/env bash

# RuBalancer VPN Server Installer
# Compatible with Ubuntu 22.04 LTS

set -e

# ANSI Color Codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}===================================================${NC}"
echo -e "${GREEN}           RuBalancer VPN Server Installer         ${NC}"
echo -e "${BLUE}===================================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this script as root (use sudo).${NC}"
  exit 1
fi

# Configuration Variables
INSTALL_DIR="/opt/rubalancer"
PORT=8080
PASSWORD=""

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -p|--port) PORT="$2"; shift ;;
        -w|--password) PASSWORD="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Prompt for password if not provided
if [ -z "$PASSWORD" ]; then
    read -p "Enter connection password (leave blank for random): " PASSWORD
    if [ -z "$PASSWORD" ]; then
        PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16 ; echo '')
        echo -e "${YELLOW}Generated random password: ${PASSWORD}${NC}"
    fi
fi

echo -e "\n${YELLOW}[1/5] Updating package lists...${NC}"
apt-get update -y

echo -e "\n${YELLOW}[2/5] Checking and installing dependencies (Python 3, iptables, iproute2, curl)...${NC}"
apt-get install -y python3 iptables iproute2 curl

cat << EOF > server.py
#!/usr/bin/env python3
import os
import sys
import struct
import socket
import select
import fcntl
import threading
import subprocess
import hashlib
import argparse
import logging
import time
from queue import PriorityQueue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("RuBalancerVPNServer")

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

class ReorderBuffer:
    def __init__(self, output_func):
        self.output_func = output_func
        self.expected_seq = 0
        self.buffer = {}
        self.lock = threading.Lock()

    def receive(self, seq, data):
        now = time.time()
        with self.lock:
            if seq < self.expected_seq:
                return # duplicate or too late
            
            self.buffer[seq] = (data, now)
            
            # Skip missing packets if the oldest packet has waited too long (e.g. 100ms)
            if self.buffer:
                min_seq = min(self.buffer.keys())
                if now - self.buffer[min_seq][1] > 0.1:
                    self.expected_seq = min_seq
            
            # Limit buffer size to prevent memory leak
            if len(self.buffer) > 1000:
                self.expected_seq = min(self.buffer.keys())

            while self.expected_seq in self.buffer:
                packet, _ = self.buffer.pop(self.expected_seq)
                self.output_func(packet)
                self.expected_seq += 1

def create_tun():
    try:
        tun_fd = os.open('/dev/net/tun', os.O_RDWR)
        ifr = struct.pack('16sH', b'tun0', IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
        
        # Bring interface up and assign IP
        subprocess.run(['ip', 'addr', 'add', '10.8.0.1/24', 'dev', 'tun0'], check=True)
        subprocess.run(['ip', 'link', 'set', 'dev', 'tun0', 'up'], check=True)
        
        # Enable IP forwarding
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
            
        # Get default interface for NAT
        route_out = subprocess.check_output(['ip', 'route']).decode()
        default_iface = [l for l in route_out.split('\n') if 'default' in l][0].split()[4]
        
        # Setup NAT and allow forwarding for UFW
        subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.8.0.0/24', '-o', default_iface, '-j', 'MASQUERADE'])
        subprocess.run(['iptables', '-I', 'FORWARD', '1', '-i', 'tun0', '-o', default_iface, '-j', 'ACCEPT'])
        subprocess.run(['iptables', '-I', 'FORWARD', '1', '-i', default_iface, '-o', 'tun0', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
        
        logger.info(f"TUN interface tun0 created. IP: 10.8.0.1. NAT enabled on {default_iface}")
        return tun_fd
    except Exception as e:
        logger.error(f"Failed to create TUN interface. Are you running as root? Error: {e}")
        sys.exit(1)

def cleanup_tun():
    try:
        route_out = subprocess.check_output(['ip', 'route']).decode()
        default_iface = [l for l in route_out.split('\n') if 'default' in l][0].split()[4]
        subprocess.run(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-s', '10.8.0.0/24', '-o', default_iface, '-j', 'MASQUERADE'])
        subprocess.run(['iptables', '-D', 'FORWARD', '-i', 'tun0', '-o', default_iface, '-j', 'ACCEPT'])
        subprocess.run(['iptables', '-D', 'FORWARD', '-i', default_iface, '-o', 'tun0', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
    except:
        pass

def main():
    parser = argparse.ArgumentParser(description="RuBalancer VPN Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to listen on")
    parser.add_argument("--port", type=int, default=8080, help="UDP Port to listen on (default: 8080)")
    parser.add_argument("--password", required=True, help="Authentication password for clients")
    
    args = parser.parse_args()
    
    auth_hash = hashlib.sha256(args.password.encode()).digest()[:4]
    
    tun_fd = create_tun()
    
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((args.host, args.port))
    # Large buffer
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
    
    client_endpoints = {} # (ip, port) -> last_seen_time
    client_endpoints_lock = threading.Lock()
    
    def write_to_tun(data):
        os.write(tun_fd, data)
        
    reorder_buffer = ReorderBuffer(write_to_tun)
    
    send_seq = 0
    seq_lock = threading.Lock()
    
    logger.info(f"Server listening on {args.host}:{args.port} (UDP)")
    
    try:
        while True:
            r, w, x = select.select([tun_fd, udp_sock], [], [])
            
            for fd in r:
                if fd == udp_sock:
                    data, addr = udp_sock.recvfrom(65535)
                    if len(data) < 12:
                        continue
                        
                    auth = data[:4]
                    if auth != auth_hash:
                        continue
                        
                    now = time.time()
                    with client_endpoints_lock:
                        client_endpoints[addr] = now
                        
                    seq = struct.unpack("<Q", data[4:12])[0]
                    
                    with reorder_buffer.lock:
                        expected = reorder_buffer.expected_seq
                        
                    if seq < expected and (expected - seq > 10 or seq == 0):
                        logger.info(f"Client connection reset detected from {addr} (seq={seq}, expected={expected}). Resetting sequences.")
                        with seq_lock:
                            send_seq = 0
                        with reorder_buffer.lock:
                            reorder_buffer.expected_seq = 0
                            reorder_buffer.buffer.clear()
                            
                    packet = data[12:]
                    
                    reorder_buffer.receive(seq, packet)
                    
                elif fd == tun_fd:
                    data = os.read(tun_fd, 65535)
                    if not data:
                        continue
                        
                    with seq_lock:
                        seq = send_seq
                        send_seq += 1
                        
                    header = auth_hash + struct.pack("<Q", seq)
                    payload = header + data
                    
                    now = time.time()
                    with client_endpoints_lock:
                        active_endpoints = []
                        for addr, last_seen in list(client_endpoints.items()):
                            if now - last_seen < 3.0:
                                active_endpoints.append(addr)
                            else:
                                del client_endpoints[addr]
                        active_endpoints.sort()
                        
                    if active_endpoints:
                        # Send back via Round-Robin to all active client endpoints
                        endpoint = active_endpoints[seq % len(active_endpoints)]
                        udp_sock.sendto(payload, endpoint)
                        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        os.close(tun_fd)
        udp_sock.close()
        cleanup_tun()

if __name__ == "__main__":
    main()

EOF

mkdir -p "$INSTALL_DIR"

if [ -f "server.py" ]; then
    cp server.py "$INSTALL_DIR/server.py"
    chmod +x "$INSTALL_DIR/server.py"
else
    echo -e "${RED}Error: server.py not found in the current directory!${NC}"
    echo -e "${RED}Please run this script from the folder containing server.py.${NC}"
    exit 1
fi

echo -e "\n${YELLOW}[3/5] Creating systemd service configuration...${NC}"
cat << EOF > /etc/systemd/system/rubalancer.service
[Unit]
Description=RuBalancer VPN Internet Bonding Server Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/server.py --port $PORT --password "$PASSWORD"
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo -e "\n${YELLOW}[4/5] Starting and enabling RuBalancer service...${NC}"
systemctl daemon-reload
systemctl enable rubalancer
systemctl restart rubalancer

echo -e "\n${YELLOW}[5/5] Configuring UFW firewall...${NC}"
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "active"; then
        ufw allow $PORT/udp comment 'RuBalancer VPN Daemon'
        ufw reload
        echo -e "${GREEN}Firewall updated: allowed port $PORT/udp.${NC}"
    else
        echo -e "${BLUE}UFW is installed but not active. Port $PORT/udp will need to be open on your firewall.${NC}"
    fi
else
    echo -e "${BLUE}UFW not found. Please ensure port $PORT/udp is open on your VPS firewall (e.g. AWS, DigitalOcean Security Groups).${NC}"
fi

# Enable IP forwarding persistently (just in case)
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-rubalancer.conf
sysctl -p /etc/sysctl.d/99-rubalancer.conf

# Fetch public IP
PUBLIC_IP=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || echo "YOUR_VPS_IP")

echo -e "\n${GREEN}===================================================${NC}"
echo -e "${GREEN}    RuBalancer VPN Server Installed Successfully!  ${NC}"
echo -e "${GREEN}===================================================${NC}"
echo -e "Use the following details in your RuBalancer GUI App:"
echo -e ""
echo -e "  ${BLUE}Server IP:${NC}   ${PUBLIC_IP}"
echo -e "  ${BLUE}Server Port:${NC} ${PORT} (UDP)"
echo -e "  ${BLUE}Password:${NC}    ${PASSWORD}"
echo -e ""
echo -e "To view logs, run: ${YELLOW}journalctl -u rubalancer -f${NC}"
echo -e "To restart, run:   ${YELLOW}systemctl restart rubalancer${NC}"
echo -e "To stop, run:      ${YELLOW}systemctl stop rubalancer${NC}"
echo -e "${BLUE}===================================================${NC}"
