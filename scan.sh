#!/bin/bash
#
# Network Scanning Script
# Safe network reconnaissance automation script
#

set -e

# Configuration
NETWORK="${1:-192.168.1.0/24}"
OUTPUT_DIR="reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${OUTPUT_DIR}/scan_${TIMESTAMP}.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

echo -e "${GREEN}=== Network Reconnaissance Scan ===${NC}"
echo "Network: ${NETWORK}"
echo "Output: ${REPORT_FILE}"
echo ""

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "${REPORT_FILE}"
}

# Function to check if host is alive
ping_host() {
    local host=$1
    if ping -c 1 -W 1 "${host}" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to scan common ports
scan_ports() {
    local host=$1
    local ports=(21 22 23 25 53 80 110 143 443 445 993 995 3389)
    local open_ports=()
    
    for port in "${ports[@]}"; do
        if timeout 1 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
            open_ports+=("${port}")
        fi
    done
    
    echo "${open_ports[@]}"
}

# Function to resolve hostname
resolve_hostname() {
    local ip=$1
    hostname=$(getent hosts "${ip}" | awk '{print $2}' | head -n1)
    if [ -z "${hostname}" ]; then
        hostname=$(dig +short -x "${ip}" 2>/dev/null | sed 's/\.$//')
    fi
    echo "${hostname:-N/A}"
}

# Main scan function
main_scan() {
    log "Starting network scan of ${NETWORK}"
    
    # Extract network base and CIDR
    network_base=$(echo "${NETWORK}" | cut -d'/' -f1)
    cidr=$(echo "${NETWORK}" | cut -d'/' -f2)
    
    log "Scanning network ${network_base}/${cidr}"
    
    # Calculate IP range (simplified for /24)
    if [ "${cidr}" = "24" ]; then
        base_ip=$(echo "${network_base}" | cut -d'.' -f1-3)
        
        active_hosts=0
        for i in {1..254}; do
            host_ip="${base_ip}.${i}"
            
            echo -ne "\rScanning ${host_ip}... "
            
            if ping_host "${host_ip}"; then
                echo -e "\r${GREEN}✓${NC} ${host_ip} is alive"
                hostname=$(resolve_hostname "${host_ip}")
                open_ports=$(scan_ports "${host_ip}")
                
                log "Host: ${host_ip}"
                log "  Hostname: ${hostname}"
                log "  Open Ports: ${open_ports:-None}"
                log ""
                
                ((active_hosts++))
            fi
        done
        
        echo ""
        log "Scan complete. Found ${active_hosts} active hosts."
    else
        log "Warning: This script currently supports /24 networks only."
        log "For other networks, please use recon.py"
    fi
}

# Check if Python script is available
if command -v python3 &> /dev/null; then
    log "Python3 detected. Using Python-based scanner for better results..."
    python3 recon.py "${NETWORK}" >> "${REPORT_FILE}" 2>&1
else
    log "Python3 not found. Using bash-based scanner..."
    main_scan
fi

echo -e "${GREEN}Scan complete! Report saved to ${REPORT_FILE}${NC}"

