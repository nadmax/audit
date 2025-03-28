#!/bin/sh
# Author: nadmax
# Date: 28/02/2025

LOG_FILE="/var/log/linux_audit_$(date '+%Y-%m-%d').log"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"
START_TIME=$(date +%s)

calculate_execution_time() {
    START_TIME=$1
    END_TIME=$(date +%s)
    EXECUTION_TIME=$((END_TIME - START_TIME))

    HOURS=$((EXECUTION_TIME / 3600))
    MINUTES=$(((EXECUTION_TIME % 3600) / 60))
    SECONDS=$((EXECUTION_TIME % 60))

    if [ "$HOURS" -gt 0 ]; then
        TIME="${MINUTES}m${SECONDS}s"
    else
        TIME="${SECONDS}s"
    fi

    echo "$TIME"
}

network_connections() {
    log info "\n[+] Active Network Connections:"
    ss -tulnp 2>/dev/null | tee -a "$LOG_FILE"
}

firewall_status() {
    log info "\n[+] Firewall Status:"
    if [ "$OS" = "Debian" ]; then
        ufw status 2>/dev/null | tee -a "$LOG_FILE" || log error "UFW not installed."
    elif [ "$OS" = "RHEL" ]; then
        if systemctl is-active firewalld 2>/dev/null; then
            firewall-cmd --list-all | tee -a "$LOG_FILE"
        else
            log error "Firewalld is not active."
        fi
    fi
}

running_services() {
    log info "\n[+] Running Services:"
    ps -e --format=comm | tee -a "$LOG_FILE"
}

installed_packages() {
    log info "\n[+] Installed Packages"
    if [ "$OS" = "Debian" ]; then
        dpkg --list | tee -a "$LOG_FILE"
    elif [ "$OS" = "RHEL" ]; then
        rpm -qa | tee -a "$LOG_FILE"
    fi
}

file_permissions() {
    log info "\n[+] Checking File Permissions"
    log info "World-writable files"
    find / -type f -perm -o+w 2>/dev/null | tee -a "$LOG_FILE"

    log info "\nSUID/SGID Files"
    find / -perm /6000 -type f 2>/dev/null | tee -a "$LOG_FILE"
}

rogue_processes() {
    log info "\n[+] Checking for Rogue Processes"
    ps aux | grep -E '/tmp|/dev/shm' | grep -v grep | tee -a "$LOG_FILE"
}

rootkit_scan() {
    log info "\n[+] Scanning for Rootkits"
    if command -v rkhunter >/dev/null 2>&1; then
        rkhunter --check --sk | tee -a "$LOG_FILE"
    else
        log error "rkhunter not installed. Install with: sudo apt install rkhunter (Debian) or sudo dnf install rkhunter (RHEL)" | tee -a "$LOG_FILE"
    fi
}

hidden_files() {
    log info "\n[+] Checking for Hidden Files & Directories"
    find / -type f -name ".*" -ls 2>/dev/null | tee -a "$LOG_FILE"
}

failed_logins() {
    log info "\n[+] Checking Unauthorized Login Attempts"
    grep "Failed password" /var/log/auth.log | tail -n 10 | tee -a "$LOG_FILE"
}

ssh_security() {
    log info "\n[+] Checking SSH Security Settings"
    SSH_PORT=$(grep '^Port' /etc/ssh/sshd_config | awk '{print $2}')
    SSH_ROOT_LOGIN=$(grep '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}')

    log info "SSH Port: ${SSH_PORT:-22} (Default is 22)"
    log info "Root SSH Login: ${SSH_ROOT_LOGIN:-'PermitRootLogin not set'}"

    if [ "$SSH_ROOT_LOGIN" = "yes" ]; then
        log warn "Warning: Root login over SSH is enabled! Consider disabling it."
    fi
}

user_security() {
    log info "\n[+] Checking User & Group Security"
    log info "Users with UID 0 (root users)"
    awk -F: '($3 == "0") {print $1}' /etc/passwd | tee -a "$LOG_FILE"

    log info "\nUsers with empty passwords"
    awk -F: '($2 == "") {print $1}' /etc/shadow | tee -a "$LOG_FILE"

    log info "\nList of sudo users"
    grep '^sudo:.*$' /etc/group | cut -d: -f4 | tee -a "$LOG_FILE"
}

security_updates() {
    log info "\n[+] Checking for Security Updates"
    if [ "$OS" = "Debian" ]; then
        apt update &>/dev/null && apt list --upgradable 2>/dev/null | grep -i security | tee -a "$LOG_FILE"
    elif [ "$OS" = "RHEL" ]; then
        dnf check-update --security | tee -a "$LOG_FILE"
    fi
}

system_info() {
    log info "\n[+] System Information"
    log info "Hostname: $(hostname)"
    log info "Kernel Version: $(uname -r)"
    log info "OS: $(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '\"')"
    log info "Uptime: $(uptime -p)"

    if [ "$OS" = "RHEL" ]; then
        log info "SELinux Status: $(getenforce)"
    elif [ "$OS" = "Debian" ]; then
        log info "AppArmor Status: $(aa-status --enforce 2>/dev/null || echo 'AppArmor not installed')"
    fi
}

detect_os() {
    if grep -qEi "debian|ubuntu" /etc/os-release; then
        OS="Debian"
    elif grep -qEi "rhel|centos|fedora|rocky|almalinux" /etc/os-release; then
        OS="RHEL"
    else
        log error "Unsupported OS detected. Exiting..."
        exit 1
    fi

    log success "[+] Detected OS: $OS"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log error "Error: Please run it with sudo."
        exit 1
    fi
}

log() {
    COLOR=$RESET
    MESSAGE_TYPE=$1
    shift

    case "$MESSAGE_TYPE" in
        info) COLOR=$YELLOW ;;
        success) COLOR=$GREEN ;;
        error) COLOR=$RED ;;
    esac

    MESSAGE="$@"

    echo -e "${COLOR}$MESSAGE${RESET}"

    echo "$MESSAGE" >> "$LOG_FILE"
}

main() {
    log info "================================="
    log info "  Linux Security Audit Report"
    log info "  Generated on: $(date)"
    log info "================================="

    check_root
    detect_os
    system_info
    security_updates
    user_security
    ssh_security
    failed_logins
    hidden_files
    file_permissions
    rootkit_scan
    rogue_processes
    installed_packages
    running_services
    firewall_status
    network_connections
    
    EXECUTION_TIME=$(calculate_execution_time "$START_TIME")

    log success "\n[+] Execution Time: $EXECUTION_TIME"
    log success "[+] Audit Complete. Report saved in $LOG_FILE"
}

main