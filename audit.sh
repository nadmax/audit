#!/bin/sh
# Author: nadmax
# Date: 28/02/2025

DATE=$(date '+%Y-%m-%d')

# Log files
LOG_FILE="logs/system_audit_$DATE.log"
NETWORK_LOG_FILE="logs/network_audit_$DATE.log"
FIREWALL_LOG_FILE="logs/firewall_audit_$DATE.log"
SERVICES_LOG_FILE="logs/services_audit_$DATE.log"
PACKAGES_LOG_FILE="logs/packages_audit_$DATE.log"
SSH_LOG_FILE="logs/ssh_audit_$DATE.log"
PERMISSIONS_LOG_FILE="logs/permissions_audit_$DATE.log"
PROCESSES_LOG_FILE="logs/processes_audit_$DATE.log"
FILES_LOG_FILE="logs/files_audit_$DATE.log"
LOGIN_LOG_FILE="logs/login_audit_$DATE.log"
USER_LOG_FILE="logs/user_audit_$DATE.log"

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
    log info "$NETWORK_LOG_FILE" "\n[+] Active Network Connections:"
    ss -tulnp 2>/dev/null | tee -a "$NETWORK_LOG_FILE"
}

firewall_status() {
    log info "$FIREWALL_LOG_FILE" "\n[+] Firewall Status:"
    if [ "$OS" = "Debian" ]; then
        ufw status 2>/dev/null | tee -a "$FIREWALL_LOG_FILE" || log error "$FIREWALL_LOG_FILE" "UFW not installed."
    elif [ "$OS" = "RHEL" ]; then
        if systemctl is-active firewalld 2>/dev/null; then
            firewall-cmd --list-all | tee -a "$FIREWALL_LOG_FILE"
        else
            log error "$FIREWALL_LOG_FILE" "Firewalld is not active."
        fi
    fi
}

running_services() {
    log info "$SERVICES_LOG_FILE" "\n[+] Running Services:"
    ps -e --format=comm | tee -a "$SERVICES_LOG_FILE"
}

installed_packages() {
    log info "$SERVICES_LOG_FILE" "\n[+] Installed Packages"
    if [ "$OS" = "Debian" ]; then
        dpkg --list | tee -a "$PACKAGES_LOG_FILE"
    elif [ "$OS" = "RHEL" ]; then
        rpm -qa | tee -a "$PACKAGES_LOG_FILE"
    fi
}

file_permissions() {
    log info "$PERMISSIONS_LOG_FILE" "\n[+] Checking File Permissions"
    log info "$PERMISSIONS_LOG_FILE" "World-writable files"
    find / -type f -perm -o+w 2>/dev/null | tee -a "$PERMISSIONS_LOG_FILE"

    log info "$PERMISSIONS_LOG_FILE" "\nSUID/SGID Files"
    find / -perm /6000 -type f 2>/dev/null | tee -a "$PERMISSIONS_LOG_FILE"
}

rogue_processes() {
    log info "$PROCESSES_LOG_FILE" "\n[+] Checking for Rogue Processes"
    ps aux | grep -E '/tmp|/dev/shm' | grep -v grep | tee -a "$PROCESSES_LOG_FILE"
}

rootkit_scan() {
    log info "$PROCESSES_LOG_FILE" "\n[+] Scanning for Rootkits"
    if command -v rkhunter >/dev/null 2>&1; then
        rkhunter --check --sk | tee -a "$PROCESSES_LOG_FILE"
    else
        log error "$PROCESSES_LOG_FILE" "rkhunter not installed. Install with: sudo apt install rkhunter (Debian) or sudo dnf install rkhunter (RHEL)" | tee -a "$LOG_FILE"
    fi
}

hidden_files() {
    log info "$PROCESSES_LOG_FILE" "\n[+] Checking for Hidden Files & Directories"
    find / -type f -name ".*" -ls 2>/dev/null | tee -a "$FILES_LOG_FILE"
}

failed_logins() {
    log info "$LOGIN_LOG_FILE" "\n[+] Checking Unauthorized Login Attempts"
    grep "Failed password" /var/log/auth.log | tail -n 10 | tee -a "$LOGIN_LOG_FILE"
}

ssh_security() {
    log info "$SSH_LOG_FILE" "\n[+] Checking SSH Security Settings"
    SSH_PORT=$(grep '^Port' /etc/ssh/sshd_config | awk '{print $2}')
    SSH_ROOT_LOGIN=$(grep '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}')

    log info "$SSH_LOG_FILE" "SSH Port: ${SSH_PORT:-22} (Default is 22)"
    log info "$SSH_LOG_FILE" "Root SSH Login: ${SSH_ROOT_LOGIN:-'PermitRootLogin not set'}"

    if [ "$SSH_ROOT_LOGIN" = "yes" ]; then
        log warn "$SSH_LOG_FILE" "Warning: Root login over SSH is enabled! Consider disabling it."
    fi
}

user_security() {
    log info "$USER_LOG_FILE" "\n[+] Checking User & Group Security"
    log info "$USER_LOG_FILE" "Users with UID 0 (root users)"
    awk -F: '($3 == "0") {print $1}' /etc/passwd | tee -a "$USER_LOG_FILE"

    log info "$USER_LOG_FILE" "\nUsers with empty passwords"
    awk -F: '($2 == "") {print $1}' /etc/shadow | tee -a "$USER_LOG_FILE"

    log info "$USER_LOG_FILE" "\nList of sudo users"
    grep '^sudo:.*$' /etc/group | cut -d: -f4 | tee -a "$USER_LOG_FILE"
}

security_updates() {
    log info "$PACKAGES_LOG_FILE" "\n[+] Checking for Security Updates"
    if [ "$OS" = "Debian" ]; then
        apt update &>/dev/null && apt list --upgradable 2>/dev/null | grep -i security | tee -a "$PACKAGES_LOG_FILE"
    elif [ "$OS" = "RHEL" ]; then
        dnf check-update --security | tee -a "$PACKAGES_LOG_FILE"
    fi
}

system_info() {
    log info "$LOG_FILE" "\n[+] System Information"
    log info "$LOG_FILE" "Hostname: $(hostname)"
    log info "$LOG_FILE" "Kernel Version: $(uname -r)"
    log info "$LOG_FILE" "OS: $(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '\"')"
    log info "$LOG_FILE" "Uptime: $(uptime -p)"

    if [ "$OS" = "RHEL" ]; then
        log info "$LOG_FILE" "SELinux Status: $(getenforce)"
    elif [ "$OS" = "Debian" ]; then
        log info "$LOG_FILE" "AppArmor Status: $(aa-status --enforce 2>/dev/null || echo 'AppArmor not installed')"
    fi
}

detect_os() {
    if grep -qEi "debian|ubuntu" /etc/os-release; then
        OS="Debian"
    elif grep -qEi "rhel|centos|fedora|rocky|almalinux" /etc/os-release; then
        OS="RHEL"
    else
        log error "$LOG_FILE" "Unsupported OS detected. Exiting..."
        exit 1
    fi

    log success "$LOG_FILE" "[+] Detected OS: $OS"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log error "$LOG_FILE" "Error: Please run it with sudo."
        exit 1
    fi
}

log() {
    COLOR=$RESET
    MESSAGE_TYPE=$1
    FILE=$2
    shift 2

    case "$MESSAGE_TYPE" in
        info) COLOR=$YELLOW ;;
        success) COLOR=$GREEN ;;
        error) COLOR=$RED ;;
    esac

    MESSAGE="$*"

    echo -e "${COLOR}$MESSAGE${RESET}"

    echo "$MESSAGE" >> "$FILE"
}

main() {
    log info "$LOG_FILE" "================================="
    log info "$LOG_FILE" "  Linux Security Audit Report"
    log info "$LOG_FILE" "  Generated on: $(date)"
    log info "$LOG_FILE" "================================="

    mkdir -p logs

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

    log success "$USER_LOG_FILE" "\n[+] Execution Time: $EXECUTION_TIME"
    log success "$LOG_FILE" "[+] Audit Complete. Report saved in $LOG_FILE"
}

main
