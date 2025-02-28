LOG_FILE="/var/log/linux_audit_$(date +%F).log"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
RESET="\e[0m"

network_connections() {
    log info "\n[+] Active Network Connections:"
    ss -tulnp | tee -a "$LOG_FILE"
}

firewall_status() {
    log info "\n[+] Firewall Status:"
    if [[ "$OS" == "Debian" ]]; then
        ufw status 2>/dev/null | tee -a "$LOG_FILE" || log error "UFW not installed."
    elif [[ "$OS" == "RHEL" ]]; then
        systemctl is-active firewalld &>/dev/null && firewall-cmd --list-all | tee -a "$LOG_FILE" || log error "Firewalld is not active."
    fi
}

running_services() {
    log info "\n[+] Running Services:"
    systemctl list-units --type=service --state=running | tee -a "$LOG_FILE"
}

installed_packages() {
    log info "\n[+] Installed Packages:"
    if [[ "$OS" == "Debian" ]]; then
        dpkg --list | tee -a "$LOG_FILE"
    elif [[ "$OS" == "RHEL" ]]; then
        rpm -qa | tee -a "$LOG_FILE"
    fi
}

file_permissions() {
    log info "\n[+] Checking File Permissions:"
    log success "World-writable files:"
    find / -type f -perm -o+w 2>/dev/null | tee -a "$LOG_FILE"

    log success "\nSUID/SGID Files:"
    find / -perm /6000 -type f 2>/dev/null | tee -a "$LOG_FILE"
}

rogue_processes() {
    log info "\n[+] Checking for Rogue Processes:"
    ps aux | grep -E '/tmp|/dev/shm' | grep -v grep | tee -a "$LOG_FILE"
}

rootkit_scan() {
    log info "\n[+] Scanning for Rootkits:"
    if command -v rkhunter &>/dev/null; then
        rkhunter --check --sk | tee -a "$LOG_FILE"
    else
        log error "rkhunter not installed. Install with: sudo apt install rkhunter (Debian) or sudo dnf install rkhunter (RHEL)"
    fi
}

hidden_files() {
    log info "\n[+] Checking for Hidden Files & Directories:"
    find / -type f -name ".*" -ls 2>/dev/null | tee -a "$LOG_FILE"
}

failed_logins() {
    log info "\n[+] Checking Unauthorized Login Attempts:"
    journalctl _SYSTEMD_UNIT=sshd.service | grep "Failed password" | tail -10 | tee -a "$LOG_FILE"
}

ssh_security() {
    log info "\n[+] Checking SSH Security Settings:"
    SSH_PORT=$(grep -E '^Port' /etc/ssh/sshd_config | awk '{print $2}')
    SSH_ROOT_LOGIN=$(grep -E '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}')
    
    log success "SSH Port: ${SSH_PORT:-22} (Default is 22)"
    log success "Root SSH Login: ${SSH_ROOT_LOGIN:-'PermitRootLogin not set'}"
    
    if [[ "$SSH_ROOT_LOGIN" == "yes" ]]; then
        log error "Warning: Root login over SSH is enabled! Consider disabling it."
    fi
}

user_security() {
    log info "\n[+] Checking User & Group Security:"
    log success "Users with UID 0 (root users):"
    awk -F: '($3 == "0") {print $1}' /etc/passwd | tee -a "$LOG_FILE"

    log success "\nUsers with empty passwords:"
    awk -F: '($2 == "") {print $1}' /etc/shadow | tee -a "$LOG_FILE"

    log success "\nList of sudo users:"
    grep '^sudo:.*$' /etc/group | cut -d: -f4 | tee -a "$LOG_FILE"
}

security_updates() {
    log info "\n[+] Checking for Security Updates:"
    if [[ "$OS" == "Debian" ]]; then
        apt update &>/dev/null && apt list --upgradable 2>/dev/null | grep -i security | tee -a "$LOG_FILE"
    elif [[ "$OS" == "RHEL" ]]; then
        dnf check-update --security | tee -a "$LOG_FILE"
    fi
}

system_info() {
    log info "\n[+] System Information:"
    log success "Hostname: $(hostname)"
    log success "Kernel Version: $(uname -r)"
    log success "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f2 | tr -d '\"')"
    log success "Uptime: $(uptime -p)"

    if [[ "$OS" == "RHEL" ]]; then
        log success "SELinux Status: $(getenforce)"
    elif [[ "$OS" == "Debian" ]]; then
        log success "AppArmor Status: $(aa-status --enforce 2>/dev/null || echo 'AppArmor not installed')"
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
    if [[ $EUID -ne  0 ]]; then
        log error "Error: Please run as root."
        exit 1
    fi
}

log() {
    local COLOR=$RESET
    local MESSAGE_TYPE=$1
    shift

    case "$MESSAGE_TYPE" in
        info) COLOR=$YELLOW ;;
        success) COLOR=$GREEN ;;
        error) COLOR=$RED ;;
    esac

    echo -e "${COLOR}$@${RESET}" | tee -a "$LOG_FILE"
}

main() {
    log info "================================="
    log info "  Linux Security Audit Report"
    log info "  Generated on: $(date)"
    log info "================================="

    check_root
    detect_os
    system_info
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

    log success "\n[+] Audit Complete. Report saved in $LOG_FILE"
}

main