# audit

## Explanation

This script does the following tasks:  

- Checks if you run the script with sudo
- Detects which OS it is to manage audit
- Checks system infos (kernel version, hostname, etc.)
- Checks security updates
- Lists users with UID 0 (root users)
- Lists users with empty passwords
- Lists users belonging to the sudo group
- Checks SSH port
- Detects if SSH root login is activated
- Checks unauthorized login attempts
- Checks hidden files and directories
- Scans rootkits
- Checks rogue processes
- Checks file permissions
- Lists installed packages
- Lists running services
- Checks firewall status
- Lists active network connections
- Logs each step  
- Calculate audit time  

## Getting started

To run the script:

```sh
chmod +x audit.sh
sudo ./audit.sh
```
