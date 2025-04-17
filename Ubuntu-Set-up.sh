#!/bin/bash

# Script to configure Samba as an AD domain member server on Ubuntu 24.04 LTS minimal
# Joins a Windows AD domain, sets up a file share, and configures SSH key-based access
# Assumes no extra packages installed; powered by Linux freedom!
# Easter eggs for coffee, Jonathan & Aodhan (loyal service dogs), and heavy metal vibes
# Run as root

# Exit on any error
set -e

# Log file for tracking actions and errors
LOGFILE="/var/log/samba_setup.log"
echo "Starting Samba AD setup at $(date) - brewing the config!" | tee -a "$LOGFILE"

# Function to log and execute commands (caffeinated for performance)
run_command() {
    echo "Executing: $@" | tee -a "$LOGFILE"
    if ! $@ 2>&1 | tee -a "$LOGFILE"; then
        echo "Error executing: $@ - even Jonathan & Aodhan can't fix this one!" | tee -a "$LOGFILE"
        exit 1
    fi
}

# Function to validate SSH public key
validate_ssh_key() {
    local key=$1
    [[ $key =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ]] || { echo "Invalid SSH public key. Must start with ssh-ed25519, ssh-rsa, or ecdsa-sha2-nistp256." | tee -a "$LOGFILE"; return 1; }
}

# Function to validate username
validate_username() {
    local name=$1
    [[ $name =~ ^[a-zA-Z0-9]+$ ]] || { echo "Invalid username '$name'. Use alphanumeric characters only, no spaces." | tee -a "$LOGFILE"; return 1; }
}

# Verify script is running as root
if [ "$(id -u)" != "0" ]; then
    echo "Error: This script must be run as root. No root, no Metallica riffs!" | tee -a "$LOGFILE"
    exit 1
fi

# Install required packages - like a double espresso for the server
echo "Installing packages - let’s crank up the Iron Maiden!" | tee -a "$LOGFILE"
run_command apt update
run_command apt install -y samba winbind realmd sssd sssd-tools krb5-user sudo passwd openssh-server htop net-tools ranger vim apt-transport-https ca-certificates libpam-winbind libnss-winbind

# Prompt for AD domain details
echo "Enter the AD domain name (e.g., AD.MYDOMAIN.ORG):"
read -r DOMAIN_NAME
while [ -z "$DOMAIN_NAME" ] || ! host -t SRV "_ldap._tcp.dc._msdcs.$DOMAIN_NAME" >/dev/null 2>&1; do
    echo "Invalid or unreachable domain. Enter a valid AD domain name (e.g., AD.MYDOMAIN.ORG):"
    read -r DOMAIN_NAME
done

echo "Enter the AD admin username (e.g., Administrator):"
read -r ADMIN_USER
while [ -z "$ADMIN_USER" ]; do
    echo "Admin username cannot be empty. Enter the AD admin username:"
    read -r ADMIN_USER
done

echo "Enter the AD admin password:"
read -s ADMIN_PASS
while [ -z "$ADMIN_PASS" ]; do
    echo "Password cannot be empty. Enter the AD admin password:"
    read -s ADMIN_PASS
done
echo

# Join the AD domain - Jonathan & Aodhan guard the gates
echo "Joining domain $DOMAIN_NAME - like a Pantera riff!" | tee -a "$LOGFILE"
echo "$ADMIN_PASS" | run_command realm join --user="$ADMIN_USER" "$DOMAIN_NAME"

# Configure SSSD - METALLICA_SSSD_CONFIG for the win
echo "Configuring SSSD - Linux runs free!" | tee -a "$LOGFILE"
cat << EOF > /etc/sssd/sssd.conf
# SSSD config, as heavy as Master of Puppets
[sssd]
services = nss, pam
config_file_version = 2
domains = $DOMAIN_NAME

[domain/$DOMAIN_NAME]
id_provider = ad
access_provider = ad
ad_domain = $DOMAIN_NAME
krb5_realm = $DOMAIN_NAME
cache_credentials = true
krb5_store_password_if_offline = true
default_shell = /bin/bash
fallback_homedir = /home/%u@%d
use_fully_qualified_names = true
EOF
run_command chmod 600 /etc/sssd/sssd.conf
run_command systemctl restart sssd
run_command systemctl enable sssd

# Update NSS to use winbind
echo "Configuring NSS - brewing the AD connection" | tee -a "$LOGFILE"
run_command sed -i '/^passwd:/ s/$/ winbind/' /etc/nsswitch.conf
run_command sed -i '/^group:/ s/$/ winbind/' /etc/nsswitch.conf

# Configure Samba - Slayer would approve
echo "Configuring Samba - caffeinating the shares!" | tee -a "$LOGFILE"
cat << EOF > /etc/samba/smb.conf
# Samba config, powered by coffee and Linux
[global]
   workgroup = ${DOMAIN_NAME%%.*}
   realm = $DOMAIN_NAME
   server string = %h server (Samba, Ubuntu)
   security = ads
   idmap config * : backend = tdb
   idmap config * : range = 10000-999999
   idmap config ${DOMAIN_NAME%%.*} : backend = rid
   idmap config ${DOMAIN_NAME%%.*} : range = 2000000-2999999
   unix password sync = yes
   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully*
   pam password change = yes
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   bind interfaces only = yes

[jonathan_aodhan_share]
   comment = AD Shared Directory for Domain Users
   path = /srv/samba/jonathan_aodhan_share
   browsable = yes
   read only = no
   valid users = @"${DOMAIN_NAME%%.*}\Domain Users"
   create mask = 0775
   directory mask = 0775
EOF
run_command testparm -s

# Configure PAM for Samba
echo "Configuring PAM - keeping it heavy!" | tee -a "$LOGFILE"
cat << EOF > /etc/pam.d/samba
# PAM config, with a nod to Jonathan’s loyalty
auth    include common-auth
account include common-account
password include common-password
session include common-session
EOF

# Create and set permissions for share directory
echo "Creating share directory - Jonathan & Aodhan approve!" | tee -a "$LOGFILE"
run_command mkdir -p /srv/samba/jonathan_aodhan_share
run_command chown "nobody:nogroup" /srv/samba/jonathan_aodhan_share
run_command chmod 2775 /srv/samba/jonathan_aodhan_share

# Restart Samba services
echo "Restarting Samba services - like a Megadeth solo!" | tee -a "$LOGFILE"
run_command systemctl restart smbd nmbd winbind
run_command systemctl enable smbd nmbd winbind

# Configure SSH - Ride the Lightning to secure access
echo "Configuring SSH - Linux security at its finest" | tee -a "$LOGFILE"
run_command sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
run_command sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
run_command sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
run_command systemctl restart ssh
run_command systemctl enable ssh

# Optional SSH key setup for local admin
echo "Create a local admin user for SSH access? (y/N):"
read -r ADMIN_ANSWER
if [ "${ADMIN_ANSWER,,}" = "y" ]; then
    echo "Enter admin username (e.g., admin):"
    read -r ADMIN_NAME
    while ! validate_username "$ADMIN_NAME"; do
        echo "Enter a valid, alphanumeric username (e.g., admin):"
        read -r ADMIN_NAME
    done
    if id "$ADMIN_NAME" >/dev/null 2>&1; then
        echo "User $ADMIN_NAME already exists - coffee break avoided!" | tee -a "$LOGFILE"
    else
        run_command useradd -m -s /bin/bash "$ADMIN_NAME"
        echo "Enter password for $ADMIN_NAME:"
        read -s ADMIN_PASS
        while [ -z "$ADMIN_PASS" ]; do
            echo "Password cannot be empty. Enter the password for $ADMIN_NAME:"
            read -s ADMIN_PASS
        done
        echo
        echo "$ADMIN_NAME:$ADMIN_PASS" | run_command chpasswd
        run_command passwd --expire "$ADMIN_NAME"
        run_command usermod -aG sudo "$ADMIN_NAME"
    fi
    echo "Enter SSH public key for $ADMIN_NAME (e.g., ssh-ed25519 AAAAC3...):"
    read -r SSH_KEY
    if validate_ssh_key "$SSH_KEY"; then
        SSH_DIR="/home/$ADMIN_NAME/.ssh"
        AUTH_KEYS="$SSH_DIR/authorized_keys"
        run_command mkdir -p "$SSH_DIR"
        run_command chown "$ADMIN_NAME":"$ADMIN_NAME" "$SSH_DIR"
        run_command chmod 700 "$SSH_DIR"
        echo "$SSH_KEY" | run_command tee -a "$AUTH_KEYS"
        run_command chown "$ADMIN_NAME":"$ADMIN_NAME" "$AUTH_KEYS"
        run_command chmod 600 "$AUTH_KEYS"
        echo "SSH public key configured for $ADMIN_NAME - ready to rock!" | tee -a "$LOGFILE"
    else
        echo "SSH key configuration skipped due to invalid key" | tee -a "$LOGFILE"
    fi
fi

# Verify setup
echo "Verifying setup - with a coffee in hand!" | tee -a "$LOGFILE"
if wbinfo -u >/dev/null 2>&1; then
    echo "AD user enumeration successful - horns up!" | tee -a "$LOGFILE"
else
    echo "Error: Failed to enumerate AD users. Check winbind and domain join." | tee -a "$LOGFILE"
    exit 1
fi
if smbclient -L localhost -U% >/dev/null 2>&1; then
    echo "Samba share enumeration successful - Linux wins!" | tee -a "$LOGFILE"
else
    echo "Error: Failed to enumerate Samba shares. Check smbd configuration." | tee -a "$LOGFILE"
    exit 1
fi

# Output completion message
cat << EOF | tee -a "$LOGFILE"
Samba AD setup completed successfully - time for a coffee break!
- Domain: $DOMAIN_NAME
- Share: /srv/samba/jonathan_aodhan_share (accessible by "${DOMAIN_NAME%%.*}\Domain Users")
- SSH: Port 2222, key-based authentication $([ "${ADMIN_ANSWER,,}" = "y" ] && echo "($ADMIN_NAME configured)" || echo "(not configured)")
- Log file: $LOGFILE
To access the share from Windows:
  - Open File Explorer, enter: \\\\$(hostname -I | awk '{print $1}')\\jonathan_aodhan_share
  - Use AD credentials (e.g., ${DOMAIN_NAME%%.*}\\username)
To test SSH (if configured):
  - ssh -p 2222 $ADMIN_NAME@$(hostname -I | awk '{print $1}')
Additional tools installed:
  - htop: System monitoring
  - net-tools: Network utilities (e.g., ifconfig)
  - ranger: Terminal file manager
  - vim: Text editor
# Easter egg: Play some Metallica while Jonathan & Aodhan guard the server!
EOF

exit 0
