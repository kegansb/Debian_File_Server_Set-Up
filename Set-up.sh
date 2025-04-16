#!/bin/bash

# Script to set up a Debian file server with Samba for Windows, macOS, and Linux
# Supports Active Directory join, avoids Bind9, uses system/AD passwords
# Run as root on a clean Debian 12 (Bookworm) minimal install
# Now with SSH key setup automation and 100% more jokes to keep you sane!

# Exit on any error
set -e

# Log file (because who doesn't love a good log to cry over later?)
LOGFILE="/var/log/samba_setup.log"
echo "Starting Samba server setup at $(date)" | tee -a "$LOGFILE"

# Default variables
SAMBA_GROUP="sambausers"
DEFAULT_WORKGROUP="WORKGROUP"
DEFAULT_SHARE_NAME="share"
DEFAULT_PASSWORD="ChangeMe123!"  # Stronger password, because "password" is so 1999
DEFAULT_DNS="8.8.8.8 1.1.1.1"  # Google and Cloudflare, the DNS dream team
GATEWAY="192.168.1.1"  # Default gateway, aka "the door to the internet"
RECYCLE_DIR="/srv/recycle"  # Where deleted files go to sulk

# Function to log and execute commands
run_command() {
    echo "Running: $@" | tee -a "$LOGFILE"
    if ! $@ 2>&1 | tee -a "$LOGFILE"; then
        echo "Error executing: $@ (RIP, we tried)" | tee -a "$LOGFILE"
        exit 1
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || { echo "That's not an IP address, it's modern art!" | tee -a "$LOGFILE"; return 1; }
}

# Function to validate share name (alphanumeric, no spaces)
validate_share_name() {
    local name=$1
    [[ $name =~ ^[a-zA-Z0-9]+$ ]] || { echo "Share name is sus. Alphanumeric only, no spaces, you rebel!" | tee -a "$LOGFILE"; return 1; }
}

# Function to validate SSH public key (basic check)
validate_ssh_key() {
    local key=$1
    [[ $key =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ]] || { echo "That’s not an SSH public key, it’s a cry for help! Starts with ssh-ed25519 or ssh-rsa, try again." | tee -a "$LOGFILE"; return 1; }
}

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo "Error: This script must be run as root (use sudo). No root, no glory!" | tee -a "$LOGFILE"
    exit 1
fi

# Detect network interface (because eth0 is so last decade)
INTERFACE=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | tr -d ' ' | head -n 1)
if [ -z "$INTERFACE" ]; then
    echo "Error: No network interface detected. Did you unplug the internet?" | tee -a "$LOGFILE"
    exit 1
fi
echo "Detected network interface: $INTERFACE (fancy, huh?)" | tee -a "$LOGFILE"

# Prompt for static IP
echo "Enter desired static IP address (e.g., 192.168.1.100):"
read -r SERVER_IP
while ! validate_ip "$SERVER_IP"; do
    echo "Invalid IP address. Please enter a valid IP (e.g., 192.168.1.100):"
    read -r SERVER_IP
done

# Prompt for gateway
echo "Enter gateway IP (default: $GATEWAY):"
read -r INPUT_GATEWAY
GATEWAY=${INPUT_GATEWAY:-$GATEWAY}
while ! validate_ip "$GATEWAY"; do
    echo "Invalid gateway IP. Please enter a valid IP (e.g., 192.168.1.1):"
    read -r GATEWAY
done

# Prompt for Active Directory join
echo "Join an Active Directory domain? (y/N):"
read -r AD_JOIN
AD_JOIN=${AD_JOIN,,}
if [ "$AD_JOIN" = "y" ]; then
    echo "Enter AD domain name (e.g., example.com):"
    read -r DOMAIN_NAME
    if [ -z "$DOMAIN_NAME" ]; then
        echo "Error: Domain name cannot be empty. Don't ghost us now!" | tee -a "$LOGFILE"
        exit 1
    fi
    echo "Enter AD domain controller IP (DNS server, e.g., 192.168.1.10):"
    read -r DC_IP
    while ! validate_ip "$DC_IP"; do
        echo "Invalid IP address. Please enter a valid IP (e.g., 192.168.1.10):"
        read -r DC_IP
    done
    echo "Enter AD admin username (e.g., administrator):"
    read -r AD_ADMIN
    echo "Enter AD admin password (no peeking!):"
    read -s AD_PASSWORD
    if [ -z "$AD_PASSWORD" ]; then
        echo "Error: Admin password cannot be empty. Blank passwords are for quitters!" | tee -a "$LOGFILE"
        exit 1
    fi
else
    echo "Enter workgroup name (default: $DEFAULT_WORKGROUP):"
    read -r WORKGROUP
    WORKGROUP=${WORKGROUP:-$DEFAULT_WORKGROUP}
fi

# Prompt for main Samba share name
echo "Enter main Samba share name (default: $DEFAULT_SHARE_NAME):"
read -r SHARE_NAME
SHARE_NAME=${SHARE_NAME:-$DEFAULT_SHARE_NAME}
while ! validate_share_name "$SHARE_NAME"; do
    echo "Invalid share name. Use alphanumeric characters, no spaces (e.g., MainShare):"
    read -r SHARE_NAME
    SHARE_NAME=${SHARE_NAME:-$DEFAULT_SHARE_NAME}
done
SHARE_PATH="/srv/$SHARE_NAME"

# Prompt for additional DNS servers
echo "Default DNS servers: 8.8.8.8, 1.1.1.1. Enter additional DNS servers (comma-separated, e.g., 9.9.9.9, or leave blank):"
read -r DNS_INPUT
EXTRA_DNS=()
if [ -n "$DNS_INPUT" ]; then
    IFS=',' read -r -a DNS_ARRAY <<< "$DNS_INPUT"
    for dns in "${DNS_ARRAY[@]}"; do
        dns=$(echo "$dns" | tr -d '[:space:]')
        if validate_ip "$dns"; then
            EXTRA_DNS+=("$dns")
        else
            echo "Warning: Invalid DNS IP '$dns' skipped. DNS is not a guessing game!" | tee -a "$LOGFILE"
            echo "Snark alert: Did you think '$dns' was an IP? Try harder, champ!" | tee -a "$LOGFILE"
        fi
    done
fi

# Prompt for users (non-AD only)
if [ "$AD_JOIN" != "y" ]; then
    echo "Enter usernames to add (comma-separated, e.g., alice,bob):"
    read -r USER_INPUT
    IFS=',' read -r -a USERS <<< "$USER_INPUT"
    if [ ${#USERS[@]} -eq 0 ]; then
        echo "Error: At least one user is required. Don't leave us lonely!" | tee -a "$LOGFILE"
        exit 1
    fi
fi

# Update system and install packages
echo "Updating system and installing packages... (grab a coffee, this might take a sec)" | tee -a "$LOGFILE"
run_command apt update
run_command apt upgrade -y
run_command apt install -y samba samba-common-bin net-tools atop htop vim ufw fail2ban unattended-upgrades
if [ "$AD_JOIN" = "y" ]; then
    run_command apt install -y realmd sssd sssd-tools krb5-user winbind libnss-winbind libpam-winbind
fi

# Configure automatic updates
echo "Configuring automatic updates... because nobody likes a vulnerable server!" | tee -a "$LOGFILE"
run_command dpkg-reconfigure --priority=low unattended-upgrades

# Configure DNS
echo "Configuring DNS... (because without DNS, we're just shouting into the void)" | tee -a "$LOGFILE"
cat > /etc/resolv.conf << EOF
$(
    if [ "$AD_JOIN" = "y" ]; then
        echo "nameserver $DC_IP  # Domain controller, the VIP of DNS"
        echo "search $DOMAIN_NAME"
        echo "nameserver 8.8.8.8  # Google DNS, the trusty backup"
        echo "nameserver 1.1.1.1  # Cloudflare DNS, the cool kid"
    else
        echo "nameserver 8.8.8.8  # Google DNS, answering queries since 2009"
        echo "nameserver 1.1.1.1  # Cloudflare DNS, fast and privacy-first"
    fi
    for dns in "${EXTRA_DNS[@]}"; do
        echo "nameserver $dns  # Your custom DNS, because you’re fancy"
    done
)
EOF

# Configure static IP using systemd-networkdhttps://github.com/kegansb/Debian_File_Server_Set-Up/blob/main/Set-up.sh
echo "Configuring static IP: $SERVER_IP (no more DHCP roulette!)" | tee -a "$LOGFILE"
DNS_SERVERS="$DC_IP 8.8.8.8 1.1.1.1"
for dns in "${EXTRA_DNS[@]}"; do
    DNS_SERVERS="$DNS_SERVERS $dns"
done
cat > /etc/systemd/network/20-static.network << EOF
[Match]
Name=$INTERFACE

[Network]
Address=$SERVER_IP/24
Gateway=$GATEWAY
DNS=$DNS_SERVERS
EOF
run_command systemctl enable systemd-networkd
run_command systemctl restart systemd-networkd

# Secure SSH
echo "Securing SSH... because who needs hackers in their life?" | tee -a "$LOGFILE"
SSH_CONFIG="/etc/ssh/sshd_config"
run_command cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"  # Backup, because paranoia is a sysadmin's best friend
cat > "$SSH_CONFIG" << EOL
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
EOL
run_command systemctl restart sshd

# Configure Fail2Ban for Samba
echo "Configuring Fail2Ban... ban those brute-forcers to the shadow realm!" | tee -a "$LOGFILE"
cat > /etc/fail2ban/jail.local << EOL
[samba]
enabled = true
port = 137,138,139,445
maxretry = 5
bantime = 3600
findtime = 600
EOL
run_command systemctl restart fail2ban
run_command systemctl enable fail2ban

# Create Samba group
echo "Creating Samba group: $SAMBA_GROUP (the cool kids' club)" | tee -a "$LOGFILE"
if ! getent group "$SAMBA_GROUP" > /dev/null; then
    run_command groupadd "$SAMBA_GROUP"
else
    echo "Group $SAMBA_GROUP already exists. Party's already started!" | tee -a "$LOGFILE"
fi

# Create main shared directory and recycle bin
echo "Setting up main shared directory: $SHARE_PATH (where files go to socialize)" | tee -a "$LOGFILE"
run_command mkdir -p "$SHARE_PATH" "$RECYCLE_DIR"
run_command chgrp "$SAMBA_GROUP" "$SHARE_PATH"
run_command chmod 770 "$SHARE_PATH"
run_command chown root:root "$RECYCLE_DIR"
run_command chmod 1777 "$RECYCLE_DIR"  # Sticky bit, because deleted files need a timeout corner

# Process users (non-AD only)
USER_SHARES=""
SSH_USERS=()
if [ "$AD_JOIN" != "y" ]; then
    for USER in "${USERS[@]}"; do
        USER=$(echo "$USER" | tr -d '[:space:]')
        [ -z "$USER" ] && continue
        echo "Processing user: $USER (welcome to the server, buddy!)" | tee -a "$LOGFILE"
        
        # Create system user
        if ! id "$USER" > /dev/null 2>&1; then
            run_command useradd -m -G "$SAMBA_GROUP" -s /bin/bash "$USER"
        else
            run_command usermod -aG "$SAMBA_GROUP" "$USER"
        fi
        
        # Prompt for password
        echo "Enter password for $USER (press Enter for default: $DEFAULT_PASSWORD):"
        read -s PASSWORD
        PASSWORD=${PASSWORD:-$DEFAULT_PASSWORD}
        echo "$USER:$PASSWORD" | run_command chpasswd
        run_command passwd --expire "$USER"  # Force password change, because defaults are for chumps
        
        # Prompt for sudoers
        echo "Add $USER to sudoers group? (y/N):"
        read -r SUDO_ANSWER
        if [ "${SUDO_ANSWER,,}" = "y" ]; then
            run_command usermod -aG sudo "$USER"
            echo "$USER is now a sudo superstar!" | tee -a "$LOGFILE"
        fi
        
        # Add to Samba
        if ! pdbedit -L | grep -q "^$USER:"; then
            (echo "$PASSWORD"; echo "$PASSWORD") | run_command smbpasswd -s -a "$USER"
        fi
        
        # Create individual user share
        USER_SHARE_PATH="$SHARE_PATH/$USER"
        echo "Setting up user share: $USER_SHARE_PATH (personal space, no trespassing!)" | tee -a "$LOGFILE"
        run_command mkdir -p "$USER_SHARE_PATH"
        run_command chown "$USER":"$USER" "$USER_SHARE_PATH"
        run_command chmod 700 "$USER_SHARE_PATH"
        
        USER_SHARES+="
[$USER]
   path = $USER_SHARE_PATH
   browsable = yes
   writable = yes
   read only = no
   valid users = $USER
   create mask = 0600
   directory mask = 0700
"
        
        # Setup SSH key
        echo "Add an SSH public key for $USER? (y/N):"
        read -r SSH_ANSWER
        if [ "${SSH_ANSWER,,}" = "y" ]; then
            echo "Paste the SSH public key for $USER (e.g., ssh-ed25519 AAAAC3...):"
            read -r SSH_KEY
            if validate_ssh_key "$SSH_KEY"; then
                SSH_DIR="/home/$USER/.ssh"
                AUTH_KEYS="$SSH_DIR/authorized_keys"
                run_command mkdir -p "$SSH_DIR"
                run_command chown "$USER":"$USER" "$SSH_DIR"
                run_command chmod 700 "$SSH_DIR"
                echo "$SSH_KEY" | run_command tee -a "$AUTH_KEYS"
                run_command chown "$USER":"$USER" "$AUTH_KEYS"
                run_command chmod 600 "$AUTH_KEYS"
                SSH_USERS+=("$USER")
                echo "SSH key added for $USER. Ready to SSH like a pro!" | tee -a "$LOGFILE"
            else
                echo "Snark alert: That key looks like you mashed the keyboard! SSH setup skipped for $USER." | tee -a "$LOGFILE"
            fi
        fi
    done
fi

# Active Directory join
if [ "$AD_JOIN" = "y" ]; then
    echo "Testing AD connectivity... (please don't be offline, DC!)" | tee -a "$LOGFILE"
    if ! ping -c 2 "$DC_IP" > /dev/null; then
        echo "Error: Cannot reach domain controller $DC_IP. Is it napping?" | tee -a "$LOGFILE"
        exit 1
    fi
    echo "Configuring Kerberos... (time to speak AD's secret handshake)" | tee -a "$LOGFILE"
    cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = ${DOMAIN_NAME^^}
    dns_lookup_realm = true
    dns_lookup_kdc = true
EOF
    echo "Joining AD domain: $DOMAIN_NAME (wish us luck!)" | tee -a "$LOGFILE"
    echo "$AD_PASSWORD" | run_command realm join -U "$AD_ADMIN" "$DOMAIN_NAME" --install=/
    echo "Configuring SSSD... (making AD and Linux play nice)" | tee -a "$LOGFILE"
    cat > /etc/sssd/sssd.conf << EOF
[sssd]
services = nss, pam
config_file_version = 2
domains = $DOMAIN_NAME

[domain/$DOMAIN_NAME]
id_provider = ad
auth_provider = ad
access_provider = ad
cache_credentials = true
krb5_store_password_if_offline = true
default_shell = /bin/bash
fallback_homedir = /home/%u
EOF
    run_command chmod 600 /etc/sssd/sssd.conf
    run_command systemctl restart sssd
    run_command systemctl enable sssd

    # Setup SSH keys for AD users
    echo "Configure SSH keys for AD users? (y/N):"
    read -r AD_SSH_ANSWER
    if [ "${AD_SSH_ANSWER,,}" = "y" ]; then
        echo "Enter AD usernames to configure SSH for (comma-separated, e.g., alice,bob):"
        read -r AD_USER_INPUT
        IFS=',' read -r -a AD_USERS <<< "$AD_USER_INPUT"
        for AD_USER in "${AD_USERS[@]}"; do
            AD_USER=$(echo "$AD_USER" | tr -d '[:space:]')
            [ -z "$AD_USER" ] && continue
            echo "Processing SSH setup for AD user: $AD_USER" | tee -a "$LOGFILE"
            SSH_DIR="/home/$AD_USER/.ssh"
            AUTH_KEYS="$SSH_DIR/authorized_keys"
            # Create home directory if it doesn't exist
            if ! id "$AD_USER" > /dev/null 2>&1; then
                echo "Warning: AD user $AD_USER not found. Ensure they log in first or check SSSD config." | tee -a "$LOGFILE"
                continue
            fi
            run_command mkdir -p "$SSH_DIR"
            run_command chown "$AD_USER":"$AD_USER" "$SSH_DIR"
            run_command chmod 700 "$SSH_DIR"
            echo "Paste the SSH public key for $AD_USER (e.g., ssh-ed25519 AAAAC3...):"
            read -r SSH_KEY
            if validate_ssh_key "$SSH_KEY"; then
                echo "$SSH_KEY" | run_command tee -a "$AUTH_KEYS"
                run_command chown "$AD_USER":"$AD_USER" "$AUTH_KEYS"
                run_command chmod 600 "$AUTH_KEYS"
                SSH_USERS+=("$AD_USER")
                echo "SSH key added for AD user $AD_USER. Secure access granted!" | tee -a "$LOGFILE"
            else
                echo "Snark alert: That key looks like you mashed the keyboard! SSH setup skipped for $AD_USER." | tee -a "$LOGFILE"
            fi
        done
    fi
fi

# Configure Samba with recycle bin
echo "Writing Samba configuration... (the moment of truth!)" | tee -a "$LOGFILE"
echo "Snark alert: Samba configs are like divas—touchy and demanding perfection!" | tee -a "$LOGFILE"
[ -f /etc/samba/smb.conf ] && run_command cp /etc/samba/smb.conf /etc/samba/smb.conf.bak  # Backup, because Samba configs are like fine china
if [ "$AD_JOIN" = "y" ]; then
    cat > /etc/samba/smb.conf << EOF
[global]
   security = ads
   realm = ${DOMAIN_NAME^^}
   workgroup = ${DOMAIN_NAME%%.*}
   server string = Debian File Server
   min protocol = SMB2
   server min protocol = SMB2
   idmap config * : backend = tdb
   idmap config * : range = 3000-7999
   idmap config ${DOMAIN_NAME^^} : backend = ad
   idmap config ${DOMAIN_NAME^^} : schema_mode = rfc2307
   idmap config ${DOMAIN_NAME^^} : range = 10000-999999
   winbind use default domain = yes
   winbind offline logon = yes
   template shell = /bin/bash
   template homedir = /home/%U
   vfs objects = recycle
   recycle:repository = $RECYCLE_DIR/%U
   recycle:keeptree = yes
   recycle:versions = yes

[$SHARE_NAME]
   path = $SHARE_PATH
   browsable = yes
   writable = yes
   read only = no
   valid users = @"${DOMAIN_NAME^^}\Domain Users"
   create mask = 0660
   directory mask = 0770
EOF
else
    cat > /etc/samba/smb.conf << EOF
[global]
   workgroup = $WORKGROUP
   server string = Debian File Server
   security = user
   map to guest = never
   min protocol = SMB2
   server min protocol = SMB2
   unix password sync = yes
   pam password change = yes
   vfs objects = recycle
   recycle:repository = $RECYCLE_DIR/%U
   recycle:keeptree = yes
   recycle:versions = yes

[$SHARE_NAME]
   path = $SHARE_PATH
   browsable = yes
   writable = yes
   read only = no
   valid users = @$SAMBA_GROUP
   create mask = 0660
   directory mask = 0770
   force group = $SAMBA_GROUP
$USER_SHARES
EOF
fi

# Test Samba configuration
echo "Testing Samba configuration... (please don't crash, Samba!)" | tee -a "$LOGFILE"
run_command testparm -s /etc/samba/smb.conf

# Restart Samba services
echo "Restarting Samba services... (wake up, Samba, time to shine!)" | tee -a "$LOGFILE"
if [ "$AD_JOIN" = "y" ]; then
    run_command systemctl restart smbd winbind
    run_command systemctl enable smbd winbind
else
    run_command systemctl restart smbd nmbd
    run_command systemctl enable smbd nmbd
fi

# Configure firewall
echo "Configuring firewall... (building the Great Wall of Debian)" | tee -a "$LOGFILE"
run_command ufw allow 2222/tcp
run_command ufw allow Samba
run_command ufw --force enable
run_command ufw status

# Output connection instructions
cat << EOF | tee -a "$LOGFILE"
Setup complete! File server is ready. Time to share files like it's 1995!

Connection Instructions:
EOF
if [ "$AD_JOIN" = "y" ]; then
    cat << EOF | tee -a "$LOGFILE"
  Main Share:
    - Windows: \\\\$SERVER_IP\\$SHARE_NAME, use domain credentials ($DOMAIN_NAME\\username)
    - macOS: Cmd+K, smb://$SERVER_IP/$SHARE_NAME, use domain username
    - Linux: mount -t cifs //$SERVER_IP/$SHARE_NAME /mnt -o username=username,domain=$DOMAIN_NAME
  Note: Use AD credentials. Recycle bin at $RECYCLE_DIR (for those "oops" moments).
EOF
else
    cat << EOF | tee -a "$LOGFILE"
  Main Share:
    - Windows: \\\\$SERVER_IP\\$SHARE_NAME, use username (e.g., ${USERS[0]})
    - macOS: Cmd+K, smb://$SERVER_IP/$SHARE_NAME
    - Linux: mount -t cifs //$SERVER_IP/$SHARE_NAME /mnt -o username=${USERS[0]})
  User Shares:
EOF
    for USER in "${USERS[@]}"; do
        [ -z "$USER" ] && continue
        echo "    - $USER: \\\\$SERVER_IP\\$USER" | tee -a "$LOGFILE"
    done
    cat << EOF | tee -a "$LOGFILE"
  Users: ${USERS[*]} (default password: $DEFAULT_PASSWORD, must change on login)
  Workgroup: $WORKGROUP
  Recycle bin at $RECYCLE_DIR (because deleting files is a personality trait).
EOF
fi
cat << EOF | tee -a "$LOGFILE"
  Server IP: $SERVER_IP
  DNS Servers: ${DC_IP:-8.8.8.8 1.1.1.1}${EXTRA_DNS:+,${EXTRA_DNS[*]}}
  SSH: Port 2222, key-based auth only. Users with SSH keys: ${SSH_USERS[*]:-none}.
  To add more keys, paste them into ~/.ssh/authorized_keys for each user.
  Log: $LOGFILE (your new bedtime reading)
EOF

exit 0  # We did it, folks! Time for a victory nap.
