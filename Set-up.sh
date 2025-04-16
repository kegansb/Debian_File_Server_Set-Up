#!/bin/bash

# Script to set up a Debian file server with Samba for Windows, macOS, and Linux
# Supports Active Directory join, avoids Bind9, uses system/AD passwords
# Run as root on a clean Debian 12 (Bookworm) minimal install

# Exit on any error
set -e

# Default variables
SAMBA_GROUP="sambausers"
DEFAULT_WORKGROUP="WORKGROUP"
DEFAULT_SHARE_NAME="share"
INTERFACE="eth0"  # Adjust if your interface differs
DEFAULT_PASSWORD="password123"
DEFAULT_DNS="8.8.8.8"

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo "Error: This script must be run as root (use sudo)."
    exit 1
fi

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate share name (alphanumeric, no spaces)
validate_share_name() {
    local name=$1
    if [[ $name =~ ^[a-zA-Z0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

# Prompt for static IP
echo "Enter desired static IP address (e.g., 192.168.1.100):"
read -r SERVER_IP
while ! validate_ip "$SERVER_IP"; do
    echo "Invalid IP address. Please enter a valid IP (e.g., 192.168.1.100):"
    read -r SERVER_IP
done

# Prompt for Active Directory join
echo "Join an Active Directory domain? (y/N):"
read -r AD_JOIN
AD_JOIN=${AD_JOIN,,}  # Convert to lowercase
if [ "$AD_JOIN" = "y" ]; then
    echo "Enter AD domain name (e.g., example.com):"
    read -r DOMAIN_NAME
    if [ -z "$DOMAIN_NAME" ]; then
        echo "Error: Domain name cannot be empty."
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
    echo "Enter AD admin password:"
    read -s AD_PASSWORD
    if [ -z "$AD_PASSWORD" ]; then
        echo "Error: Admin password cannot be empty."
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
echo "Enter additional DNS servers (comma-separated, e.g., 8.8.8.8,1.1.1.1, or leave blank):"
read -r DNS_INPUT
EXTRA_DNS=()
if [ -n "$DNS_INPUT" ]; then
    IFS=',' read -r -a DNS_ARRAY <<< "$DNS_INPUT"
    for dns in "${DNS_ARRAY[@]}"; do
        dns=$(echo "$dns" | tr -d '[:space:]')
        if validate_ip "$dns"; then
            EXTRA_DNS+=("$dns")
        else
            echo "Warning: Invalid DNS IP '$dns' skipped."
        fi
    done
fi

# Prompt for users
echo "Enter usernames to add (comma-separated, e.g., alice,bob):"
read -r USER_INPUT
IFS=',' read -r -a USERS <<< "$USER_INPUT"
if [ ${#USERS[@]} -eq 0 ]; then
    echo "Error: At least one user is required."
    exit 1
fi

# Update system and install packages
echo "Updating system and installing packages..."
apt update && apt upgrade -y
if [ "$AD_JOIN" = "y" ]; then
    apt install -y samba samba-common-bin realmd sssd sssd-tools krb5-user samba-winbind net-tools atop htop vim
else
    apt install -y samba samba-common-bin net-tools atop htop vim
fi

# Configure DNS
echo "Configuring DNS..."
if [ "$AD_JOIN" = "y" ]; then
    {
        echo "nameserver $DC_IP"
        echo "search $DOMAIN_NAME"
        for dns in "${EXTRA_DNS[@]}"; do
            echo "nameserver $dns"
        done
    } > /etc/resolv.conf
else
    {
        echo "nameserver $DEFAULT_DNS"
        for dns in "${EXTRA_DNS[@]}"; do
            echo "nameserver $dns"
        done
    } > /etc/resolv.conf
fi

# Configure static IP
echo "Configuring static IP: $SERVER_IP"
DNS_SERVERS="${DC_IP:-$DEFAULT_DNS}"
for dns in "${EXTRA_DNS[@]}"; do
    DNS_SERVERS="$DNS_SERVERS $dns"
done
cat > /etc/network/interfaces.d/static_ip << EOF
auto $INTERFACE
iface $INTERFACE inet static
    address $SERVER_IP
    netmask 255.255.255.0
    gateway 192.168.1.1  # Adjust if your gateway differs
    dns-nameservers $DNS_SERVERS
EOF
systemctl restart networking || echo "Warning: Failed to restart networking. Check /etc/network/interfaces.d/static_ip."

# Create Samba group (used for non-AD setup or fallback)
echo "Creating Samba group: $SAMBA_GROUP"
if ! getent group "$SAMBA_GROUP" > /dev/null; then
    groupadd "$SAMBA_GROUP"
else
    echo "Group $SAMBA_GROUP already exists."
fi

# Create main shared directory
echo "Setting up main shared directory: $SHARE_PATH"
if [ ! -d "$SHARE_PATH" ]; then
    mkdir -p "$SHARE_PATH"
fi
chgrp "$SAMBA_GROUP" "$SHARE_PATH"
chmod 770 "$SHARE_PATH"

# Process users (only for non-AD setup)
USER_SHARES=""
if [ "$AD_JOIN" != "y" ]; then
    for USER in "${USERS[@]}"; do
        USER=$(echo "$USER" | tr -d '[:space:]')  # Trim whitespace
        if [ -z "$USER" ]; then
            continue
        fi
        echo "Processing user: $USER"
        
        # Create system user if not exists
        if ! id "$USER" > /dev/null 2>&1; then
            useradd -m -G "$SAMBA_GROUP" -s /bin/bash "$USER"
            echo "Created system user: $USER"
        else
            echo "User $USER already exists, adding to $SAMBA_GROUP"
            usermod -aG "$SAMBA_GROUP" "$USER"
        fi
        
        # Prompt for password
        echo "Enter password for $USER (press Enter for default: $DEFAULT_PASSWORD):"
        read -s PASSWORD
        PASSWORD=${PASSWORD:-$DEFAULT_PASSWORD}
        echo "$USER:$PASSWORD" | chpasswd
        passwd --expire "$USER" >/dev/null
        echo "Set password for $USER. User must change password on first login."
        
        # Prompt for sudoers
        echo "Add $USER to sudoers group? (y/N):"
        read -r SUDO_ANSWER
        if [ "${SUDO_ANSWER,,}" = "y" ]; then
            usermod -aG sudo "$USER"
            echo "Added $USER to sudoers group."
        else
            echo "$USER not added to sudoers (default: No)."
        fi
        
        # Add to Samba
        if ! pdbedit -L | grep -q "^$USER:"; then
            (echo "$PASSWORD"; echo "$PASSWORD") | smbpasswd -s -a "$USER"
            pdbedit -u "$USER" --pwd-must-change-at-next-login=false
            echo "Added $USER to Samba with system password sync."
        else
            echo "$USER already in Samba database."
        fi
        
        # Create individual user share
        USER_SHARE_PATH="$SHARE_PATH/$USER"
        echo "Setting up user share: $USER_SHARE_PATH"
        if [ ! -d "$USER_SHARE_PATH" ]; then
            mkdir -p "$USER_SHARE_PATH"
        fi
        chown "$USER":"$USER" "$USER_SHARE_PATH"
        chmod 700 "$USER_SHARE_PATH"
        
        # Add to Samba share config
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
    done
fi

# Active Directory join
if [ "$AD_JOIN" = "y" ]; then
    echo "Configuring Kerberos..."
    cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = ${DOMAIN_NAME^^}
    dns_lookup_realm = true
    dns_lookup_kdc = true
EOF

    echo "Joining AD domain: $DOMAIN_NAME"
    echo "$AD_PASSWORD" | realm join -U "$AD_ADMIN" "$DOMAIN_NAME" --install=/
    if [ $? -eq 0 ]; then
        echo "Successfully joined domain."
    else
        echo "Error: Failed to join domain. Check credentials and DNS."
        exit 1
    fi

    echo "Configuring SSSD..."
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
    chmod 600 /etc/sssd/sssd.conf
    systemctl restart sssd
    systemctl enable sssd
fi

# Backup existing Samba config
echo "Backing up existing Samba configuration..."
if [ -f /etc/samba/smb.conf ]; then
    cp /etc/samba/smb.conf /etc/samba/smb.conf.bak
    echo "Backed up to /etc/samba/smb.conf.bak"
fi

# Write Samba configuration
echo "Writing Samba configuration..."
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
echo "Testing Samba configuration..."
if testparm -s /etc/samba/smb.conf; then
    echo "Samba configuration is valid."
else
    echo "Error: Invalid Samba configuration. Restoring backup."
    cp /etc/samba/smb.conf.bak /etc/samba/smb.conf
    exit 1
fi

# Restart Samba services
echo "Restarting Samba services..."
if [ "$AD_JOIN" = "y" ]; then
    systemctl restart smbd winbind
    systemctl enable smbd winbind
else
    systemctl restart smbd nmbd
    systemctl enable smbd nmbd
fi

# Open firewall ports
if command -v ufw > /dev/null; then
    echo "Configuring firewall..."
    ufw allow Samba
    ufw reload
else
    echo "Note: ufw not installed. Ensure firewall allows Samba ports (137,138/UDP, 139,445/TCP)."
fi

# Output connection instructions
echo "Setup complete! File server is ready."
echo ""
echo "Connection Instructions:"
if [ "$AD_JOIN" = "y" ]; then
    echo "  Main Share:"
    echo "    - Windows: Open File Explorer, enter \\\\$SERVER_IP\\$SHARE_NAME, use domain credentials (e.g., $DOMAIN_NAME\\username)."
    echo "    - macOS: In Finder, press Cmd+K, enter smb://$SERVER_IP/$SHARE_NAME, use domain username and password."
    echo "    - Linux: Mount with 'mount -t cifs //$SERVER_IP/$SHARE_NAME /mnt -o username=username,domain=$DOMAIN_NAME'."
    echo "  Note: Use AD credentials. User shares not created for AD setup (use group policies for user folders)."
else
    echo "  Main Share:"
    echo "    - Windows: Open File Explorer, enter \\\\$SERVER_IP\\$SHARE_NAME, use username (e.g., ${USERS[0]})."
    echo "    - macOS: In Finder, press Cmd+K, enter smb://$SERVER_IP/$SHARE_NAME, use username and password."
    echo "    - Linux: Mount with 'mount -t cifs //$SERVER_IP/$SHARE_NAME /mnt -o username=${USERS[0]},uid=$(id -u),gid=$(id -g)'."
    echo "  User Shares:"
    for USER in "${USERS[@]}"; do
        [ -z "$USER" ] && continue
        echo "    - $USER: \\\\$SERVER_IP\\$USER (Windows) or smb://$SERVER_IP/$USER (macOS/Linux)"
    done
    echo "  Users: ${USERS[*]} (default password: $DEFAULT_PASSWORD if none set, must change on login)"
    echo "  Workgroup: $WORKGROUP"
fi
echo "  Server IP: $SERVER_IP"
echo "  DNS Servers: ${DC_IP:-$DEFAULT_DNS}${EXTRA_DNS:+,${EXTRA_DNS[*]}}"
echo "  Note: Ensure $SERVER_IP is reachable. Secure passwords."

exit 0
