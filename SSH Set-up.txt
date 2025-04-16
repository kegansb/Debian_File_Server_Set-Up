SSH Key-Based Authentication Setup for Debian File Server
Welcome to the SSH setup guide for your shiny new Debian 12 file server! This server is locked down tighter than a sysadmin’s coffee stash, with SSH on port 2222 and key-based authentication only (passwords? So last century!). Follow these steps to generate SSH keys, configure access, and connect securely from Windows, macOS, or Linux. Let’s make sure you can SSH in without summoning the IT gremlins.
Prerequisites

Your server is running and configured using the Samba setup script (setup_samba.sh).
SSH is set to port 2222, root login is disabled, and only key-based authentication is allowed.
You know the server’s IP address (e.g., 192.168.1.100, as set in the script).
You have a user account on the server (e.g., one created during the script’s non-AD setup or an AD user with a home directory).
You have a client machine (Windows, macOS, or Linux) with admin access to generate keys.

Step 1: Generate an SSH Key Pair on Your Client Machine
You need an SSH key pair: a private key (keep it secret!) and a public key (share it with the server). We’ll use ed25519 keys for modern security, but rsa works too if you’re feeling retro.
On Linux or macOS

Open a terminal.
Generate a key pair:ssh-keygen -t ed25519 -C "your_email@example.com"


Press Enter to accept the default file location (~/.ssh/id_ed25519).
Enter a passphrase (recommended for extra security) or leave blank for no passphrase.


You’ll see output like:Your identification has been saved in /home/user/.ssh/id_ed25519
Your public key has been saved in /home/user/.ssh/id_ed25519.pub


The public key (e.g., id_ed25519.pub) is what you’ll copy to the server.

On Windows

Use PowerShell or Windows Terminal (or install Git Bash for a Linux-like experience).
Generate a key pair:ssh-keygen -t ed25519 -C "your_email@example.com"


Press Enter to save in the default location (C:\Users\YourUser\.ssh\id_ed25519).
Enter a passphrase or leave blank.


Find your keys in C:\Users\YourUser\.ssh:
id_ed25519 (private key)
id_ed25519.pub (public key)



Pro Tip: Don’t share your private key, or hackers will throw a party in your server faster than you can say “unauthorized access”!
Step 2: Copy the Public Key to the Server
You need to add your public key to the ~/.ssh/authorized_keys file of the user you want to log in as (e.g., alice from the script’s user setup). Since the server disables password logins, you’ll need initial access (e.g., via a console or temporary password if you haven’t disabled passwords yet).
Option 1: Using ssh-copy-id (Linux/macOS, if passwords are temporarily enabled)

If the server still allows password logins (not the default after running the script), enable it temporarily:
On the server, edit /etc/ssh/sshd_config:sudo nano /etc/ssh/sshd_config

Change PasswordAuthentication no to PasswordAuthentication yes.
Restart SSH:sudo systemctl restart sshd




From your client, copy the public key:ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2222 username@server_ip

Replace username with your server username (e.g., alice) and server_ip with the server’s IP (e.g., 192.168.1.100).
Enter the user’s password when prompted.
Disable password authentication again on the server:
Revert PasswordAuthentication yes to no in /etc/ssh/sshd_config.
Restart SSH: sudo systemctl restart sshd.



Option 2: Manual Copy (Any OS, Console Access)

Access the server via console (e.g., physical access, VM console, or a temporary SSH session).
Log in as the target user (e.g., alice).
Create the SSH directory and file:mkdir -p ~/.ssh
touch ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys


On your client, display your public key:
Linux/macOS:cat ~/.ssh/id_ed25519.pub


Windows (PowerShell):Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub



Copy the output (e.g., ssh-ed25519 AAAAC3... your_email@example.com).

On the server, edit ~/.ssh/authorized_keys:nano ~/.ssh/authorized_keys

Paste the public key on a new line. Save and exit.
Verify permissions:ls -ld ~ ~/.ssh ~/.ssh/authorized_keys

Ensure ~/.ssh is drwx------ (700) and authorized_keys is -rw------- (600).

Option 3: Using SCP (If Another Key Exists)
If another user (e.g., an admin) already has SSH access, use scp to copy the public key:

From the client:scp -P 2222 ~/.ssh/id_ed25519.pub admin@server_ip:/tmp


Log in as the admin user:ssh -p 2222 admin@server_ip


Move the key to the target user’s authorized_keys:sudo mkdir -p /home/username/.ssh
sudo cat /tmp/id_ed25519.pub >> /home/username/.ssh/authorized_keys
sudo chown -R username:username /home/username/.ssh
sudo chmod 700 /home/username/.ssh
sudo chmod 600 /home/username/.ssh/authorized_keys

Replace username with the target user (e.g., alice).

Snark Alert: If you mess up permissions, SSH will sulk and refuse to let you in. Keep those 700/600 perms or face eternal sadness!
Step 3: Test the SSH Connection
Test logging in with your key to ensure everything’s working.
On Linux/macOS
ssh -p 2222 username@server_ip


Replace username and server_ip.
If you set a passphrase, enter it when prompted.
You should land in the user’s home directory (e.g., /home/alice).

On Windows

Using PowerShell:ssh -p 2222 username@server_ip


Or use PuTTY:
Open PuTTY, enter server_ip and port 2222.
Go to Connection > SSH > Auth, browse to your private key (id_ed25519).
Connect and enter your passphrase if set.



If you see a welcome prompt, congrats! You’re in. If not, don’t panic—check the troubleshooting section.
Step 4: Verify Server Security
The script already locked down SSH, but double-check:

Connect to the server (via console or SSH).
Verify /etc/ssh/sshd_config:cat /etc/ssh/sshd_config

Ensure:
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes


Check SSH service status:sudo systemctl status sshd


If changes were made, restart SSH:sudo systemctl restart sshd



Troubleshooting

“Permission denied”:
Verify ~/.ssh/authorized_keys has the correct public key.
Check permissions: chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys.
Ensure the user’s home directory isn’t world-writable: chmod 755 ~.


Connection refused:
Confirm SSH is running: sudo systemctl status sshd.
Check firewall: sudo ufw status (port 2222 should be allowed).
Verify the server IP and port (2222).


Key not working:
Ensure you’re using the right private key.
Check server logs: sudo tail -f /var/log/auth.log.


AD users:
AD users need a home directory (/home/username or as set in sssd.conf).
Run sudo mkhomedir_helper username if the home directory is missing.



Pro Tip: If you’re stuck, the server’s log (/var/log/samba_setup.log) is your bedtime reading. It might hint at SSH misconfigs from the setup.
Additional Tips

Multiple Keys: Add more public keys to ~/.ssh/authorized_keys (one per line) for multiple devices or users.
Backup Keys: Store your private key securely (e.g., encrypted USB). Lose it, and you’re locked out!
SSH Config (Client): Simplify connections by adding to ~/.ssh/config on your client:Host fileserver
    HostName server_ip
    Port 2222
    User username
    IdentityFile ~/.ssh/id_ed25519

Then connect with: ssh fileserver.
Rotate Keys: If a key is compromised, remove it from authorized_keys and generate a new pair.

All Done!
You’re now SSH-ing like a pro, with keys securing your Debian file server. Share files, manage users, and enjoy the server’s snarky setup log (/var/log/samba_setup.log) for a chuckle. If you hit issues, ping your friendly sysadmin or check the logs—those gremlins don’t stand a chance!
Snark Alert: Don’t lose your private key, or you’ll be begging the console for mercy. Stay secure, and happy SSH-ing!
