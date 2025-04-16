Test Scenarios for Samba Setup Script
Ready to put your setup_samba.sh script through its paces? This Debian 12 file server setup is packed with Samba shares, SSH key automation, DNS wizardry (8.8.8.8 and 1.1.1.1, plus your extras), and enough snark to keep you chuckling. Below are test scenarios to ensure it sings like a well-tuned server—or at least doesn’t crash like a bad IT prank. Grab your coffee, and let’s break this thing (gently)!
Prerequisites

Environment: A clean Debian 12 (Bookworm) minimal install (VM or physical server).
Access: Root privileges (sudo) and console access (in case SSH goes rogue).
Network: Connectivity for package installs and DNS testing. Ensure ports 2222 (SSH) and 137-139, 445 (Samba) are open.
SSH Key: Generate a test SSH key pair on a client machine:ssh-keygen -t ed25519 -C "test@example.com"
cat ~/.ssh/id_ed25519.pub

Copy the public key (e.g., ssh-ed25519 AAAAC3... test@example.com) for SSH tests.
AD Setup (optional): If testing AD, have a domain controller IP, domain name (e.g., example.com), admin username, and password ready.
Client Machines: Windows, macOS, or Linux boxes to test Samba shares and SSH.

Snark Alert: No SSH key? No problem—just don’t expect the server to welcome you with open arms. Keys are the VIP pass here!
Scenario 1: Non-AD Setup with SSH Key Automation
Test the script’s core functionality without Active Directory, focusing on user creation, SSH key setup, and Samba shares.

Prepare:

Snapshot your VM/server for a clean rollback.
Save setup_samba.sh and make it executable:chmod +x setup_samba.sh




Run the Script:

Execute as root:sudo ./setup_samba.sh


Inputs:
Static IP: Enter 192.168.1.100.
Gateway: Use default (192.168.1.1) or your network’s gateway.
AD Join: Enter n (no AD).
Workgroup: Use default (WORKGROUP).
Share Name: Use default (share).
DNS: Add an extra DNS (e.g., 9.9.9.9) or leave blank.
Users: Enter alice,bob.
For Alice:
Password: Use default (ChangeMe123!).
Sudo: y (add to sudoers).
SSH Key: y, paste your public key (e.g., ssh-ed25519 AAAAC3...).


For Bob:
Password: Use default.
Sudo: n.
SSH Key: n (skip).


Try an invalid SSH key (e.g., not-a-key) for a third user (e.g., add charlie) to trigger the snarky error.




Verify:

Users:
Check alice and bob exist: id alice, id bob.
Confirm alice is in sudo: groups alice.


SSH:
Test SSH for alice:ssh -p 2222 alice@192.168.1.100

Expect login without a password (or enter passphrase if set).
Test SSH for bob (should fail, no key):ssh -p 2222 bob@192.168.1.100

Expect “Permission denied (publickey)”.
Verify alice’s key:ls -l /home/alice/.ssh/authorized_keys

Should be -rw------- (600), owned by alice:alice.


Samba:
From a client:
Windows: Open \\192.168.1.100\share, log in as alice/ChangeMe123!.
macOS: Cmd+K, smb://192.168.1.100/share, use alice credentials.
Linux: mount -t cifs //192.168.1.100/share /mnt -o username=alice.


Test alice’s personal share: \\192.168.1.100\alice.
Create a file, delete it, and check /srv/recycle/alice for the recycled file.


DNS:
Check /etc/resolv.conf:cat /etc/resolv.conf

Should list 8.8.8.8, 1.1.1.1, and 9.9.9.9 (if added).
Test resolution: ping -c 2 google.com.


Firewall:
Verify: sudo ufw status.Expect 2222/tcp and Samba ports (137-139, 445) allowed.


Logs:
Check /var/log/samba_setup.log:cat /var/log/samba_setup.log

Look for “SSH key added for alice”, snarky error for charlie (e.g., “That key looks like you mashed the keyboard!”), and user/share setup messages.




Expected Issues:

Invalid SSH key input should trigger a logged error and skip SSH setup.
SSH failure for alice? Check permissions:ls -ld /home/alice /home/alice/.ssh /home/alice/.ssh/authorized_keys

Fix with chmod 700 /home/alice/.ssh; chmod 600 /home/alice/.ssh/authorized_keys.
Samba login fails? Verify smbd and nmbd are running: systemctl status smbd nmbd.



Scenario 2: AD Setup with SSH Key Automation
Test the script with Active Directory integration, focusing on domain join and SSH key setup for AD users.

Prepare:

Snapshot your VM/server.
Ensure a domain controller is reachable (e.g., 192.168.1.10).
Have AD admin credentials and user accounts (e.g., alice, bob in example.com).


Run the Script:

Execute: sudo ./setup_samba.sh.
Inputs:
Static IP: 192.168.1.100.
Gateway: Default or your network’s gateway.
AD Join: y.
Domain Name: example.com.
DC IP: 192.168.1.10.
AD Admin: administrator.
AD Password: Your admin password.
Share Name: Default (share).
DNS: Add 9.9.9.9 or leave blank.
AD SSH Users:
Answer y to configure SSH keys.
Enter alice,bob.
For alice: Paste your public key.
For bob: Skip (Ctrl+D or invalid key to test snark).
Try an invalid key for bob (e.g., not-a-key).






Verify:

AD Join:
Check domain membership: realm list.
Verify AD user: id alice.
If alice lacks a home directory, create it: sudo mkhomedir_helper alice.


SSH:
Test for alice:ssh -p 2222 alice@192.168.1.100

Expect login with key.
Test for bob (should fail if no key):ssh -p 2222 bob@192.168.1.100


Check alice’s key:ls -l /home/alice/.ssh/authorized_keys

Should be -rw-------, owned by alice.


Samba:
Test share with AD credentials:
Windows: \\192.168.1.100\share, use EXAMPLE\alice and AD password.
macOS: smb://192.168.1.100/share, same credentials.
Linux: mount -t cifs //192.168.1.100/share /mnt -o username=alice,domain=EXAMPLE.


Check recycle bin: /srv/recycle/alice.


DNS:
Verify /etc/resolv.conf lists 192.168.1.10, 8.8.8.8, 1.1.1.1, and 9.9.9.9 (if added).
Test: ping -c 2 google.com.


Firewall: Same as Scenario 1.
Logs:
Check /var/log/samba_setup.log for AD join, SSH key messages, and snarky errors (e.g., for bob’s invalid key).
Check /var/log/auth.log for SSH attempts: sudo tail -f /var/log/auth.log.




Expected Issues:

No home directory for AD users? Run sudo mkhomedir_helper alice or log in as alice via Samba first.
AD join fails? Verify DC IP and credentials. Check logs: /var/log/sssd/sssd.log.
SSH fails? Ensure home directory exists and permissions are correct.



Scenario 3: Edge Cases and Validation
Push the script’s validation by throwing bad inputs at it.

Prepare: Same as Scenario 1.

Run the Script:

Execute: sudo ./setup_samba.sh.
Inputs:
Static IP: Try not-an-ip, then correct to 192.168.1.100.
Gateway: Try invalid, then 192.168.1.1.
AD Join: n.
Users: Enter alice,,bob (test empty entry).
SSH Key: For alice, enter not-a-key, then a valid key.
DNS: Enter bad-dns, then 9.9.9.9.
Share Name: Try bad name!, then share.




Verify:

Validation:
Expect snarky errors in terminal and log:
IP: “That’s not an IP address, it’s modern art!”
DNS: “Did you think 'bad-dns' was an IP? Try harder, champ!”
SSH: “That’s not an SSH public key, it’s a cry for help!”
Share: “Share name is sus. Alphanumeric only, no spaces, you rebel!”


Empty user (,,) should be skipped.


Functionality: After correcting inputs, verify as in Scenario 1 (SSH, Samba, DNS, firewall).
Logs: Confirm all errors logged in /var/log/samba_setup.log.


Expected Issues:

Script should loop until valid inputs are provided.
If it exits unexpectedly, note the error and check logs.



Post-Test Checklist

Rollback: Revert to your snapshot if testing multiple scenarios.
Logs: Archive /var/log/samba_setup.log for reference.
Network: Confirm no unintended firewall blocks (e.g., sudo ufw reset if needed, then rerun script).
SSH Security:
Verify: cat /etc/ssh/sshd_config.Expect Port 2222, PermitRootLogin no, PasswordAuthentication no.
Test root login (should fail): ssh -p 2222 root@192.168.1.100.


Cleanup: Remove test users if not needed:sudo userdel -r alice



Troubleshooting

SSH Fails:
Check permissions: chmod 700 /home/alice/.ssh; chmod 600 /home/alice/.ssh/authorized_keys.
Verify key: cat /home/alice/.ssh/authorized_keys.
Logs: sudo tail -f /var/log/auth.log.


Samba Fails:
Check services: systemctl status smbd winbind (AD) or smbd nmbd (non-AD).
Test config: testparm.


AD Issues:
Verify SSSD: systemctl status sssd.
Check logs: /var/log/sssd/sssd_example.com.log.


DNS Issues:
Test: nslookup google.com.
Fix /etc/resolv.conf if incorrect.



Snark Alert: If the server laughs at your inputs (check that log!), you’re probably feeding it gibberish. Feed it valid data, or it’ll sulk harder than a misconfigured Samba share!
Notes

Logs Are Your Friend: /var/log/samba_setup.log has all the snarky details and errors.
Snapshots Save Lives: Always snapshot before testing—unless you enjoy reinstalling Debian.
AD Testing: Needs a real domain controller. If unavailable, skip to non-AD tests.
Client Testing: Use multiple clients (Windows, macOS, Linux) for Samba to catch OS-specific quirks.

Now go make that script sweat! If it passes, you’ve got a rock-solid file server. If it trips, grab those logs and let’s debug like it’s 1995.
