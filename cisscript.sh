#!/bin/bash
#Created 


# Secure the server and the services
# Apply CIS ssh hardening
sshd_config='/etc/ssh/sshd_config'
sudo chown root:root ${sshd_config}						# CIS 5.2.1
sudo chmod 600 ${sshd_config}						# CIS 5.2.1
sudo sed -i "s/\#Protocol/Protocol/" ${sshd_config}				# CIS 5.2.2
sudo sed -i "s/\#LogLevel/LogLevel/" ${sshd_config}				# CIS 5.2.3
sudo sed -i "s/X11Forwarding yes/X11Forwarding no/" ${sshd_config}		# CIS 5.2.4
sudo sed -i "s/\#MaxAuthTries 6/MaxAuthTries 4/" ${sshd_config}		# CIS 5.2.5
sudo sed -i "s/\#IgnoreRhosts yes/IgnoreRhosts yes/" ${sshd_config}		# CIS 5.2.6
sudo sed -i "s/\#HostbasedAuthentication no/HostbasedAuthentication no/" ${sshd_config}	# CIS 5.2.7
sudo sed -i "s/\#PermitRootLogin yes/PermitRootLogin no/" ${sshd_config}	# CIS 5.2.8
sudo sed -i "s/\#PermitEmptyPasswords no/PermitEmptyPasswords no/" ${sshd_config}	# CIS 5.2.9
sudo sed -i "s/\#PermitUserEnvironment no/PermitUserEnvironment no/" ${sshd_config}	# CIS 5.2.10
line_num=$(sudo grep -n "^\# Ciphers and keying" ${sshd_config} | cut -d: -f1)
sudo sed -i "${line_num} a MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160" ${sshd_config}  # CIS 5.2.12
sudo sed -i "${line_num} a Ciphers aes128-ctr,aes192-ctr,aes256-ctr" ${sshd_config}  # CIS 5.2.11
sudo sed -i "s/\#ClientAliveInterval 0/ClientAliveInterval 300/" ${sshd_config}	# CIS 5.2.13
sudo sed -i "s/\#ClientAliveCountMax 3/ClientAliveCountMax 0/" ${sshd_config}	# CIS 5.2.13
sudo sed -i "s/\#LoginGraceTime 2m/LoginGraceTime 60/" ${sshd_config}	# CIS 5.2.14
sudo sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" ${sshd_config}    	# CIS 5.2.16
sudo systemctl restart sshd
# CIS 1.1.6 + 1.1.15-1.1.17
cat << EOF | sudo tee -a /etc/fstab
none  /dev/shm  tmpfs  nosuid,nodev,noexec  0  0
EOF
sudo mount -o remount,noexec /dev/shm

# Restrict Core Dumps					# CIS 1.5.1
cat << EOF | sudo tee /etc/sysctl.conf
fs.suid_dumpable = 0					# CIS 1.5.1
kernel.randomize_va_space = 2				# CIS 1.5.3
net.ipv4.ip_forward = 0					# CIS 3.1.1
net.ipv4.conf.all.send_redirects = 0			# CIS 3.1.2
net.ipv4.conf.default.send_redirects = 0		# CIS 3.1.2
net.ipv4.conf.all.accept_source_route = 0		# CIS 3.2.1
net.ipv4.conf.default.accept_source_route = 0		# CIS 3.2.1
net.ipv4.conf.all.accept_redirects = 0 			# CIS 3.2.2
net.ipv4.conf.default.accept_redirects = 0 		# CIS 3.2.2
net.ipv4.conf.all.secure_redirects = 0 			# CIS 23.2.3
net.ipv4.conf.default.secure_redirects = 0 		# CIS 3.2.3
net.ipv4.conf.all.log_martians = 1 			# CIS 3.2.4
net.ipv4.conf.default.log_martians = 1 			# CIS 3.2.4
net.ipv4.icmp_echo_ignore_broadcasts = 1		# CIS 3.2.5
net.ipv4.icmp_ignore_bogus_error_responses = 1		# CIS 3.2.6
net.ipv4.conf.all.rp_filter = 1				# CIS 3.2.7
net.ipv4.conf.default.rp_filter = 1			# CIS 3.2.7
net.ipv4.tcp_syncookies = 1				# CIS 3.2.8
EOF

# Disable IPv6
cat << EOF | sudo tee /etc/sysconfig/network
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.d/ipv6.conf
EOF

# CIS 4.1.4 - 4.1.18 Audit events are collected
cat << EOF | sudo tee /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /etc/selinux/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

-e 2
EOF

# CIS 5.3.3 Password Policy
line_num="$(grep -n "^password[[:space:]]*sufficient[[:space:]]*pam_unix.so*" /etc/pam.d/system-auth | cut -d: -f1)"
sed -n "$line_num p" system-auth | grep remember || sed "${line_num} s/$/ remember=5/" /etc/pam.d/system-auth

login_defs=/etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}		# CIS 5.4.1.1
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}		# CIS 5.4.1.2
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}		# CIS 5.4.1.3

root_gid="$(id -g root)"
if [[ "${root_gid}" -ne 0 ]] ; then
  usermod -g 0 root							# CIS 5.4.3
fi

# CIS 5.5 Ensure root login is restricted to system console
cp /etc/securetty /etc/securetty.orig
#> /etc/securetty
cat << EOF | sudo tee /etc/securetty
tty1
EOF

# Install AIDE     						# CIS 1.3.2  Ensure filesystem integrity is regularly checked
echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root
#Initialise last so it doesn't pick up changes made by the post-install of the KS
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'
