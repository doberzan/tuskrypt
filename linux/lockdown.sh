#!/bin/bash
# Discription: Linux lockdown script
# Author: TNAR5
# Version: 1

CURRENT_USER=$(whoami)

if ! [[ $CURRENT_USER == "root" ]];then 
echo "You must execute this script as root."
exit 1
fi

echo "Linux lockdown script"
echo "Author: TNAR5"
echo "Version: 1"
echo "OS:" `uname -o`


function ssh_lockdown()
{	
	printf "\nSSH LOCKDOWN\n"
	if dpkg --get-selections | grep -q "^openssh-server[[:space:]]*install$" >/dev/null;then
		echo "[+] SSH is installed switching to secure config."
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
		printf "Port 22\nPermitRootLogin no\nListenAddress 0.0.0.0\nMaxAuthTries 3\nMaxSessions 1\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nUsePAM yes\nPrintMotd yes\nAcceptEnv LANG LC_*\nSubsystem\tsftp\t/usr/lib/openssh/sftp-server" > /etc/ssh/sshd_config
	else
		echo "[-] SSH is not installed."
	fi
}

function kernel_lockdown()
{	
	printf "\nKERNEL LOCKDOWN\n"
	echo "[+] Enabling secure Kernel options."
	cp /etc/sysctl.conf /etc/sysctl.conf.bak
	printf "net.ipv4.conf.default.rp_filter=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.tcp_syncookies=1\nnet.ipv4.ip_forward=0\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv6.conf.all.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\nnet.ipv6.conf.all.accept_source_route=0\nnet.ipv4.conf.all.log_martians=1\nnet.ipv4.icmp_echo_ignore_broadcasts=1\nnet.ipv6.conf.all.disable_ipv6=0\nnet.ipv6.conf.default.disable_ipv6=0\nnet.ipv6.conf.lo.disable_ipv6=1\nkernel.core_uses_pid=1\nkernel.sysrq=0" > /etc/sysctl.conf
	sysctl -w net.ipv4.conf.default.rp_filter=1>/dev/null;sysctl -w net.ipv4.conf.all.rp_filter=1>/dev/null;sysctl -w net.ipv4.tcp_syncookies=1>/dev/null;sysctl -w net.ipv4.ip_forward=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.send_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv4.conf.all.log_martians=1>/dev/null;
}

function lockout_policy()
{
echo "c"
} 

function remove_guest()
{
echo "d"
}

function user_lockdown()
{
	printf "\nUSER LOCKDOWN\n"
	echo "[!] Starting interactive user lockdown."
	echo "[+] Backup user list "$HOME"/users.txt"
	getent passwd | grep "home" | cut -d ':' -f 1 > ~/users.txt
	users=($(getent passwd | grep "home" | cut -d ':' -f 1))
	echo "[+] Found "${#users[@]}" users."
	for u in "${users[@]}"
	do
		read -p "[?] Is user "$u" authorized to be on the system? [y/n] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Nn]$ ]]
		then
			#userdel $u
			echo "[+] "$u" has been removed."
		else
			read -p "[?] Would you like to change their password? [y/n]" -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ ]]
			then
				passwd $u
			fi
			read -p "[?] Is this user an administrator? [y/n]" -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ ]]
			then
				groups $u | grep "sudo" > /dev/null
				if [ $? -eq 0 ];
				then 
					echo "[+] User is an Administrator - no change."
				else
					#usermod -aG sudo $u
					echo "[+] User was added to the sudo group."
				fi
			else
				groups $u | grep "sudo" > /dev/null
				if [ $? -eq 0 ];
				then 
					echo "[!] User was an Administrator."
					#deluser $u sudo
					echo "[+] Removed "$u" from sudo group."
				else
					echo "[+] User is not an Administrator - no change."
				fi			
			fi
			

		fi
	done
	read -p "[?] Press any key to check sudoers." -n 1 -r
	echo "[+] Launching visudo."
	visudo > /dev/null

	# Group check
	

}

function enable_ufw()
{
	printf "\nFIREWALL LOCKDOWN\n"
	command -v ufw >/dev/null
	if [ $? -eq 0 ];then
		echo "[+] UFW found enableing firewall."
		ufw enable > /dev/null
	else
		echo "[-] UFW not installed."
		read -p "[?] Would you like to install ufw? [y/n] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install ufw
			ufw enable > /dev/null
			echo "[+] UFW is now enabled."
		fi
	fi
}

function ask_to_install_updates()
{
	printf "\nINSTALLING UPDATES\n"
	read -p "[?] Would you like to install updates? [y/n] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		apt-get update
		apt-get upgrade
	fi
}

ssh_lockdown
enable_ufw
kernel_lockdown
user_lockdown
#ask_to_install_updates

echo "[+] Script finished exiting."
exit 0
