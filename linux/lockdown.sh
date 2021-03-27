#!/bin/bash
# Discription: Linux lockdown script
# Author: TNAR5
# Version: 1

CURRENT_USER=$(whoami)
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if ! [[ $CURRENT_USER == "root" ]];then 
echo "You must execute this script as root."
exit 1
fi

echo "Linux lockdown script"
echo "Author: TNAR5"
echo "Version: 1"
echo "OS:" `uname -o`

function warn()
{
	echo -e "$YELLOW[!]$NC $1"
}

function error()
{
	echo -e "$RED[-]$NC $1"
}

function success()
{
	echo -e "$GREEN[+]$NC $1"
}

function ssh_lockdown()
{	
	printf "\nSSH Lockdown\n"
	if dpkg --get-selections | grep -q "^openssh-server[[:space:]]*install$" >/dev/null;then
		success "SSH is installed switching to secure config."
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
		printf "Port 22\nPermitRootLogin no\nListenAddress 0.0.0.0\nMaxAuthTries 3\nMaxSessions 1\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nUsePAM yes\nPrintMotd yes\nAcceptEnv LANG LC_*\nSubsystem\tsftp\t/usr/lib/openssh/sftp-server" > /etc/ssh/sshd_config
	else
		error "SSH is not installed."
	fi
}

function kernel_lockdown()
{	
	printf "\nKernel Lockdown\n"
	success "Enabling secure Kernel options."
	cp /etc/sysctl.conf /etc/sysctl.conf.bak
	printf "net.ipv4.conf.default.rp_filter=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.tcp_syncookies=1\nnet.ipv4.ip_forward=0\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv6.conf.all.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\nnet.ipv6.conf.all.accept_source_route=0\nnet.ipv4.conf.all.log_martians=1\nnet.ipv4.icmp_echo_ignore_broadcasts=1\nnet.ipv6.conf.all.disable_ipv6=0\nnet.ipv6.conf.default.disable_ipv6=0\nnet.ipv6.conf.lo.disable_ipv6=1\nkernel.core_uses_pid=1\nkernel.sysrq=0" > /etc/sysctl.conf
	sysctl -w kernel.randomize_va_space=2 >/dev/null;sysctl -w net.ipv4.conf.default.rp_filter=1>/dev/null;sysctl -w net.ipv4.conf.all.rp_filter=1>/dev/null;sysctl -w net.ipv4.tcp_syncookies=1>/dev/null;sysctl -w net.ipv4.ip_forward=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.send_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv4.conf.all.log_martians=1>/dev/null;
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
	printf "\nUser Lockdown\n"
	warn "Starting interactive user lockdown."
	success "Backup user list ${HOME}/users.txt"
	getent passwd | grep "home" | cut -d ':' -f 1 > ~/users.txt
	users=($(getent passwd | grep "home" | cut -d ':' -f 1))
	success "Found "${#users[@]}" users."
	for u in "${users[@]}"
	do
		read -p "[?] Is user "$u" authorized to be on the system? [y/n] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Nn]$ ]]
		then
			#userdel $u
			success "${u} has been removed."
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
					success "User is an Administrator - no change."
				else
					#usermod -aG sudo $u
					success "User was added to the sudo group."
				fi
			else
				groups $u | grep "sudo" > /dev/null
				if [ $? -eq 0 ];
				then 
					warn "User was an Administrator."
					#deluser $u sudo
					success "Removed "$u" from sudo group."
				else
					success "User is not an Administrator - no change."
				fi			
			fi
			

		fi
	done
	read -p "[?] Press any key to check sudoers." -n 1 -r
	success "Launching visudo."
	printf "\n"
	visudo
	printf "\n"
	

}

function enable_ufw()
{
	printf "\nFirewall Lockdown\n"
	command -v ufw >/dev/null
	if [ $? -eq 0 ];then
		success "UFW found enableing firewall."
		ufw enable > /dev/null
	else
		error "UFW not installed."
		read -p "[?] Would you like to install ufw? [y/n] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install ufw
			ufw enable > /dev/null
			success "UFW is now enabled."
		fi
	fi
}

function enable_av()
{
	printf "\nAnti-Virus lockdown\n"
	command -v clamscan >/dev/null
	if [ $? -eq 0 ];then
		success "ClamAV found."
		ufw enable > /dev/null
	else
		error "ClamAV not installed."
		read -p "[?] Would you like to install ClamAV and chkrootkit? [y/n] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y clamav chkrootkit
			ufw enable > /dev/null
			success "ClamAV is now enabled."
		fi
	fi
}

function ask_to_install_updates()
{
	printf "\nInstalling Updates\n"
	read -p "[?] Would you like to install updates? [y/n] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		apt-get update
		apt-get upgrade
	fi
}

function check_files()
{
	read -p "[?] Would you like to check random system config files? [y/n] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			echo "nospoof on" >> /etc/hosts
			vim /etc/hosts
			vim /etc/crontab
			read -p "[!] Make sure to set lightdm guest to false. (allow-guest = False)" -n 1 -r
			vim /etc/lightdm/lightdm.conf
			printf "\n"
			success "Finish config editing."
		fi

}

function check_bad_programs()
{
	echo -e "\nChecking for 'bad' programs."
	if dpkg --get-selections | grep -q "^nmap[[:space:]]*install$" >/dev/null;then
		warn "Nmap is installed, removing."
		#apt-get purge nmap
	fi
	if dpkg --get-selections | grep -q "^john[[:space:]]*install$" >/dev/null;then
		warn "John is installed, removing."
		#apt-get purge john
	fi
	if dpkg --get-selections | grep -q "^rainbowcrack[[:space:]]*install$" >/dev/null;then
		warn "rainbowcrack is installed, removing."
		#apt-get purge rainbowcrack
	fi
	if dpkg --get-selections | grep -q "^ophcrack[[:space:]]*install$" >/dev/null;then
		warn "Ophcrack is installed, removing."
		#apt-get purge ophcrack
	fi
	if dpkg --get-selections | grep -q "^nc[[:space:]]*install$" >/dev/null;then
		warn "Nc is installed, removing."
		#apt-get purge nc
	fi
	if dpkg --get-selections | grep -q "^netcat[[:space:]]*install$" >/dev/null;then
		warn "Netcat is installed, removing."
		#apt-get purge netcat
	fi
	if dpkg --get-selections | grep -q "^hashcat[[:space:]]*install$" >/dev/null;then
		warn "Hashcat is installed, removing."
		#apt-get purge hashcat
	fi
	#apt-get purge netcat*

	if dpkg --get-selections | grep -q "^samba[[:space:]]*install$" >/dev/null;then
		warn "Samba is installed, make sure this is a required service."
	fi
	if dpkg --get-selections | grep -q "^bind9[[:space:]]*install$" >/dev/null;then
		warn "Bind9 is installed, make sure this is a required service."
	fi
	if dpkg --get-selections | grep -q "^vsftpd[[:space:]]*install$" >/dev/null;then
		warn "Vsftpd is installed, make sure this is a required service."
	fi
	if dpkg --get-selections | grep -q "^apache2[[:space:]]*install$" >/dev/null;then
		warn "Apache2 is installed, make sure this is a required service."
	fi
	if dpkg --get-selections | grep -q "^nginx[[:space:]]*install$" >/dev/null;then
		warn "Nginx is installed, make sure this is a required service."
	fi
	if dpkg --get-selections | grep -q "^telnet[[:space:]]*install$" >/dev/null;then
		warn "Telnet is installed, make sure this is a required service."
	fi
	success "Displaying other active services:"
	service --status-all | grep '+'
}


ssh_lockdown
enable_ufw
enable_av
kernel_lockdown
user_lockdown
check_files
#ask_to_install_updates
check_bad_programs

echo -e "\nThings left to do:"
warn "Update kernel"
warn "Pam cracklib password requirements"
warn "Discover rootkits"
warn "Check file permissions"
warn "Check for media files, mp4, mp3, ogg, wav, png, jpg, jpeg, gif, mov, txt, "
warn "Win"

success "Script finished exiting."
exit 0
