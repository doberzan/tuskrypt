#!/bin/bash
# Discription: Linux lock down script
# Author: TNAR5
# Version: 1

CURRENT_USER=$(whoami)

if ! [[ $CURRENT_USER == "root" ]];then 
echo "You must execute this script as root."
exit 1
fi

echo "OS:" `uname -o`


function ssh_lockdown()
{
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
echo "b"
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
echo "e"
}

function ask_to_install_updates()
{
	read -p "Would you like to install updates? [y/n] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		apt-get update
		apt-get upgrade
	fi
}

ssh_lockdown
ask_to_install_updates
