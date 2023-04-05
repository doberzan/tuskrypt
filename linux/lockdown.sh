#!/bin/bash
# Description: Linux lockdown script
# Authors: TNAR5, colonket, ferdinand
# Version: 1.3
# Competitions:
#	- Hivestorm 2020, 2021 
#	- Southwest CCDC Regionals 2022
#	- Southwest CCDC Regionals 2023

# Text Colors
HEADER='\e[1m'
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PURPLE='\033[1;35m'

# Operators
function notify()
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

function header()
{
	echo -e "$HEADER$1$NC"
}

function heart()
{
	echo -e "$PURPLE[<3]$NC $1"
}


# Main functions

# Disable aliases (they can be tricky)
function disable_aliases()
{
	header "\nDisable Aliases"
	read -p "[?] Do you want to disable aliases (persistent)? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		unalias -a 
		grep -qxF 'unalias -a' $HOME/.bashrc || echo 'unalias -a' >> $HOME/.bashrc
		success "Aliases disabled, added to .bashrc for persistence."
	fi
}

# Choose preferred text editor
function choose_editor()
{
	header "\nChoose Text Editor"
	read -p "[?] Do you want to choose your text editor? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		update-alternatives --config editor
	fi
}

# Offline - Modify config
function ssh_lockdown()
{
	header "\nSSH Lockdown"
	if dpkg --get-selections | grep -q "^openssh-server[[:space:]]*install$" >/dev/null;then
		success "SSH is installed, switching to secure config."
		notify "Backup created at /etc/ssh/sshd_config.bak"
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
		printf "Port 22\nPermitRootLogin no\nListenAddress 0.0.0.0\nMaxAuthTries 3\nMaxSessions 1\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nUsePAM yes\nPrintMotd yes\nAcceptEnv LANG LC_*\nSubsystem\tsftp\t/usr/lib/openssh/sftp-server" > /etc/ssh/sshd_config
	else
		error "SSH is not installed, skipping lockdown."
	fi
}

# Offline - Modify kernel
function kernel_lockdown()
{
	header "\nKernel Lockdown"
	read -p "[?] Do you want to secure kernel options? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
	cp /etc/sysctl.conf /etc/sysctl.conf.bak
	notify "Backup created at /etc/sysctl.conf.bak"
	printf "net.ipv4.conf.default.rp_filter=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.tcp_syncookies=1\nnet.ipv4.ip_forward=0\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv6.conf.all.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\nnet.ipv6.conf.all.accept_source_route=0\nnet.ipv4.conf.all.log_martians=1\nnet.ipv4.icmp_echo_ignore_broadcasts=1\nnet.ipv6.conf.all.disable_ipv6=0\nnet.ipv6.conf.default.disable_ipv6=0\nnet.ipv6.conf.lo.disable_ipv6=1\nkernel.core_uses_pid=1\nkernel.sysrq=0" > /etc/sysctl.conf
	sysctl -w kernel.randomize_va_space=2 >/dev/null;sysctl -w net.ipv4.conf.default.rp_filter=1>/dev/null;sysctl -w net.ipv4.conf.all.rp_filter=1>/dev/null;sysctl -w net.ipv4.tcp_syncookies=1>/dev/null;sysctl -w net.ipv4.ip_forward=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.send_redirects=0>/dev/null;sysctl -w net.ipv4.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv6.conf.all.accept_source_route=0>/dev/null;sysctl -w net.ipv4.conf.all.log_martians=1>/dev/null;
	success "Enabled secure kernel options."
	fi

}

# Offline - Modify users
function user_lockdown()
{
	header "\nUser Lockdown"
	read -p "[?] Do you want to lockdown human users? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		notify "Starting interactive user lockdown."
		success "User list saved to $HOME/users.txt"
		users=($(awk -F ':' '$3>=1000 {print $i}' /etc/passwd | cut -d':' -f1))
		
		printf "%s\n" "${users[@]}" > $HOME/users.txt
		success "Found "${#users[@]}" human users."
		echo

		password="changeMe!123"

		#read -p "[?] HIVESTORM ONLY Do you want to set every user's password to '$password'? [y/N]" -n 1 -r
		#echo
		#if [[ $REPLY =~ ^[Yy]$ ]]
		#then
		#	for u in "${users[@]}"
		#	do
		#		# passwd asks to enter new password twice
		#		echo -e "$password\n$password" | passwd $u
		#		success "Changed user $u's password to $password"
		#		echo
		#	done
		#fi

		for u in "${users[@]}"
		do
			read -p "[?] Modify user $u ? [y/N]" -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ ]]
			then
				header "Editing user: $u"
				read -p "[?] Remove user $u ? [y/N] " -n 1 -r
				echo
				if [[ $REPLY =~ ^[Yy]$ ]]
				then
				 	if [[ $u == $SUDO_USER ]]
					then
					 	error "You are $u, cannot remove yourself!"
					else
						userdel $u
						groupdel $u
						success "$u has been removed."
					fi
				else
					read -p "[?] Change $u's password? [y/N]" -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]
					then
						passwd $u
						success "$u's password changed."
					else
						notify "Did not change $u's password"
					fi
					
					read -p "[?] Lock $u's account to prevent login? [y/N]" -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]
					then
						passwd -l $u
						success "User $u locked."
					else
						notify "Did not lock $u's account"
					fi


					read -p "[?] Should $u be an administrator (in sudo)? [y/N]" -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]
					then
						groups $u | grep "sudo" > /dev/null
						if [ $? -eq 0 ];
						then
							success "User $u is already an administrator - no change."
						else
							usermod -aG sudo $u
							success "User $u was added to the sudo group."
						fi
					else
						groups $u | grep "sudo" > /dev/null
						if [ $? -eq 0 ];
						then
							notify "User $u was an Administrator."
							deluser $u sudo
							success "Removed $u from sudo group."
						else
							success "User $u is already not an administrator - no change."
						fi
					fi
				fi
			fi
		done
	fi
	success "All user modifications complete."
	read -p "[?] Do you want to check /etc/sudoers? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		read -p "Press any key to check sudoers." -n 1 -r
		echo
		success "Launching visudo."
		visudo
	fi
	printf "\n"
	success "User lockdown complete."
}

# Offline - Modify Configs
function check_configs()
{
	header "\nCheck Configs"
	read -p "[?] Would you like to check config files? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		#grep -qxF 'nospoof on' /etc/host.conf || echo 'nospoof on' >> /etc/host.conf  # obsolete?
		sudoedit /etc/hosts
		sudoedit /etc/crontab
		echo "The following users have active crontabs:"
		ls /var/spool/cron/crontabs
		echo
		notify "Make sure to set lightdm guest to false and if asked to, disable auto-login. (allow-guest=False)"
		read -p "[?] Press any key to check /etc/lightdm/lightdm.conf" -n 1 -r
		echo
		grep -qxF 'allow-guest=False' /etc/lightdm/lightdm.conf || echo 'allow-guest=False' >> /etc/lightdm/lightdm.conf
		sudoedit /etc/lightdm/lightdm.conf
		printf "\n"
		success "Finish config editing."
	fi
}

# Offline - Remove packages
function check_bad_programs()
{
	declare -a bad=(
		"aircrack-ng"
		"airgeddon"
		"amass"
		"arjun"
		"armitage"
		"arping"
		"autopsy"
		"bed"
		"beef-xss"
		"binwalk"
		"bloodhound"
		"btscanner"
		"bully"
		"burpsuite"
		"cadaver"
		"chisel"
		"chntpw"
		"cmospwd"
		"commix"
		"crackmapexec"
		"crunch"
		"cupp3"
		"dirb"
		"dirbuster"
		"dirsearch"
		"dmitry"
		"dnsmap"
		"dnsrecon"
		"driftnet"
		"enum4linux"
		"evil-winrm"
		"exploitdb"
		"eyewitness"
		"fcrackzip"
		"fern-wifi-cracker"
		"ffuf"
		"fierce"
		"foremost"
		"gobuster"
		"goldeneye"
		"hashcat"
		"hping3"
		"hydra"
		"ike-scan"
		"impacket-scripts"
		"john"
		"johnny"
		"kismet"
		"legion"
		"macchanger"
		"maltego"
		"masscan"
		"mdk3"
		"mdk4"
		"medusa"
		"metagoofil"
		"mimikatz"
		"nbtscan"
		"nc"
		"ncrack"
		"netcat"
		"netdiscover"
		"nikto"
		"nmap"
		"nuclei"
		"ophcrack"
		"p0f"
		"parsero"
		"rainbowcrack"
		"reaver"
		"recon-ng"
		"responder"
		"routersploit"
		"scapy"
		"shellter"
		"sherlock"
		"smbmap"
		"socat"
		"spiderfoot"
		"sqlmap"
		"sslscan"
		"sslstrip"
		"steghide"
		"sublist3r"
		"tcpdump"
		"telnet"
		"theharvester"
		"veil"
		"wafw00f"
		"wfuzz"
		"whatweb"
		"wifiphisher"
		"wifite"
		"wireshark"
		"wpscan"
		"yersinia"
	)

	declare -a possibly_bad=(
		"samba"
		"bind9"
		"vsftpd"
		"apache2"
		"nginx"
		"telnet"
	)

	header  "\nChecking for 'bad' programs."
	read -p "[?] Would you like to check for bad programs? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		header "Checking netcat variants..."
		apt-get purge netcat-*   # Removes any alternative netcat packages

		# Remove bad programs
		header "Checking bad programs..."
		for b in "${bad[@]}"
		do
			if dpkg --get-selections | grep -q "^$b[[:space:]]*install$" >/dev/null;then
				notify "$b is installed, remove?"
				apt-get purge $b
			fi
		done
		success "Checking bad programs done."
		
		# Notify of any bad programs that may be a required service
		header "Checking potentially bad programs..."
		for pb in "${possibly_bad[@]}"
		do
			if dpkg --get-selections | grep -q "^$pb[[:space:]]*install$" >/dev/null;then
				notify "$pb is installed, remove/disable if not a required service."
			fi
		done
		success "Checking potentially bad programs done."
	fi
}

function check_services()
{
	header "\nServices"
	read -p "[?] List enabled services? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		success "Displaying enabled services:"
		service --status-all | grep '+'
	fi
	echo

	read -p "[?] List active network connections? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		success "Displaying active network connections with 'lsof -nP -i':"
		lsof -nP -i
	fi
	echo
}

# Forensics / Hivestorm
function find_media()
{
	header "\nMedia files"
	read -p "[?] Find prohibited media files? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		chkdir="/home/"
		dmpfile="$HOME/media_files.txt"
		sarray=()
		header "Checking for media files in ${chkdir}"
		touch $dmpfile
		declare -a extensions=(
			"avi"
			"flac"
			"gif"
			"ico"
			"jpeg"
			"jpg"
			"m4a"
			"m4b"
			"mid"
			"midi"
			"mov"
			"movi"
			"mp3"
			"mp4"
			"mpeg"
			"mpg"
			"ogg"
			"png"
			"svg"
			"txt"
			"wav"
			"wmv"
		)
		for i in "${extensions[@]}"
		do
			sarray=($(find $chkdir -type f -name "*.$i" | tee -a $dmpfile))
			echo "[*] Checking $i files - Found ${#sarray[@]}"
		done
		printf "\n"
		notify "Saving file paths to ${dmpfile}"
	fi

}

# Online - Updating packages
function install_updates()
{
	header "\nInstalling Updates"
	read -p "[?] Would you like to install updates? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		apt-get update
		apt-get upgrade -y
		#apt-get dist-upgrade -y  # probably not recommended?
	fi
}

# Online - Installing AV
function enable_av()
{
	header "\nAnti-Virus lockdown"
	command -v clamscan >/dev/null
	if [ $? -eq 0 ];then
		success "ClamAV found."
		freshclam
		success "Updated definitions."
	else
		error "ClamAV not installed."
		read -p "[?] Would you like to install ClamAV? [y/N] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y clamav
			freshclam
			success "ClamAV is now enabled and updated."
		fi
	fi
}

# Online - rkhunter
function check_rootkits()
{
	header "\nChecking for rootkits (rkhunter)"
	command -v rkhunter >/dev/null
	if [ $? -eq 0 ];then
		success "rkhunter found."
		rkhunter --update
		rkhunter --propupd
		success "Updated definitions."
	else
		error "rkhunter not installed."
		read -p "[?] Would you like to install rkhunter? [y/N] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y rkhunter
			rkhunter --update
			rkhunter --propupd
			rkhunter -c --enable all --disable none
			cat /var/log/rkhunter.log | grep "Warning"

			success "Rkhunter scan finished. Check /var/log/rkhunter.log and grep for \"Warning\" to see results"
		fi
	fi
}

# Online - Installing ufw
function enable_ufw()
{
	header "\nFirewall Lockdown"
	command -v ufw >/dev/null
	if [ $? -eq 0 ];then
		success "UFW found"
		read -p "[?] Enable UFW? [y/N] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
		ufw enable > /dev/null
		success "UFW enabled."
		else
		notify "UFW not enabled."
		fi
	else
		error "UFW not installed."
		read -p "[?] Would you like to install & enable UFW? [y/N] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y ufw
			ufw enable > /dev/null
			success "UFW installed and enabled."
		else
			notify "UFW not installed."
		fi
	fi
}


# Main Modes
function mode_auto(){
	# sudo ./lockdown.sh -a
	success "RUN MODE: AUTOMATIC (just y/n prompts)"

	disable_aliases
	choose_editor
	ssh_lockdown
	kernel_lockdown
	user_lockdown
	check_configs
	check_bad_programs
	check_services
	enable_ufw
	#enable_av		# Disabled for time
	#check_rootkits # Disabled for time
	install_updates
	find_media 
}
function mode_autoOffline(){
	# sudo ./lockdown.sh -o
	success "RUN MODE: OFFLINE"

	#choose_editor
	ssh_lockdown
	kernel_lockdown
	#user_lockdown
	#check_configs
	check_bad_programs
	check_services
	#enable_ufw
	#enable_av		# Disabled for time
	#install_updates
	#find_media 	# Disabled for CCDC
}
function mode_userLockdown(){
	# sudo ./lockdown.sh -u
	success "RUN MODE: USER LOCKDOWN"

	user_lockdown
}
function mode_avScan(){
	# sudo ./lockdown.sh -s
	success "RUN MODE: AV/ROOTKIT SCAN (SLOW!)"

	enable_av
	check_rootkits
}
function mode_help(){
    echo "Specify an option:"
	echo "-a: Auto mode, default (recommended)"
	echo "-o: Auto mode, offline boxes only"
	echo "-u: User lockdown steps only"
	echo "-s: Scan for viruses/rootkits only"
	exit 0
}

# Main runtime code
if [ "$EUID" -ne 0 ]
  then echo "Please run as root: sudo ./lockdown.sh"
  exit 1
fi

CURRENT_USER=$(whoami)

echo
header "Linux Lockdown Script"
echo "Authors.......: TNAR5, colonket, ferdinand"
echo "Version.......: 1.3"
echo "OS............: $(hostnamectl | grep "Operating System" | awk -F ": " '{print $2}')"
echo "Executing User: $CURRENT_USER"
printf "\n\n"

# no args provided, help menu
if [[ $# -eq 0 ]] ; then
	mode_help
fi

# mandatory readme
read -p "[?] Have you read the README and the Forensics Questions? [y/N]" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]];then
	heart "Thank you for reading the info!" 
	echo
else
	error "Please read the files on the desktop to make sure that the script is not messing with anything essential."
	exit 1
fi

# args for different options
case "$1" in
	-a) 	mode_auto;;
	-o) 	mode_autoOffline;;
	-u) 	mode_userLockdown;;
	-s)		mode_avScan;;
	*)		mode_help;;
esac

header "\nThings left to do:"
notify "Secure Root - Change root password and disable if allowed!"
notify "Update kernel"
notify "Update the APT Package Manager Source (Settings > Software and Updates > Download From)"
notify "Pam cracklib password requirements/logging"
notify "Discover rootkits/backdoors"
notify "Check file permissions"
notify "Check init scripts"
notify "Web browser updates and security"
notify "ADD USERS NOT IN THE LIST"
notify "Win - Good Luck! :D"

success "Script finished execution."
exit 0
