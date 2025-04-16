BIBlack='\033[1;90m'     # Black
BIRed='\033[1;91m'       # Red
BIGreen='\033[1;92m'     # Green
BIYellow='\033[1;93m'    # Yellow
BIBlue='\033[1;94m'      # Blue
BIPurple='\033[1;95m'    # Purple
BICyan='\033[1;96m'      # Cyan
BIWhite='\033[1;97m'     # White
UWhite='\033[4;37m'      # White
On_IPurple='\033[0;105m' #
On_IRed='\033[0;101m'
IBlack='\033[0;90m'  # Black
IRed='\033[0;91m'    # Red
IGreen='\033[0;92m'  # Green
IYellow='\033[0;93m' # Yellow
IBlue='\033[0;94m'   # Blue
IPurple='\033[0;95m' # Purple
ICyan='\033[0;96m'   # Cyan
IWhite='\033[0;97m'  # White
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'

# // Export Banner Status Information
export EROR="[${RED} EROR ${NC}]"
export INFO="[${YELLOW} INFO ${NC}]"
export OKEY="[${GREEN} OKEY ${NC}]"
export PENDING="[${YELLOW} PENDING ${NC}]"
export SEND="[${YELLOW} SEND ${NC}]"
export RECEIVE="[${YELLOW} RECEIVE ${NC}]"

# // Export Align
export BOLD="\e[1m"
export WARNING="${RED}\e[5m"
export UNDERLINE="\e[4m"

# // Exporting URL Host
export Server_URL="raw.githubusercontent.com/NevermoreSSH/Blueblue/main/test"
export Server1_URL="raw.githubusercontent.com/NevermoreSSH/Blueblue/main/limit"
export Server_Port="443"
export Server_IP="underfined"
export Script_Mode="Stable"
export Auther=".geovpn"

# // Root Checking
if [ "${EUID}" -ne 0 ]; then
	echo -e "${EROR} Please Run This Script As Root User !"
	exit 1
fi

# // Exporting IP Address
export IP=$(curl -s https://ipinfo.io/ip/)

# // Exporting Network Interface
export NETWORK_IFACE="$(ip route show to default | awk '{print $5}')"

clear
function del() {
	clear
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[0;41;36m               DELETE USER                \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo ""
	read -p "Username SSH to Delete : " Pengguna

	if getent passwd $Pengguna >/dev/null 2>&1; then
		userdel $Pengguna >/dev/null 2>&1
		echo -e "User $Pengguna was removed."
	else
		echo -e "Failure: User $Pengguna Not Exist."
	fi

	read -n 1 -s -r -p "Press any key to back on menu"

	menu
}
function autodel() {
	clear
	hariini=$(date +%d-%m-%Y)
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[0;41;36m               AUTO DELETE                \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo "Thank you for removing the EXPIRED USERS"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	cat /etc/shadow | cut -d: -f1,8 | sed /:$/d >/tmp/expirelist.txt
	totalaccounts=$(cat /tmp/expirelist.txt | wc -l)
	for ((i = 1; i <= $totalaccounts; i++)); do
		tuserval=$(head -n $i /tmp/expirelist.txt | tail -n 1)
		username=$(echo $tuserval | cut -f1 -d:)
		userexp=$(echo $tuserval | cut -f2 -d:)
		userexpireinseconds=$(($userexp * 86400))
		tglexp=$(date -d @$userexpireinseconds)
		tgl=$(echo $tglexp | awk -F" " '{print $3}')
		while [ ${#tgl} -lt 2 ]; do
			tgl="0"$tgl
		done
		while [ ${#username} -lt 15 ]; do
			username=$username" "
		done
		bulantahun=$(echo $tglexp | awk -F" " '{print $2,$6}')
		echo "echo "Expired- User : $username Expire at : $tgl $bulantahun"" >>/usr/local/bin/alluser
		todaystime=$(date +%s)
		if [ $userexpireinseconds -ge $todaystime ]; then
			:
		else
			echo "echo "Expired- Username : $username are expired at: $tgl $bulantahun and removed : $hariini "" >>/usr/local/bin/deleteduser
			echo "Username $username that are expired at $tgl $bulantahun removed from the VPS $hariini"
			userdel $username
		fi
	done
	echo " "
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

	read -n 1 -s -r -p "Press any key to back on menu"
	menu

}
function ceklim() {
	clear
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[0;41;36m         CHECK USER MULTI SSH        \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	if [ -e "/root/log-limit.txt" ]; then
		echo "User Who Violate The Maximum Limit"
		echo "Time - Username - Number of Multilogin"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		cat /root/log-limit.txt
	else
		echo " No user has committed a violation"
		echo " "
		echo " or"
		echo " "
		echo " The user-limit script not been executed."
	fi
	echo " "
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo " "
	read -n 1 -s -r -p "Press any key to back on menu"
	menu
}
function cek() {
	if [ -e "/var/log/auth.log" ]; then
		LOG="/var/log/auth.log"
	fi
	if [ -e "/var/log/secure" ]; then
		LOG="/var/log/secure"
	fi

	data=($(ps aux | grep -i dropbear | awk '{print $2}'))
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[0;41;36m         Dropbear User Login       \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo "ID  |  Username  |  IP Address"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" >/tmp/login-db.txt
	for PID in "${data[@]}"; do
		cat /tmp/login-db.txt | grep "dropbear\[$PID\]" >/tmp/login-db-pid.txt
		NUM=$(cat /tmp/login-db-pid.txt | wc -l)
		USER=$(cat /tmp/login-db-pid.txt | awk '{print $10}')
		IP=$(cat /tmp/login-db-pid.txt | awk '{print $12}')
		if [ $NUM -eq 1 ]; then
			echo "$PID - $USER - $IP"
		fi
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

	done
	echo " "
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[0;41;36m          OpenSSH User Login       \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo "ID  |  Username  |  IP Address"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	cat $LOG | grep -i sshd | grep -i "Accepted password for" >/tmp/login-db.txt
	data=($(ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'))

	for PID in "${data[@]}"; do
		cat /tmp/login-db.txt | grep "sshd\[$PID\]" >/tmp/login-db-pid.txt
		NUM=$(cat /tmp/login-db-pid.txt | wc -l)
		USER=$(cat /tmp/login-db-pid.txt | awk '{print $9}')
		IP=$(cat /tmp/login-db-pid.txt | awk '{print $11}')
		if [ $NUM -eq 1 ]; then
			echo "$PID - $USER - $IP"
		fi
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

	done
	if [ -f "/etc/openvpn/server/openvpn-tcp.log" ]; then
		echo " "
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "\E[0;41;36m          OpenVPN TCP User Login         \E[0m"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo "Username  |  IP Address  |  Connected Since"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		cat /etc/openvpn/server/openvpn-tcp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' >/tmp/vpn-login-tcp.txt
		cat /tmp/vpn-login-tcp.txt
	fi
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

	if [ -f "/etc/openvpn/server/openvpn-udp.log" ]; then
		echo " "
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "\E[0;41;36m          OpenVPN UDP User Login         \E[0m"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo "Username  |  IP Address  |  Connected Since"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		cat /etc/openvpn/server/openvpn-udp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' >/tmp/vpn-login-udp.txt
		cat /tmp/vpn-login-udp.txt
	fi
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo ""

	rm -f /tmp/login-db-pid.txt
	rm -f /tmp/login-db.txt
	rm -f /tmp/vpn-login-tcp.txt
	rm -f /tmp/vpn-login-udp.txt
	read -n 1 -s -r -p "Press any key to back on menu"

	menu
}
function member() {
	clear
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[0;41;36m                 MEMBER SSH               \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo "USERNAME          EXP DATE          STATUS"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	while read expired; do
		AKUN="$(echo $expired | cut -d: -f1)"
		ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
		exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
		status="$(passwd -S $AKUN | awk '{print $2}')"
		if [[ $ID -ge 1000 ]]; then
			if [[ "$status" = "L" ]]; then
				printf "%-17s %2s %-17s %2s \n" "$AKUN" "$exp     " "LOCKED${NORMAL}"
			else
				printf "%-17s %2s %-17s %2s \n" "$AKUN" "$exp     " "UNLOCKED${NORMAL}"
			fi
		fi
	done </etc/passwd
	JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo "Account number: $JUMLAH user"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	read -n 1 -s -r -p "Press any key to back on menu"
	menu
}
function renew() {
	clear
	clear
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[0;41;36m               RENEW  USER                \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo
	read -p "Username : " User
	egrep "^$User" /etc/passwd >/dev/null
	if [ $? -eq 0 ]; then
		read -p "Day Extend : " Days
		Today=$(date +%s)
		Days_Detailed=$(($Days * 86400))
		Expire_On=$(($Today + $Days_Detailed))
		Expiration=$(date -u --date="1970-01-01 $Expire_On sec GMT" +%Y/%m/%d)
		Expiration_Display=$(date -u --date="1970-01-01 $Expire_On sec GMT" '+%d %b %Y')
		passwd -u $User
		usermod -e $Expiration $User
		egrep "^$User" /etc/passwd >/dev/null
		echo -e "$Pass\n$Pass\n" | passwd $User &>/dev/null
		clear
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "\E[0;41;36m               RENEW  USER                \E[0m"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""
		echo -e " Username : $User"
		echo -e " Days Added : $Days Days"
		echo -e " Expires on :  $Expiration_Display"
		echo -e ""
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	else
		clear
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "\E[0;41;36m               RENEW  USER                \E[0m"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""
		echo -e "   Username Doesnt Exist      "
		echo -e ""
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	fi
	read -n 1 -s -r -p "Press any key to back on menu"
	menu
}
function autokill() {
	clear
	Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
	Info="${Green_font_prefix}[ON]${Font_color_suffix}"
	Error="${Red_font_prefix}[OFF]${Font_color_suffix}"
	cek=$(grep -c -E "^# Autokill" /etc/cron.d/tendang)
	if [[ "$cek" = "1" ]]; then
		sts="${Info}"
	else
		sts="${Error}"
	fi

	# Check if tendang script exists
	if [ ! -f "/usr/bin/tendang" ]; then
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "\E[44;1;39m             AUTOKILL SSH          \E[0m"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "${Red_font_prefix}Error: tendang script not found in /usr/bin/${Font_color_suffix}"
		echo -e "Please make sure tendang.sh is properly installed as /usr/bin/tendang"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		read -n 1 -s -r -p "Press any key to back on menu"
		menu
		return
	fi

	clear
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[44;1;39m             AUTOKILL SSH          \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "Status Autokill : $sts        "
	echo -e ""
	echo -e "[1]  Configure AutoKill Settings"
	echo -e "[2]  Turn Off AutoKill/MultiLogin"
	echo -e "[3]  View Current Settings"
	echo -e "[x]  Menu"
	echo ""
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e ""
	read -p "Select option [1-3 or x]: " option
	echo -e ""

	case $option in
	1)
		clear
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "\E[44;1;39m      CONFIGURE AUTOKILL SETTINGS    \E[0m"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""

		# Ask for check frequency
		echo -e "How often should the system check for violations (in minutes)?"
		echo -e "Options: Any value between 1-30 minutes"
		echo -e "Recommended values:"
		echo -e "- 1-2 minutes: For very strict monitoring (higher server load)"
		echo -e "- 5 minutes: Standard monitoring (recommended)"
		echo -e "- 10-15 minutes: Less frequent checks (lower server load)"
		echo -e ""
		read -p "Enter check frequency in minutes [1-30]: " check_freq_min

		# Validate input and set default if needed
		if [[ -z "$check_freq_min" || ! "$check_freq_min" =~ ^[0-9]+$ || "$check_freq_min" -lt 1 || "$check_freq_min" -gt 30 ]]; then
			check_freq_min=5
			echo -e "Using default value: 5 minutes"
			cron_freq="*/5"
			check_display="5 minutes"
		else
			cron_freq="*/$check_freq_min"
			check_display="$check_freq_min minutes"
		fi
		echo -e ""

		# Ask for max connections
		echo -e "What is the maximum number of simultaneous connections allowed per user?"
		echo -e "This is the limit before counting a violation. For example:"
		echo -e "- If set to 1: A user connecting from 2+ devices gets 1 violation"
		echo -e "- If set to 2: A user can use 2 devices, but a 3rd device counts as a violation"
		echo -e "Recommended: 1-2 connections"
		echo -e ""
		read -p "Enter maximum allowed connections [1-10]: " max
		# Set default if empty or invalid
		if [[ -z "$max" || ! "$max" =~ ^[0-9]+$ || "$max" -lt 1 ]]; then
			max=1
			echo -e "Using default value: 1 connection"
		fi
		echo -e ""

		# Ask for violation threshold
		echo -e "How many violations are needed before a user gets banned?"
		echo -e "This counts how many times a user exceeds their connection limit."
		echo -e "Examples:"
		echo -e "- If set to 1: User is banned on first violation (strict)"
		echo -e "- If set to 2: User gets one warning, banned on 2nd violation"
		echo -e "- If set to 3: User gets two warnings, banned on 3rd violation"
		echo -e "Recommended: 2-3 violations"
		echo -e ""
		read -p "Enter violation threshold [1-10]: " violation_threshold
		# Set default if empty or invalid
		if [[ -z "$violation_threshold" || ! "$violation_threshold" =~ ^[0-9]+$ || "$violation_threshold" -lt 1 ]]; then
			violation_threshold=2
			echo -e "Using default value: 2 violations"
		fi
		echo -e ""

		# Ask for repeat violation period
		echo -e "Set the time window to check for repeat violations (in minutes)"
		echo -e "If a user exceeds the connection limit multiple times within"
		echo -e "this period, they will be temporarily banned."
		echo -e "Recommended: 5-15 minutes"
		echo -e ""
		read -p "Enter repeat violation check period [1-60 minutes]: " repeat_period
		# Set default if empty or invalid
		if [[ -z "$repeat_period" || ! "$repeat_period" =~ ^[0-9]+$ || "$repeat_period" -lt 1 ]]; then
			repeat_period=5
			echo -e "Using default value: 5 minutes"
		fi
		echo -e ""

		# Ask for ban duration
		echo -e "How long should users be banned for violations? (in minutes)"
		echo -e "Recommended: 5-30 minutes"
		echo -e ""
		read -p "Enter ban duration [1-1440 minutes]: " ban_minutes
		# Set default if empty or invalid
		if [[ -z "$ban_minutes" || ! "$ban_minutes" =~ ^[0-9]+$ || "$ban_minutes" -lt 1 ]]; then
			ban_minutes=5
			echo -e "Using default value: 5 minutes"
		fi
		# Convert minutes to seconds for the script
		ban_duration=$((ban_minutes * 60))
		echo -e ""

		# Show summary and confirm
		clear
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "\E[44;1;39m         CONFIRM SETTINGS          \E[0m"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "Check frequency    : Every $check_display"
		echo -e "Max connections    : $max"
		echo -e "Violation threshold: $violation_threshold violations"
		echo -e "Violation period   : $repeat_period minutes"
		echo -e "Ban duration       : $ban_minutes minutes"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""
		read -p "Apply these settings? (y/n): " confirm

		if [[ "$confirm" =~ [Yy] ]]; then
			# Make sure tendang has execute permissions
			chmod +x /usr/bin/tendang

			# Create a temporary file for the cron job to avoid issues with truncation
			TEMP_CRON=$(mktemp)

			# Debug: echo settings before writing to cron
			echo "Writing to cron: MAX=$max, PERIOD=$repeat_period, DURATION=$ban_duration, THRESHOLD=$violation_threshold" >>/root/autokill-settings.log

			# Write cron configuration to the temporary file
			echo "# Autokill" >$TEMP_CRON
			echo "$cron_freq * * * *  root /usr/bin/tendang $max $repeat_period $ban_duration $violation_threshold" >>$TEMP_CRON

			# Verify cron content
			echo "Cron content: $(cat $TEMP_CRON)" >>/root/autokill-settings.log

			# Move the temporary file to the final location
			mv $TEMP_CRON /etc/cron.d/tendang

			# Set correct permissions on cron file
			chmod 644 /etc/cron.d/tendang

			# Verify final cron content
			echo "Final cron content: $(cat /etc/cron.d/tendang)" >>/root/autokill-settings.log

			# Log settings for debugging
			echo "$(date): AutoKill settings updated: max=$max, period=$repeat_period, duration=$ban_duration, threshold=$violation_threshold" >>/root/autokill-settings.log

			# Reset logs
			echo "" >/root/log-limit.txt
			echo "" >/root/violations.log

			# Create empty banned-users.txt if it doesn't exist
			touch /root/banned-users.txt

			echo -e ""
			echo -e "======================================"
			echo -e ""
			echo -e "      AutoKill has been activated!"
			echo -e "      System will check every $check_display"
			echo -e "      Max connections allowed: $max"
			echo -e "      Users will be banned after $violation_threshold violations"
			echo -e "      within $repeat_period minutes for $ban_minutes minutes"
			echo -e ""
			echo -e "      Reloading cron service..."

			# Reload and restart cron service with output
			service cron reload
			service cron restart

			echo -e "      Cron service reloaded."
			echo -e "      Installed cron job configuration:"
			echo -e "      $(cat /etc/cron.d/tendang)"
			echo -e "======================================"
		else
			echo -e ""
			echo -e "Settings not applied. No changes made."
		fi
		;;
	2)
		# Backup existing cron file if it exists for reference
		if [ -f "/etc/cron.d/tendang" ]; then
			cp /etc/cron.d/tendang /root/tendang.cron.backup.$(date +%Y%m%d%H%M%S)
		fi

		# Remove cron file
		rm -f /etc/cron.d/tendang

		# Reset logs
		echo "" >/root/log-limit.txt
		echo "" >/root/violations.log

		# Clear banned users
		if [ -f "/root/banned-users.txt" ] && [ -s "/root/banned-users.txt" ]; then
			echo -e "Do you want to unban all currently banned users? (y/n)"
			read -p "" unban_choice

			if [[ "$unban_choice" =~ [Yy] ]]; then
				# Unban all users
				while IFS= read -r line || [ -n "$line" ]; do
					# Skip empty lines
					if [ -z "$line" ]; then
						continue
					fi

					user=$(echo $line | awk '{print $1}')
					# Unlock the account
					passwd -u $user >/dev/null 2>&1
				done </root/banned-users.txt

				# Clear the banned users file
				>/root/banned-users.txt
				echo -e "All users have been unbanned."
			fi
		fi

		echo -e ""
		echo -e "======================================"
		echo -e ""
		echo -e "      AutoKill MultiLogin Turned Off"
		echo -e ""
		echo -e "======================================"
		service cron reload
		service cron restart
		;;
	3)
		clear
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "\E[44;1;39m       CURRENT AUTOKILL SETTINGS     \E[0m"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""

		if [ -f "/etc/cron.d/tendang" ]; then
			# Extract settings from cron file
			cron_schedule=$(grep -v "^#" /etc/cron.d/tendang | awk '{print $1, $2, $3, $4, $5}')
			tendang_params=$(grep -v "^#" /etc/cron.d/tendang | awk '{for(i=8;i<=NF;i++) printf "%s ", $i}')

			# Extract individual parameters
			max_conn=$(echo $tendang_params | awk '{print $1}')
			period=$(echo $tendang_params | awk '{print $2}')
			duration=$(echo $tendang_params | awk '{print $3}')
			threshold=$(echo $tendang_params | awk '{print $4}')

			# Convert duration from seconds to minutes
			duration_min=$((duration / 60))

			echo -e "Cron schedule     : $cron_schedule"
			echo -e "Max connections   : $max_conn"
			echo -e "Violation period  : $period minutes"
			echo -e "Ban duration      : $duration_min minutes"
			echo -e "Violation threshold: $threshold violations"
			echo -e ""
			echo -e "Raw cron entry:"
			echo -e "$(cat /etc/cron.d/tendang)"

			# Debug log info
			if [ -f "/root/autokill-settings.log" ]; then
				echo -e ""
				echo -e "Last setting changes (from log):"
				tail -n 5 /root/autokill-settings.log
			fi
		else
			echo -e "AutoKill is not currently active."
			echo -e "No cron job found in /etc/cron.d/tendang"
		fi

		echo -e ""
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		;;
	x | *)
		menu
		;;
	esac
	read -n 1 -s -r -p "Press any key to back on menu"
	menu
}

function view_banned() {
	clear
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[44;1;39m         BANNED USERS LIST          \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "Username        Ban Time           Remaining"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

	if [ -f "/root/banned-users.txt" ] && [ -s "/root/banned-users.txt" ]; then
		current_time=$(date +%s)
		while IFS= read -r line || [ -n "$line" ]; do
			# Skip empty lines
			if [ -z "$line" ]; then
				continue
			fi

			user=$(echo $line | awk '{print $1}')
			ban_time=$(echo $line | awk '{print $2}')
			ban_duration=$(echo $line | awk '{print $3}')

			# Skip entries with invalid timestamps
			if [[ -z "$ban_time" || "$ban_time" == "@" ]]; then
				continue
			fi

			# Use default duration if not specified
			if [ -z "$ban_duration" ]; then
				ban_duration=300 # Default to 5 minutes
			fi

			ban_date=$(date -d @$ban_time '+%Y-%m-%d %H:%M:%S')
			remaining_seconds=$((ban_duration - (current_time - ban_time)))

			# Only show users still under ban
			if [ $remaining_seconds -gt 0 ]; then
				remaining_minutes=$((remaining_seconds / 60))
				remaining_seconds=$((remaining_seconds % 60))
				printf "%-15s %-18s %dm %ds\n" "$user" "$ban_date" "$remaining_minutes" "$remaining_seconds"
			fi
		done </root/banned-users.txt

		if [ $? -ne 0 ]; then
			echo -e " Error reading banned-users.txt"
		fi
	else
		echo -e " No users are currently banned"
	fi

	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e ""
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[44;1;39m      RECENT VIOLATIONS LOG        \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

	if [ -f "/root/log-limit.txt" ]; then
		# Show the last 15 violations from the log
		echo -e "Last 15 violations:"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		grep -E " - .* - [0-9]+$" /root/log-limit.txt | tail -n 15

		# Show ban events
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e "Recent ban events:"
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		grep "BANNED user" /root/log-limit.txt | tail -n 10
	else
		echo -e " No violation logs found"
	fi

	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e ""
	echo -e "[1] Unban Specific User"
	echo -e "[2] Unban All Users"
	echo -e "[3] Return to Main Menu"
	echo -e ""
	read -p "Select an option [1-3]: " option

	case $option in
	1)
		unban_user
		;;
	2)
		unban_all_users
		;;
	*)
		menu
		;;
	esac
}

function unban_user() {
	clear
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[44;1;39m            UNBAN USER             \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e ""

	if [ ! -f "/root/banned-users.txt" ]; then
		echo -e "No banned users file found."
		echo -e ""
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""
		read -n 1 -s -r -p "Press any key to back on menu"
		menu
		return
	fi

	if [ ! -s "/root/banned-users.txt" ]; then
		echo -e "No banned users found."
		echo -e ""
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""
		read -n 1 -s -r -p "Press any key to back on menu"
		menu
		return
	fi

	echo -e "Currently banned users:"
	echo -e ""
	echo -e "Username        Ban Time           Remaining"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

	current_time=$(date +%s)
	cat /root/banned-users.txt | while read LINE || [ -n "$LINE" ]; do
		# Skip empty lines
		if [ -z "$LINE" ]; then
			continue
		fi

		user=$(echo $LINE | awk '{print $1}')
		ban_time=$(echo $LINE | awk '{print $2}')
		ban_duration=$(echo $LINE | awk '{print $3}')

		# Skip entries with invalid timestamps
		if [[ -z "$ban_time" || "$ban_time" == "@" ]]; then
			continue
		fi

		# Use default duration if not specified
		if [ -z "$ban_duration" ]; then
			ban_duration=300 # Default to 5 minutes
		fi

		ban_date=$(date -d @$ban_time '+%Y-%m-%d %H:%M:%S')
		remaining_seconds=$((ban_duration - (current_time - ban_time)))

		if [ $remaining_seconds -gt 0 ]; then
			remaining_minutes=$((remaining_seconds / 60))
			remaining_seconds=$((remaining_seconds % 60))
			printf "%-15s %-18s %dm %ds\n" "$user" "$ban_date" "$remaining_minutes" "$remaining_seconds"
		fi
	done

	echo -e ""
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e ""
	read -p "Enter username to unban: " UNBAN_USER

	if [[ -n "$UNBAN_USER" ]]; then
		# Check if user exists in banned list
		if grep -q "^$UNBAN_USER " /root/banned-users.txt; then
			# Unlock the account
			passwd -u $UNBAN_USER >/dev/null 2>&1

			# Remove user from banned list
			grep -v "^$UNBAN_USER " /root/banned-users.txt >/tmp/banned-users.tmp
			mv /tmp/banned-users.tmp /root/banned-users.txt

			echo -e "User $UNBAN_USER has been unbanned successfully!"
			echo "$(date): Admin manually unbanned user $UNBAN_USER" >>/root/log-limit.txt
		else
			echo -e "User $UNBAN_USER is not in the banned list."
		fi
	else
		echo -e "No username specified. No action taken."
	fi

	echo -e ""
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e ""
	read -n 1 -s -r -p "Press any key to back on menu"
	menu
}

function unban_all_users() {
	clear
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e "\E[44;1;39m          UNBAN ALL USERS          \E[0m"
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e ""

	if [ ! -f "/root/banned-users.txt" ]; then
		echo -e "No banned users file found."
		echo -e ""
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""
		read -n 1 -s -r -p "Press any key to back on menu"
		menu
		return
	fi

	if [ ! -s "/root/banned-users.txt" ]; then
		echo -e "No banned users found."
		echo -e ""
		echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
		echo -e ""
		read -n 1 -s -r -p "Press any key to back on menu"
		menu
		return
	fi

	banned_count=$(grep -v "^$" /root/banned-users.txt | wc -l)
	echo -e "You are about to unban $banned_count user(s)."
	echo -e "Do you want to continue? (y/n) "
	read answer

	if [[ "$answer" =~ [Yy] ]]; then
		# Unban all users
		while IFS= read -r line || [ -n "$line" ]; do
			# Skip empty lines
			if [ -z "$line" ]; then
				continue
			fi

			user=$(echo $line | awk '{print $1}')
			# Unlock the account
			passwd -u $user >/dev/null 2>&1
		done </root/banned-users.txt

		# Clear the banned users file
		>/root/banned-users.txt
		echo -e "Successfully unbanned all users!"
		echo "$(date): Admin unbanned all users" >>/root/log-limit.txt
	else
		echo -e "Operation cancelled."
	fi

	echo -e ""
	echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
	echo -e ""
	read -n 1 -s -r -p "Press any key to back on menu"
	menu
}

clear
echo -e "${BICyan} ┌─────────────────────────────────────────────────────┐${NC}"
echo -e "       ${BIWhite}${UWhite}SSH MENU ${NC}"
echo -e ""
echo -e "     ${BICyan}[${BIWhite}1${BICyan}] Add Account SSH      "
echo -e "     ${BICyan}[${BIWhite}2${BICyan}] Delete Account SSH      "
echo -e "     ${BICyan}[${BIWhite}3${BICyan}] Renew Account SSH      "
echo -e "     ${BICyan}[${BIWhite}4${BICyan}] Check User SSH     "
echo -e "     ${BICyan}[${BIWhite}5${BICyan}] Multilogin SSH     "
echo -e "     ${BICyan}[${BIWhite}6${BICyan}] Auto Delete user Expired     "
echo -e "     ${BICyan}[${BIWhite}7${BICyan}] Auto Kill user SSH    "
echo -e "     ${BICyan}[${BIWhite}8${BICyan}] Check Member SSH"
echo -e "     ${BICyan}[${BIWhite}9${BICyan}] View Banned Users & Violations"
echo -e " ${BICyan}└─────────────────────────────────────────────────────┘${NC}"
echo -e "     ${BIYellow}Press x or [ Ctrl+C ] • To-${BIWhite}Exit${NC}"
echo ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1)
	clear
	usernew
	;;
2)
	clear
	del
	;;
3)
	clear
	renew
	;;
4)
	clear
	cek
	;;
5)
	clear
	ceklim
	;;
6)
	clear
	autodel
	;;
7)
	clear
	autokill
	;;
8)
	clear
	member
	;;
9)
	clear
	view_banned
	;;
0)
	clear
	menu
	;;
x) exit ;;
*)
	echo -e ""
	echo "Press any key to back on menu"
	sleep 1
	menu
	;;
esac
