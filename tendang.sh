#!/bin/bash
clear
MAX=1
REPEAT_PERIOD=10      # Minutes to look back for repeat violations
BAN_DURATION=60       # Ban duration in seconds (1 minute)
VIOLATION_THRESHOLD=2 # Number of violations before banning

# Get parameters, if provided
if [[ ${1+x} ]]; then
    MAX=$1
fi
if [[ ${2+x} ]]; then
    REPEAT_PERIOD=$2
fi
if [[ ${3+x} ]]; then
    BAN_DURATION=$3
fi
if [[ ${4+x} ]]; then
    VIOLATION_THRESHOLD=$4
fi

# Log parameters for debugging
echo "$(date): tendang executed with: MAX=$MAX, PERIOD=$REPEAT_PERIOD, DURATION=$BAN_DURATION, THRESHOLD=$VIOLATION_THRESHOLD" >>/root/tendang-debug.log

# Determine OS type for log file
if [ -e "/var/log/auth.log" ]; then
    OS=1
    LOG="/var/log/auth.log"
fi
if [ -e "/var/log/secure" ]; then
    OS=2
    LOG="/var/log/secure"
fi

# Restart services
if [ $OS -eq 1 ]; then
    service ssh restart >/dev/null 2>&1
fi
if [ $OS -eq 2 ]; then
    service sshd restart >/dev/null 2>&1
fi
service dropbear restart >/dev/null 2>&1

# Create necessary files if they don't exist
touch /root/banned-users.txt
touch /root/violations.log # New dedicated violations log
touch /root/unban-debug.log # Debug log for unban operations

# Clean up old violations from the log - keep only entries within our window
# This prevents continuous banning due to old entries
current_time=$(date +%s)
cutoff_time=$((current_time - REPEAT_PERIOD * 60))
cutoff_date=$(date -d "@$cutoff_time" "+%Y-%m-%d %H:%M:%S")

# Clean violations log - keep only recent violations
if [ -f "/root/violations.log" ]; then
    # Create temp file with only recent violations
    awk -v cutoff="$cutoff_date" '$0 >= cutoff {print $0}' /root/violations.log >/tmp/recent-violations.log
    # Replace the violations log with only recent entries
    mv /tmp/recent-violations.log /root/violations.log
fi

# Debug: log banned users before processing
echo "$(date): Current banned users before unban check:" >>/root/unban-debug.log
if [ -s "/root/banned-users.txt" ]; then
    cat "/root/banned-users.txt" >>/root/unban-debug.log
else
    echo "  No banned users found" >>/root/unban-debug.log
fi

# Check for expired bans and unban users
echo "$(date): Starting unban check. Current time: $current_time" >>/root/unban-debug.log
unbanned_count=0

while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines
    if [ -z "$line" ]; then
        continue
    fi

    username=$(echo $line | awk '{print $1}')
    ban_time=$(echo $line | awk '{print $2}')
    ban_duration=$(echo $line | awk '{print $3}')

    # Log each entry being processed
    echo "$(date): Processing ban record: username='$username', ban_time='$ban_time', duration='$ban_duration'" >>/root/unban-debug.log

    # Skip if ban_time is not valid
    if [[ -z "$ban_time" || "$ban_time" == "@" ]]; then
        echo "$(date): Invalid ban time for $username, skipping" >>/root/unban-debug.log
        continue
    fi

    # Use default ban duration if not specified in file
    if [ -z "$ban_duration" ]; then
        ban_duration=$BAN_DURATION
        echo "$(date): No duration specified for $username, using default: $ban_duration seconds" >>/root/unban-debug.log
    fi

    # Calculate time elapsed since ban
    time_elapsed=$((current_time - ban_time))
    ban_expiry=$((ban_time + ban_duration))
    readable_ban_time=$(date -d "@$ban_time" "+%Y-%m-%d %H:%M:%S")
    readable_expiry=$(date -d "@$ban_expiry" "+%Y-%m-%d %H:%M:%S")
    
    echo "$(date): User $username was banned at $readable_ban_time, expires at $readable_expiry" >>/root/unban-debug.log
    echo "$(date): Time elapsed: $time_elapsed seconds, Duration: $ban_duration seconds" >>/root/unban-debug.log

    # Check if ban period is over
    if [ $time_elapsed -ge $ban_duration ]; then
        echo "$(date): Ban period expired for $username, unlocking account..." >>/root/unban-debug.log
        
        # Check if user exists before trying to unban
        if id "$username" >/dev/null 2>&1; then
            # Get current account status
            account_status=$(passwd -S "$username" 2>/dev/null)
            echo "$(date): Current account status: $account_status" >>/root/unban-debug.log
            
            # Try to unlock with passwd -u and capture output
            unban_output=$(passwd -u "$username" 2>&1)
            unban_result=$?
            echo "$(date): Unban command result: $unban_result, Output: $unban_output" >>/root/unban-debug.log
            
            # Check new account status
            new_status=$(passwd -S "$username" 2>/dev/null)
            echo "$(date): New account status: $new_status" >>/root/unban-debug.log
            
            # Remove from banned list
            grep -v "^$username " /root/banned-users.txt >/tmp/banned-users.tmp
            mv /tmp/banned-users.tmp /root/banned-users.txt
            
            # IMPORTANT: Clear this user's violations from the violations log
            # to prevent immediate re-banning after unban
            if [ -f "/root/violations.log" ]; then
                echo "$(date): Clearing previous violations for $username" >>/root/unban-debug.log
                # Create temp file without this user's violations
                grep -v " - $username - " /root/violations.log >/tmp/clean-violations.log
                # Replace the violations log with the cleaned version
                mv /tmp/clean-violations.log /root/violations.log
            fi
            
            echo "$(date): Auto-unbanned user $username (ban period expired)" >>/root/log-limit.txt
            unbanned_count=$((unbanned_count + 1))
            
            # Notify user they've been unbanned if possible
            if [ -d "/home/${username}" ]; then
                echo "Your account has been automatically unbanned. Please maintain proper connection limits to avoid future bans." >/home/${username}/unban_notification.txt
                # Set appropriate permissions
                chown ${username}:${username} /home/${username}/unban_notification.txt 2>/dev/null
            fi
        else
            echo "$(date): Error: User $username does not exist, cannot unban" >>/root/unban-debug.log
            # Still remove from banned list
            grep -v "^$username " /root/banned-users.txt >/tmp/banned-users.tmp
            mv /tmp/banned-users.tmp /root/banned-users.txt
            
            # Also remove violations for non-existent users
            if [ -f "/root/violations.log" ]; then
                grep -v " - $username - " /root/violations.log >/tmp/clean-violations.log
                mv /tmp/clean-violations.log /root/violations.log
            fi
        fi
    else
        time_remaining=$((ban_duration - time_elapsed))
        echo "$(date): Ban still active for $username. $time_remaining seconds remaining." >>/root/unban-debug.log
    fi
done </root/banned-users.txt

echo "$(date): Unban check completed. Unbanned $unbanned_count users." >>/root/unban-debug.log

# Debug: log banned users after processing
echo "$(date): Remaining banned users after unban check:" >>/root/unban-debug.log
if [ -s "/root/banned-users.txt" ]; then
    cat "/root/banned-users.txt" >>/root/unban-debug.log
else
    echo "  No banned users remaining" >>/root/unban-debug.log
fi

# Get all users with home directories
cat /etc/passwd | grep "/home/" | cut -d":" -f1 >/root/user.txt
username1=($(cat "/root/user.txt"))
i="0"
for user in "${username1[@]}"; do
    username[$i]=$(echo $user | sed 's/'\''//g')
    jumlah[$i]=0
    i=$i+1
done

# Process Dropbear connections
cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" >/tmp/log-db.txt
proc=($(ps aux | grep -i dropbear | awk '{print $2}'))
for PID in "${proc[@]}"; do
    cat /tmp/log-db.txt | grep "dropbear\[$PID\]" >/tmp/log-db-pid.txt
    NUM=$(cat /tmp/log-db-pid.txt | wc -l)
    USER=$(cat /tmp/log-db-pid.txt | awk '{print $10}' | sed 's/'\''//g')
    IP=$(cat /tmp/log-db-pid.txt | awk '{print $12}')
    if [ $NUM -eq 1 ]; then
        i=0
        for user1 in "${username[@]}"; do
            if [ "$USER" == "$user1" ]; then
                jumlah[$i]=$(expr ${jumlah[$i]} + 1)
                pid[$i]="${pid[$i]} $PID"
            fi
            i=$i+1
        done
    fi
done

# Process SSH connections
cat $LOG | grep -i sshd | grep -i "Accepted password for" >/tmp/log-db.txt
data=($(ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'))
for PID in "${data[@]}"; do
    cat /tmp/log-db.txt | grep "sshd\[$PID\]" >/tmp/log-db-pid.txt
    NUM=$(cat /tmp/log-db-pid.txt | wc -l)
    USER=$(cat /tmp/log-db-pid.txt | awk '{print $9}')
    IP=$(cat /tmp/log-db-pid.txt | awk '{print $11}')
    if [ $NUM -eq 1 ]; then
        i=0
        for user1 in "${username[@]}"; do
            if [ "$USER" == "$user1" ]; then
                jumlah[$i]=$(expr ${jumlah[$i]} + 1)
                pid[$i]="${pid[$i]} $PID"
            fi
            i=$i+1
        done
    fi
done

# Check for users exceeding max connections and take action
j="0"
for i in ${!username[*]}; do
    if [ ${jumlah[$i]} -gt $MAX ]; then
        current_date=$(date +"%Y-%m-%d %H:%M:%S")
        current_timestamp=$(date +%s)

        # Log to both the general log and the violations log
        echo "$current_date - ${username[$i]} - ${jumlah[$i]}" >>/root/log-limit.txt
        echo "$current_date - ${username[$i]} - ${jumlah[$i]}" >>/root/violations.log

        # Output to console
        echo "$current_date - ${username[$i]} - ${jumlah[$i]}"

        # Check if the user is already banned
        if grep -q "^${username[$i]} " /root/banned-users.txt; then
            # User is already banned, just kill their connections
            kill ${pid[$i]} 2>/dev/null
            pid[$i]=""
            echo "$(date): KILLED connections for banned user ${username[$i]}" >>/root/log-limit.txt
            j=$(expr $j + 1)
            continue
        fi

        # Count recent violations (only from the cleaned violations log)
        violation_count=$(grep -c " - ${username[$i]} - " /root/violations.log)

        # If violations meet or exceed the threshold, ban the user
        if [ $violation_count -ge $VIOLATION_THRESHOLD ]; then
            echo "$(date): Banning user ${username[$i]} due to $violation_count violations in last $REPEAT_PERIOD minutes" >>/root/log-limit.txt

            # Lock the account
            passwd -l ${username[$i]} >/dev/null 2>&1

            # Add to banned users with timestamp and duration
            echo "${username[$i]} $current_timestamp $BAN_DURATION" >>/root/banned-users.txt

            # Format readable time for log
            ban_end_time=$(date -d "@$((current_timestamp + BAN_DURATION))" "+%Y-%m-%d %H:%M:%S")
            echo "$(date): BANNED user ${username[$i]} until $ban_end_time for exceeding connection limit" >>/root/log-limit.txt

            # Inform the user of the ban (through a file they can check)
            if [ -d "/home/${username[$i]}" ]; then
                echo "You have been banned for $((BAN_DURATION / 60)) minutes due to multiple multilogin violations." >/home/${username[$i]}/ban_notification.txt
            fi
        else
            echo "$(date): Warning given to ${username[$i]} for exceeding connection limit ($violation_count/$VIOLATION_THRESHOLD)" >>/root/log-limit.txt
        fi

        # Kill all connections for this user
        kill ${pid[$i]} 2>/dev/null
        pid[$i]=""
        j=$(expr $j + 1)
    fi
done

# Restart services if any violations were found
if [ $j -gt 0 ]; then
    if [ $OS -eq 1 ]; then
        service ssh restart >/dev/null 2>&1
    fi
    if [ $OS -eq 2 ]; then
        service sshd restart >/dev/null 2>&1
    fi
    service dropbear restart >/dev/null 2>&1
    j=0
fi
