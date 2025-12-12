#!/bin/bash
# Auto Delete Expired Users Script
# Triggered via cron to automatically remove expired user accounts
# Logs all deletions to /root/expired-users.txt

# Create log file if it doesn't exist
touch /root/expired-users.txt

# Get current date/time info
current_date=$(date +"%Y-%m-%d %H:%M:%S")
today=$(date +%d-%m-%Y)
todaystime=$(date +%s)

# Log script execution start
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> /root/expired-users.txt
echo "[$current_date] Auto-delete check started" >> /root/expired-users.txt

# Get users with expiration dates from /etc/shadow
# Format: username:expiration_days (days since epoch)
cat /etc/shadow | cut -d: -f1,8 | sed /:$/d > /tmp/expirelist.txt

totalaccounts=$(cat /tmp/expirelist.txt | wc -l)
deleted_count=0

if [ $totalaccounts -eq 0 ]; then
    echo "[$current_date] No accounts with expiration dates found" >> /root/expired-users.txt
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> /root/expired-users.txt
    exit 0
fi

for ((i = 1; i <= $totalaccounts; i++)); do
    tuserval=$(head -n $i /tmp/expirelist.txt | tail -n 1)
    username=$(echo $tuserval | cut -f1 -d:)
    userexp=$(echo $tuserval | cut -f2 -d:)
    
    # Skip if no expiration date set or invalid
    if [ -z "$userexp" ] || [ "$userexp" == "" ]; then
        continue
    fi
    
    # Convert expiration days to seconds (days since epoch * 86400 seconds/day)
    userexpireinseconds=$(($userexp * 86400))
    
    # Get readable expiration date
    tglexp=$(date -d @$userexpireinseconds 2>/dev/null)
    if [ -z "$tglexp" ]; then
        continue
    fi
    
    # Extract day, month, year for formatting
    exp_day=$(echo $tglexp | awk -F" " '{print $3}')
    exp_month=$(echo $tglexp | awk -F" " '{print $2}')
    exp_year=$(echo $tglexp | awk -F" " '{print $6}')
    
    # Pad day with leading zero if needed
    while [ ${#exp_day} -lt 2 ]; do
        exp_day="0"$exp_day
    done
    
    exp_date_formatted="$exp_day $exp_month $exp_year"
    
    # Check if user is expired (expiration time is less than current time)
    if [ $userexpireinseconds -lt $todaystime ]; then
        # Calculate how many days ago the account expired
        days_expired=$(( (todaystime - userexpireinseconds) / 86400 ))
        
        # Get user info before deletion
        user_home=$(grep "^$username:" /etc/passwd | cut -d: -f6)
        user_shell=$(grep "^$username:" /etc/passwd | cut -d: -f7)
        
        # Log detailed info before deletion
        echo "[$current_date] DELETED: $username" >> /root/expired-users.txt
        echo "  - Expired on: $exp_date_formatted" >> /root/expired-users.txt
        echo "  - Days overdue: $days_expired" >> /root/expired-users.txt
        echo "  - Home directory: $user_home" >> /root/expired-users.txt
        echo "  - Deleted on: $today" >> /root/expired-users.txt
        
        # Kill any active sessions for this user first
        pkill -u $username 2>/dev/null
        
        # Delete the user (with home directory removal option: -r)
        # Using -r to also remove home directory, remove -r if you want to keep home dirs
        userdel -r $username 2>/dev/null
        del_result=$?
        
        if [ $del_result -eq 0 ]; then
            echo "  - Status: Successfully removed" >> /root/expired-users.txt
            deleted_count=$((deleted_count + 1))
        else
            # Try without -r flag if first attempt failed
            userdel $username 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "  - Status: Removed (home directory preserved)" >> /root/expired-users.txt
                deleted_count=$((deleted_count + 1))
            else
                echo "  - Status: FAILED to remove (error code: $del_result)" >> /root/expired-users.txt
            fi
        fi
        echo "" >> /root/expired-users.txt
    fi
done

# Log summary
echo "[$current_date] Auto-delete completed: $deleted_count user(s) removed" >> /root/expired-users.txt
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> /root/expired-users.txt
echo "" >> /root/expired-users.txt

# Clean up temp file
rm -f /tmp/expirelist.txt

# Output for cron mail (optional)
if [ $deleted_count -gt 0 ]; then
    echo "Auto-delete: Removed $deleted_count expired user(s) on $today"
fi

exit 0

