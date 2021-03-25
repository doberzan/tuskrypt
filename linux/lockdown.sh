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
echo "a"
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
