#!/bin/bash
# Discription: Linux lock down script
# Author: TNAR5
# Version: 1

CURRENT_USER = $(whoami)

if ! [($CURRENT_USER == 'root')];
then echo "You must execute this script as root."
exit 1
fi




function ssh_lockdown{

}

function kernel_lockdown{

}

function lockout_policy{

} 

function remove_guest{

}

function user_lockdown{

}