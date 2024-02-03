#!/usr/bin/env bash 

#
# change network ports to mtu 9000
#

errmsg()
{
    echo $* >&1
} # errmsg

validate_nic()
{

    # Validate NICs
    ip a | grep $1: &> /dev/null
    if [ $? != 0 ]; then
        errmsg "Error: Network interface $1 not found"
        return 1
    fi

    ethtool $1 &> /dev/null
    if [ $? != 0 ]; then
        errmsg "Error: Network interface $1 not found"
        return 1
    fi

    if [ `ethtool $1 | grep "Link detected:" | cut -d: -f2` != "yes" ]; then
        errmsg "Error: Network interface $1 offline"
        return 1
    fi

    INET=`ip address show dev $1 | grep "inet "`
    if [ $? != 0 ]; then
        errmsg "Error: Interface $1 has no ip address"
        return 1
    fi

    echo "$INET" | awk '{print $2}'

    return 0
} # validate_nic


###################################################
# Main
###################################################

#Garther Info
if [ $# -ne 2 ]; then
    echo "Usage: $0 nic_interface1"
    echo "    example: $0 enp59s0f0"
    exit 1
else
    NIC1=`nmcli con show | grep $1 |awk '{print $1}'`
    NIC_DEV1=`nmcli con show | grep $1 |awk '{print $4}'`
fi

# check that the nic given is sane and fetch address info - X.X.X.X/nn
NIC1_IP_SPEC=`validate_nic $NIC_DEV1`
if [ $? != 0 ]; then
    exit 1

# unit test
#exit
#example 
#nmcli connection modify team1-port1 802-3-ethernet.mtu 9000
#nmcli device reapply ens3f0np0;
# check for route scripts
echo "Setting MTU 9000 for $NIC1"
nmcli connection modify $NIC1 802-3-ethernet.mtu 9000

# Apply nmcli
nmcli device reapply $NIC_DEV1
