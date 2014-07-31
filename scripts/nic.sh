#!/bin/bash
#
# nic.sh
#
# Copyright (C) SINA Corporation
# 


TESTED_DRIVERS=("igb" "ixgbe" "bnx2" "tg3")
TESTED_MODELS=(
    # igb
    "Intel Corporation 82576 Gigabit Network Connection (rev 01)"
    "Intel Corporation I350 Gigabit Network Connection (rev 01)"
    # ixgbe
    "Intel Corporation 82599EB 10-Gigabit SFI/SFP+ Network Connection (rev 01)"
    "Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01)"
    # tg3
    "Broadcom Corporation NetXtreme BCM5720 Gigabit Ethernet PCIe"
    "Broadcom Corporation NetXtreme BCM5761 Gigabit Ethernet PCIe (rev 10)"
    # bnx2
    "Broadcom Corporation NetXtreme II BCM5708 Gigabit Ethernet (rev 12)"
    "Broadcom Corporation NetXtreme II BCM5709 Gigabit Ethernet (rev 20)"
)

if tput colors > /dev/null; then
    RED='\e[0;31m'
    YELLOW='\e[1;33m'
    GREEN='\e[0;32m'
    NC='\e[0m'
else
    RED=''
    YELLOW=''
    NC=''
fi

function print_usage() {
    echo "Usage: $0 -i <NIC to be used>"
    exit 0
}

function err_msg() {
    local msg=$1
    echo -e "$RED[Error] $msg $NC"
    exit 1
}

function warn_msg() {
    local msg=$1
    echo -e "$YELLOW[Warning] $msg $NC"
}

function info_msg() {
    local msg=$1
    echo -e "$msg $NC"
}

function tested() {
    local iface=$1
    local model=$2

    for m in "${TESTED_MODELS[@]}"; do
	if [[ "$model" == "$m" ]]; then
	    return 0
	fi
    done

    return 1
}

function intr_pattern() {
    local iface=$1
    local driver=$2
    case $driver in
	igb|ixgbe)
	    echo $iface-TxRx;;
	bnx2|tg3)
	    echo $iface;;
    esac
}

function hardware_queues() {
    local driver=$1
    local intrs=$2
    case $driver in
	igb|ixgbe|bnx2)
	    echo $intrs;;
	tg3)
	    echo $((intrs-1));;
    esac
}

function intr_list() {
    local iface=$1
    local driver=$2

    case $driver in
	igb|ixgbe|bnx2|tg3)
	    intr_pattern $IFACE $DRIVER | xargs -i grep {} /proc/interrupts | grep -o "^ *[0-9]*" | xargs -i echo {};;
    esac
}

function cpuid_to_mask() {
    local id=$1
    echo $((10**(id/4) * 2**(id%4)))
}

##################################################
# Main part starts here

if [[ ! "$UID" = 0 ]]; then
    err_msg "This script must be run as ROOT"
fi

while getopts i:h option
do
    case "$option" in
        i)
            IFACE=$OPTARG;;
        h|\?)
	    print_usage;;
    esac
done

if [[ -z $IFACE ]]; then
    print_usage
fi

# Sanity checks on the interface given
if ! ifconfig $IFACE > /dev/null 2>&1; then
    err_msg "$IFACE not available... please double check"
fi
if ! ip link show $IFACE | grep UP > /dev/null 2>&1; then
    err_msg "$IFACE not up... please double check"
fi

# Check the driver of the interface
DRIVER=$(ethtool -i $IFACE 2>/dev/null | grep driver | egrep -o "[a-zA-Z0-9_]+$")
if [[ -z $DRIVER ]] || [[ ! -n "${TESTED_DRIVERS[$DRIVER]}" ]]; then
    err_msg "We have not tested on $IFACE (driver: $DRIVER) and not sure how to configure it yet. Consider choosing another?"
fi

# Check the model of the interface
BUS=$(ethtool -i $IFACE 2>/dev/null | grep bus-info | egrep -o "[0-9a-f]+:[0-9a-f]+\.[0-9a-f]+")
MODEL=$(lspci | grep $BUS | sed "s/$BUS //g" | sed "s/Ethernet controller: //g")
if ! tested "$IFACE" "$MODEL"; then
    warn_msg "We have not tested specifically on \"$MODEL\""
    warn_msg "We'll try configuring $IFACE in the way we have done on NICs supported by $DRIVER..."
fi

INTRS=$(intr_pattern $IFACE $DRIVER | xargs -i grep {} /proc/interrupts | wc -l)
CORES=$(grep processor /proc/cpuinfo | wc -l)
TX_QUEUES=$(ls /sys/class/net/$IFACE/queues | grep tx | wc -l)
RX_QUEUES=$(ls /sys/class/net/$IFACE/queues | grep rx | wc -l)
HW_QUEUES=$(hardware_queues $DRIVER $INTRS)

info_msg "Configuring $IFACE..."
info_msg "    Bus info: $BUS"
info_msg "    Model: $MODEL"
info_msg "    Driver: $DRIVER"
info_msg "    Number of..."
info_msg "        CPU cores: $CORES"
info_msg "        software Tx queues: $TX_QUEUES"
info_msg "        software Rx queues: $RX_QUEUES"
info_msg "        hardware queues: $HW_QUEUES"

# Allow 3000 interrupts at most per second
ethtool -C $IFACE rx-usecs 333 > /dev/null 2>&1
info_msg "    Interrupt throttle rate is set to 3000"

# Use XPS to set affinities of Tx queues
# Note: This is only done when we have more Tx queues than cores.
if [[ $TX_QUEUES -ge $CORES ]]; then
    for i in $(seq 0 $((CORES-1))); do
	cpuid_to_mask $((i%CORES)) | xargs -i echo {} > /sys/class/net/$IFACE/queues/tx-$i/xps_cpus
    done
    info_msg "    XPS enabled"
fi

# Enable RPS if number of cores and hardware cores are not equal
if [[ ! $HW_QUEUES == $CORES ]]; then
    for i in /sys/class/net/$IFACE/queues/rx-*; do
	printf "%x\n" $((2**CORES-1)) | xargs -i echo {} > $i/rps_cpus;
    done
    info_msg "    RPS enabled"
else
    for i in /sys/class/net/$IFACE/queues/rx-*; do
	echo 0 > $i/rps_cpus;
    done
    info_msg "    RPS disabled"
fi

# Disable irqbalance
if ps aux | grep irqbalance | grep -v grep; then
    info_msg "Disable irqbalance..."
    # XXX Do we have a more moderate way to do this?
    killall irqbalance > /dev/null 2>&1
fi

# Set interrupt affinities
i=0
intr_list $IFACE $DRIVER | while read irq; do
    cpuid_to_mask $((i%CORES)) | xargs -i echo {} > /proc/irq/$irq/smp_affinity
    i=$((i+1))
done

info_msg "    NIC interrupt affinity is configured."

# Enlarge open file limits
if [ `ulimit -n` -le 1024 ]; then
    warn_msg "Max open file limit is possibly too small for a performance test."
fi

if lsmod | grep iptable > /dev/null 2>&1; then
    warn_msg "Iptables is active and it has a negative impact on network performance. It is recommended to turn it off."
fi	

info_msg "${GREEN}System and $IFACE have been successfully configured for best performance.$NC"
