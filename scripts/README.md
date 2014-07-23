 README for FASTSOCKET System Configuration Script
========================================================================

## TABLE OF CONTENT ##
* [Introduction](#introduction)
* [Configurations Involved](#configurations-involved)
  * [Interrupt Affinity](#interrupt-affinity)
  * [Interrupt Throttle Rate](#interrupt-throttle-rate)
  * [RPS](#rps)
  * [XPS](#xps)
  * [Iptables](#iptables)

## INTRODUCTION ##

The script (nic.sh) takes charge of most configuration work to maximize the
benefits of Fastsocket. Given a specific network interface, it adjusts various
features of the interface as well as a few system-wide configurations.

## CONFIGURATIONS INVOLVED ##

### INTERRUPT AFFINITY ###

Each NIC hardware queue and its associating interrupt is bound to a different
CPU core. If there are more NIC hardware queues than CPU cores, then the queues 
are configured in a round-robin way. Irqbalance service is disabled to prevent it 
from changing the configuration afterwords.

### INTERRUPT THROTTLE RATE ###

To avoid interrupt storm, nic.sh limits the maximum number of interrupts allowed
per second via ethtool coalesce option. The interval of two Rx interrupts is
forced to be at least 333us (i.e. ~3000 interrupts per second at most).

### RPS ###

It is desirable to map each CPU core with a different NIC hardware queue since this way 
all CPU cores can be evenly utilized to process network packets. However, when the number 
of hardware queues is less than CPU cores, nic.sh use a software method, that is 
RPS (Receive Packet Steering), to steer incoming loads to these CPU cores that 
do not have an associating hardware queue. In this case, RPS is configured as such that 
upon receiving a packet, the receiving CPU core can steer the packet to any of the CPU 
cores available. 

### XPS ###

XPS (Transmit Packet Steering) in Linux manages a mapping from CPU cores to 
Tx queues and steers outgoing packets accordingly. On a machine with N cores, 
nic.sh configures XPS when there are at least N Tx queues on the interface, and
establishes a 1-1 map between the first N Tx queues and the CPU cores available.

### IPTABLES ###

During stress tests, iptables rules would consume much CPU cycles, leading to 
poor network stack performance. Therefore, nic.sh would print a warming message 
if it notices that iptable is active.
