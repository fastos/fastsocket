 README for FASTSOCKET System Configuration Script
========================================================================

## TABLE OF CONTENT ##
* [Introduction](#introduction)
* [Configurations Involved](#configurations-involved)
  * [Interrupt Throttle Rate](#interrupt-throttle-rate)
  * [XPS](#XPS)
  * [RPS](#RPS)
  * [Interrupt Affinity](#interrupt-affinity)
  * [nf_conntrack](#nf_conntrack)

## INTRODUCTION ##

The script (nic.sh) takes charge of most configuration work to maximize the
benefits of Fastsocket. Given a specific network interface, it adjusts various
features of the interface as well as a few system-wide configurations.

## CONFIGURATIONS INVOLVED ##

### INTERRUPT THROTTLE RATE ###

To avoid interrupt storm, nic.sh limits the maximum number of interrupts allowed
per second via ethtool coalesce options. The interval of two Rx interrupts is
forced to be at least 333us (i.e. ~3000 interrupts per second at most).

### XPS ###

XPS (Transmit Packet Steering) in Linux manages a mapping from CPUs to Tx queues
and steers outgoing packets accordingly. On a machine with N cores, nic.sh
configures XPS when there are at least N Tx queues on the interface, and
establishes a 1-1 map between the first N Tx queues and cores available.

### RPS ###

When configured, RPS (Receive Packet Steering) determines what CPU will handle
each incoming packet by hashing the packet header. When the number of hardware
Rx queues (guessed from number of interrupts) and cores are not equal, nic.sh
enables RPS to balance incoming loads. Each Rx queue is allowed to steer a
packet to any of the cores available.

### INTERRUPT AFFINITY ###

Interrupts of the given interfaces are bound to a single core in a round-robin
way, and IRQ balance service is disabled to prevent it from changing the
configuration afterwords.

### NF_CONNTRACK ###

During stress tests, the connection tracking table is likely to be completed
filled, leading to errors like the following.

    nf_conntrack: table full, dropping packet.

Nic.sh workarounds this issue by disabling this feature via iptables.
