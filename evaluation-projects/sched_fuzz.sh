#!/bin/bash
# for i in {1..100}; do
# Step 1: Save current tc rules and ip routes
tc qdisc show dev enp109s0 > ./saved_tc_rules.txt
ip route show > ./saved_ip_routes.txt

# Step 2: Fuzzing Test
IFACE="enp109s0"  # Replace with your actual network interface
tc qdisc add dev $IFACE root handle 1: htb default 10 || echo "Root qdisc already exists, continuing..."
tc class add dev $IFACE parent 1: classid 1:1 htb rate 100mbit

# Fuzzing Commands (200 commands)
for i in {1..250}; do
  tc class add dev $IFACE parent 1:1 classid 1:1$i htb rate ${i}mbit ceil ${i}mbit prio $i
  tc filter add dev $IFACE parent 1: protocol ip prio $i u32 match ip src 192.168.99.$i/32 flowid 1:1$i
  tc filter add dev $IFACE parent 1: protocol ip prio $i u32 match ip dst 192.168.99.$((i+50))/32 flowid 1:1$i
  tc filter add dev $IFACE parent 1: protocol ip prio $i u32 match ip protocol 1 0xff flowid 1:1$i  # ICMP
done

# Step 3: Remove Fuzzing Rules
for i in {1..250}; do
  tc filter del dev $IFACE parent 1: prio $i
  tc class del dev $IFACE parent 1:1 classid 1:1$i
done
tc qdisc del dev $IFACE root

# Step 4: Recover Saved tc Rules and ip routes
while IFS= read -r line; do
  if [[ -n "$line" && ! "$line" =~ "noqueue" && ! "$line" =~ "backlog" && ! "$line" =~ "Sent" ]]; then
    tc $line || echo "Failed to execute: tc $line"
  fi
done < ./saved_tc_rules.txt

while IFS= read -r line; do
  if [[ -n "$line" ]]; then
    ip route add $line || echo "Failed to add route: $line"
  fi
done < ./saved_ip_routes.txt
# done
