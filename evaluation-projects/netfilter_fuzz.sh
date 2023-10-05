#!/bin/bash

nft list ruleset > ./saved_ruleset.nft

# Step 2: Fuzzing Test
# Initialize Tables and Base Chains for Fuzzing
nft add table ip fuzz_table
nft add chain ip fuzz_table fuzz_input { type filter hook input priority 0 \; }
nft add chain ip fuzz_table fuzz_output { type filter hook output priority 0 \; }
nft add chain ip fuzz_table fuzz_forward { type filter hook forward priority 0 \; }

for i in $(seq 1 20); do
# Fuzzing Commands (200 commands)
for i in {1..50}; do
  nft add rule ip fuzz_table fuzz_input ip saddr 192.168.99.$i drop
  nft add rule ip fuzz_table fuzz_input tcp dport 10$i drop
  nft add rule ip fuzz_table fuzz_output ip daddr 192.168.99.$((i+50)) accept
  nft add rule ip fuzz_table fuzz_output udp sport 20$i accept
done

# Additional Fuzzing Commands to Cover More Functionalities
nft add rule ip fuzz_table fuzz_input ct state new,established accept
nft add rule ip fuzz_table fuzz_output ct state new,established drop
nft add rule ip fuzz_table fuzz_forward ct state invalid drop
nft add rule ip fuzz_table fuzz_input ip tos 0x10 drop
nft add rule ip fuzz_table fuzz_output ip tos 0x08 accept
nft add rule ip fuzz_table fuzz_forward ip tos 0x04 drop
nft add rule ip fuzz_table fuzz_input ip frag-off 0x4000 drop
nft add rule ip fuzz_table fuzz_output ip frag-off 0x2000 accept
nft add rule ip fuzz_table fuzz_forward ip frag-off 0x1000 drop
nft add rule ip fuzz_table fuzz_input ip id 1000 drop
nft add rule ip fuzz_table fuzz_output ip id 2000 accept
nft add rule ip fuzz_table fuzz_forward ip id 3000 drop


nft add chain ip fuzz_table input { type filter hook input priority 0 \; }
nft add chain ip fuzz_table output { type filter hook output priority 0 \; }
nft add chain ip fuzz_table forward { type filter hook forward priority 0 \; }

# Input Chain Rules
nft add rule ip fuzz_table input ip saddr 192.168.99.1 drop
nft add rule ip fuzz_table input ip daddr 192.168.99.2 accept
nft add rule ip fuzz_table input ip protocol icmp drop
nft add rule ip fuzz_table input tcp dport 12345 drop
nft add rule ip fuzz_table input tcp sport 54321 accept
nft add rule ip fuzz_table input udp dport 12346 drop
nft add rule ip fuzz_table input udp sport 54322 accept
nft add rule ip fuzz_table input meta iifname "eth99" drop
nft add rule ip fuzz_table input meta oifname "eth99" accept
nft add rule ip fuzz_table input ip ttl 64 drop

# Output Chain Rules
nft add rule ip fuzz_table output ip saddr 192.168.99.3 drop
nft add rule ip fuzz_table output ip daddr 192.168.99.4 accept
nft add rule ip fuzz_table output ip protocol igmp drop
nft add rule ip fuzz_table output tcp dport 12347 drop
nft add rule ip fuzz_table output tcp sport 54323 accept
nft add rule ip fuzz_table output udp dport 12348 drop
nft add rule ip fuzz_table output udp sport 54324 accept
nft add rule ip fuzz_table output meta iifname "eth99" drop
nft add rule ip fuzz_table output meta oifname "eth99" accept
nft add rule ip fuzz_table output ip ttl 63 drop

# Forward Chain Rules
nft add rule ip fuzz_table forward ip saddr 192.168.99.5 drop
nft add rule ip fuzz_table forward ip daddr 192.168.99.6 accept
nft add rule ip fuzz_table forward ip protocol tcp drop
nft add rule ip fuzz_table forward tcp dport 12349 drop
nft add rule ip fuzz_table forward tcp sport 54325 accept
nft add rule ip fuzz_table forward udp dport 12350 drop
nft add rule ip fuzz_table forward udp sport 54326 accept
nft add rule ip fuzz_table forward meta iifname "eth99" drop
nft add rule ip fuzz_table forward meta oifname "eth99" accept
nft add rule ip fuzz_table forward ip ttl 62 drop

# Additional Rules to Cover More Functionalities
nft add rule ip fuzz_table input ct state new,established accept
nft add rule ip fuzz_table output ct state new,established drop
nft add rule ip fuzz_table forward ct state invalid drop
nft add rule ip fuzz_table input ip tos 0x10 drop
nft add rule ip fuzz_table output ip tos 0x08 accept
nft add rule ip fuzz_table forward ip tos 0x04 drop
nft add rule ip fuzz_table input ip frag-off 0x4000 drop
nft add rule ip fuzz_table output ip frag-off 0x2000 accept
nft add rule ip fuzz_table forward ip frag-off 0x1000 drop
nft add rule ip fuzz_table input ip id 1000 drop
nft add rule ip fuzz_table output ip id 2000 accept
nft add rule ip fuzz_table forward ip id 3000 drop
nft add rule ip fuzz_table input ip length 100 drop
nft add rule ip fuzz_table output ip length 200 accept
nft add rule ip fuzz_table forward ip length 300 drop
nft add rule ip fuzz_table input ip version 4 drop
nft add rule ip fuzz_table output ip version 4 accept
nft add rule ip fuzz_table forward ip version 4 drop
nft add rule ip fuzz_table input icmp type echo-request drop
nft add rule ip fuzz_table output icmp type echo-reply accept
nft add rule ip fuzz_table forward icmp type destination-unreachable drop
done
# Step 3: Remove Fuzzing Rules
nft delete table ip fuzz_table

nft flush ruleset

# Step 4: Recover Saved Netfilter Rules
nft -f ./saved_ruleset.nft