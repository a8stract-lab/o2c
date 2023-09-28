# evaluation


## ipv6

```
python -m http.server --bind ::1  8000

ab -n 100 -c 10 http://[::1]:8000/

curl -6 http://[::1]:8000/


# create test files 100kb 1mb 10mb
dd if=/dev/zero of=100kb.test bs=100KB count=1
dd if=/dev/zero of=1mb.test bs=1MB count=1
dd if=/dev/zero of=10mb.test bs=10MB count=1


ab -n 100 -c 10 http://[::1]:8000/100kb.test
ab -n 100 -c 10 http://[::1]:8000/1mb.test
ab -n 100 -c 10 http://[::1]:8000/10mb.test


for i in $(seq 1 100); do
  ab -n 100 -c 10 http://[::1]:8000/100kb.test
  ab -n 100 -c 10 http://[::1]:8000/1mb.test
  ab -n 100 -c 10 http://[::1]:8000/10mb.test
done
```

## netfilter

all commands needs `sudo`

```c
nft list ruleset > /path/to/saved_ruleset.nft

# Step 2: Fuzzing Test
# Initialize Tables and Base Chains for Fuzzing
nft add table ip fuzz_table
nft add chain ip fuzz_table fuzz_input { type filter hook input priority 0 \; }
nft add chain ip fuzz_table fuzz_output { type filter hook output priority 0 \; }
nft add chain ip fuzz_table fuzz_forward { type filter hook forward priority 0 \; }

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

# Step 3: Remove Fuzzing Rules
nft delete table ip fuzz_table

# Step 4: Recover Saved Netfilter Rules
nft -f /path/to/saved_ruleset.nft
```