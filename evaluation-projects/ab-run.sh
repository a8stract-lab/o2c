#!/bin/bash

# Check if an argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <argument>"
  exit 1
fi

# Create the ab-res directory if it doesn't exist
mkdir -p ab-res

# Loop to execute the commands 20 times
for i in {1..20}; do
  ab -n 1000 -c 10 "http://[::1]:8000/100kb.test" >> "ab-res/1005-$1-100kb-c10.txt"
  ab -n 1000 -c 100 "http://[::1]:8000/100kb.test" >> "ab-res/1005-$1-100kb-c100.txt"
  ab -n 1000 -c 10 "http://[::1]:8000/1mb.test" >> "ab-res/1005-$1-1mb-c10.txt"
  ab -n 1000 -c 100 "http://[::1]:8000/1mb.test" >> "ab-res/1005-$1-1mb-c100.txt"
  ab -n 1000 -c 10 "http://[::1]:8000/10mb.test" >> "ab-res/1005-$1-10mb-c10.txt"
  ab -n 1000 -c 100 "http://[::1]:8000/10mb.test" >> "ab-res/1005-$1-10mb-c100.txt"
done