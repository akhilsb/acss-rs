#!/usr/bin/env python3
import sys
import re

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <log_filename>")
    sys.exit(1)

filename = sys.argv[1]

consensus_time = None
avid_time = None

# Regex patterns to capture the time values after the colon
pattern_consensus = re.compile(r"Consensus Start time:\s*(.+)")
pattern_avid = re.compile(r"Received request to disperse message through AVID at time:\s*(.+)")

with open(filename, 'r') as f:
    for line in f:
        # Look for consensus time
        match_c = pattern_consensus.search(line)
        if match_c:
            consensus_time = match_c.group(1).strip()

        # Look for AVID time
        match_a = pattern_avid.search(line)
        if match_a:
            avid_time = match_a.group(1).strip()

# Ensure both timestamps were found
if consensus_time is None:
    print("Error: Consensus Start time not found in file.")
    sys.exit(1)

if avid_time is None:
    print("Error: AVID request time not found in file.")
    sys.exit(1)

# Convert to float if numeric, otherwise just print both
try:
    time_x = float(consensus_time)
    time_y = float(avid_time)
    diff = time_y - time_x
    print(f"Difference = {diff}")
except ValueError:
    print("Extracted values are not numeric.")
    print(f"Consensus Start time: {consensus_time}")
    print(f"AVID Request time: {avid_time}")

