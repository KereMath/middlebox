#!/usr/bin/env python3
import os
import re
import glob
import matplotlib.pyplot as plt
import numpy as np

# Lists to store raw data
delay_values = []
avg_rtts = []

# Process all text files
for filename in glob.glob("*.txt"):
    try:
        # Extract exact value from filename
        delay_value = float(filename.split('.')[0])
        
        with open(filename, 'r') as f:
            content = f.read()
            
            # Extract average RTT
            rtt_match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', content)
            
            if rtt_match:
                avg_rtt = float(rtt_match.group(2))
                
                # Store the raw values
                delay_values.append(delay_value)
                avg_rtts.append(avg_rtt)
    except:
        print(f"Skipping file: {filename}")

# Sort data points by delay value
combined = sorted(zip(delay_values, avg_rtts))
delay_values, avg_rtts = zip(*combined)

# Create simple plot
plt.figure(figsize=(10, 6))

# Plot data points with connected lines
plt.plot(delay_values, avg_rtts, 'o-', markersize=8, linewidth=2)

# Add labels
plt.title("Effect of Random Delay on Round-Trip Time", fontsize=16)
plt.xlabel("Delay Value (λ)", fontsize=14)
plt.ylabel("Average RTT (ms)", fontsize=14)

# Add grid
plt.grid(True, linestyle='--', alpha=0.6)

# Save and show
plt.tight_layout()
plt.savefig("delay_analysis.png", dpi=300)
print("Plot saved as 'delay_analysis.png'")

# Print data for verification
print("\nData points:")
for d, r in zip(delay_values, avg_rtts):
    print(f"Delay: {d}, RTT: {r:.2f} ms")

plt.show()