#!/usr/bin/env python3
import os
import re
import glob
import matplotlib.pyplot as plt
import numpy as np

# Lists to store raw data
delay_values = []  # Lambda values
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

# Calculate mean delay values (1/lambda in milliseconds)
mean_delays = [1000/dv for dv in delay_values]

# Create plot for Mean Delay vs RTT
plt.figure(figsize=(12, 8))

# Plot data points with connected lines
plt.plot(mean_delays, avg_rtts, 'o-', markersize=10, linewidth=2, color='blue')

# Don't clutter x-axis with all ticks
plt.xticks([])  # Remove x-ticks
plt.xlim(min(mean_delays)*0.5, max(mean_delays)*1.5)  # Add more margin

# Add annotations with well-spaced arrows
num_points = len(mean_delays)
for i, (x, y) in enumerate(zip(mean_delays, avg_rtts)):
    # Calculate varied arrow angles and distances
    angle = (i * 40) % 360  # Different angles
    distance = 60 + (i * 10) % 40  # Varied distances
    
    # Calculate offset based on angle
    rad_angle = np.radians(angle)
    dx = distance * np.cos(rad_angle)
    dy = distance * np.sin(rad_angle)
    
    plt.annotate(f"{x:.1f}", 
                xy=(x, y), 
                xytext=(dx, dy), 
                textcoords='offset points',
                arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0.2', color='gray'),
                ha='center', va='center', 
                fontsize=10, 
                bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='gray', alpha=0.8))

# Simple labels, explicitly mentioning the calculation
plt.title("Effect of Random Delay on Round-Trip Time", fontsize=16)
plt.xlabel("Mean Value (1/λ*1000 ms)", fontsize=14)
plt.ylabel("Average RTT (ms)", fontsize=14)

# Set grid
plt.grid(True, linestyle='--', alpha=0.6)

# Save the plot
plt.tight_layout()
plt.savefig("mean_delay_rtt_analysis.png", dpi=300)

# Print data table
print("\nData points:")
print("--------------------------------------")
print("| Lambda (λ) | Mean Delay (ms) | RTT (ms) |")
print("--------------------------------------")
for d, m, r in zip(delay_values, mean_delays, avg_rtts):
    print(f"| {d:9.1f} | {m:14.2f} | {r:7.2f} |")
print("--------------------------------------")

plt.show()