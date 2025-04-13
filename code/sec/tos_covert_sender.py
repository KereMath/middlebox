#!/usr/bin/env python3

import argparse
import socket
import time
import os
import sys
import random
import struct
import binascii
from scapy.all import IP, UDP, Raw, send

parser = argparse.ArgumentParser(description='TOS Covert Channel Sender')
parser.add_argument('--message', type=str, default='CENG435 TOS COVERT CHANNEL',
                    help='Message to transmit covertly')
parser.add_argument('--tos-mapping-bits', type=int, default=3, 
                    help='Number of bits to use in TOS field (1-8)')
parser.add_argument('--interval', type=float, default=0.1, 
                    help='Time interval between packets (seconds)')
parser.add_argument('--target-ip', type=str, 
                    default=os.getenv('INSECURENET_HOST_IP', '10.0.0.15'),
                    help='Target IP address')
parser.add_argument('--port', type=int, default=8888, 
                    help='UDP port to use')
parser.add_argument('--packets-per-symbol', type=int, default=1,
                    help='Number of packets per symbol for redundancy')
parser.add_argument('--repeat-message', type=int, default=1,
                    help='Number of times to repeat the message')
parser.add_argument('--experiment-mode', action='store_true',
                    help='Run in experiment mode with multiple configurations')
parser.add_argument('--simple-coding', action='store_true',
                    help='Use simpler character-based coding (for reliability)')

args = parser.parse_args()

def string_to_binary(message, bits_per_symbol):
    binary = ''.join(format(ord(char), '08b') for char in message)
    
    print(f"Binary representation: {binary}")
    
    if len(binary) % bits_per_symbol != 0:
        padding = bits_per_symbol - (len(binary) % bits_per_symbol)
        binary += '0' * padding
        print(f"Added {padding} bits of padding")
    
    symbols = [binary[i:i+bits_per_symbol] for i in range(0, len(binary), bits_per_symbol)]
    print(f"Binary chunks: {symbols}")
    
    return [int(symbol, 2) for symbol in symbols]

def string_to_simple_symbols(message, max_value):
    symbols = []
    for char in message:
        char_code = ord(char)
        if char_code > max_value:
            num_symbols = (char_code // max_value) + (1 if char_code % max_value > 0 else 0)
            
            remainder = char_code % max_value
            
            for _ in range(num_symbols - 1):
                symbols.append(max_value)
            
            symbols.append(remainder if remainder > 0 else max_value)
        else:
            symbols.append(char_code)
    
    print(f"Character codes: {[ord(c) for c in message]}")
    print(f"Symbols: {symbols}")
    return symbols

def send_message(message, bits_per_symbol, interval, target_ip, port, packets_per_symbol, start_marker=True, end_marker=True, simple_coding=False):
    max_value = (1 << bits_per_symbol) - 1
    
    if simple_coding:
        message_values = string_to_simple_symbols(message, max_value)
    else:
        message_values = string_to_binary(message, bits_per_symbol)
    
    print(f"Sending message: '{message}'")
    print(f"Using {bits_per_symbol} bits per symbol (max value: {max_value})")
    print(f"Message converted to {len(message_values)} symbols: {message_values}")
    
    start_value = max_value - 1 if max_value > 1 else 1
    end_value = max_value if max_value > 1 else 0
    
    start_time = time.time()
    total_packets = 0
    
    if start_marker:
        for _ in range(packets_per_symbol * 3):
            packet = IP(dst=target_ip, tos=start_value)/UDP(dport=port, sport=random.randint(1024, 65535))/Raw(load="START")
            send(packet, verbose=0)
            total_packets += 1
            time.sleep(interval)
    
    for value in message_values:
        tos_value = value & max_value
        
        for _ in range(packets_per_symbol):
            packet = IP(dst=target_ip, tos=tos_value)/UDP(dport=port, sport=random.randint(1024, 65535))/Raw(load="DATA")
            send(packet, verbose=0)
            total_packets += 1
            time.sleep(interval)
    
    if end_marker:
        for _ in range(packets_per_symbol * 3):
            packet = IP(dst=target_ip, tos=end_value)/UDP(dport=port, sport=random.randint(1024, 65535))/Raw(load="END")
            send(packet, verbose=0)
            total_packets += 1
            time.sleep(interval)
    
    end_time = time.time()
    time_taken = end_time - start_time
    
    return time_taken, len(message_values), total_packets

def calculate_capacity(bits_per_symbol, time_taken, symbols_sent):
    if time_taken <= 0:
        return 0
    return (symbols_sent * bits_per_symbol) / time_taken

def run_experiment():
    results = []
    
    bit_configs = [1, 2, 3, 4, 6, 8]
    interval_configs = [0.01, 0.05, 0.1, 0.2]
    redundancy_configs = [1, 2, 3]
    
    print("Running experiments with different configurations...")
    
    for bits in bit_configs:
        for interval in interval_configs:
            for redundancy in redundancy_configs:
                iteration_results = []
                for iteration in range(3):
                    print(f"\nExperiment: bits={bits}, interval={interval}s, redundancy={redundancy}, iteration={iteration+1}")
                    
                    time_taken, symbols_sent, packets_sent = send_message(
                        args.message, bits, interval, args.target_ip, args.port, 
                        redundancy, start_marker=True, end_marker=True,
                        simple_coding=args.simple_coding
                    )
                    
                    capacity = calculate_capacity(bits, time_taken, symbols_sent)
                    theoretical_capacity = bits / interval / redundancy
                    
                    result = {
                        'bits': bits,
                        'interval': interval,
                        'redundancy': redundancy,
                        'time_taken': time_taken,
                        'symbols_sent': symbols_sent,
                        'packets_sent': packets_sent,
                        'capacity_bps': capacity,
                        'theoretical_capacity_bps': theoretical_capacity,
                        'efficiency': capacity / theoretical_capacity if theoretical_capacity > 0 else 0
                    }
                    
                    iteration_results.append(result)
                    print(f"Sent {symbols_sent} symbols ({packets_sent} packets) in {time_taken:.2f}s")
                    print(f"Capacity: {capacity:.2f} bits/second")
                    print(f"Theoretical max: {theoretical_capacity:.2f} bits/second")
                    print(f"Efficiency: {(capacity / theoretical_capacity * 100):.2f}% of theoretical")
                    
                    time.sleep(1)
                
                avg_result = {
                    'bits': bits,
                    'interval': interval, 
                    'redundancy': redundancy,
                    'avg_time': sum(r['time_taken'] for r in iteration_results) / len(iteration_results),
                    'avg_capacity': sum(r['capacity_bps'] for r in iteration_results) / len(iteration_results),
                    'avg_efficiency': sum(r['efficiency'] for r in iteration_results) / len(iteration_results)
                }
                
                results.append(avg_result)
                
                print(f"\nAverage for bits={bits}, interval={interval}s, redundancy={redundancy}:")
                print(f"Capacity: {avg_result['avg_capacity']:.2f} bits/second")
                print(f"Efficiency: {avg_result['avg_efficiency'] * 100:.2f}%")
    
    results.sort(key=lambda x: x['avg_capacity'], reverse=True)
    
    print("\nTop 5 configurations by capacity:")
    for i, result in enumerate(results[:5]):
        print(f"{i+1}. Bits: {result['bits']}, Interval: {result['interval']}s, Redundancy: {result['redundancy']}")
        print(f"   Capacity: {result['avg_capacity']:.2f} bits/second, Efficiency: {result['avg_efficiency'] * 100:.2f}%")

def main():
    if args.experiment_mode:
        run_experiment()
        return
    
    if args.tos_mapping_bits < 1 or args.tos_mapping_bits > 8:
        print("Error: tos-mapping-bits must be between 1 and 8")
        sys.exit(1)
    
    total_time = 0
    total_symbols = 0
    total_packets = 0
    
    for i in range(args.repeat_message):
        print(f"\nSending message iteration {i+1}/{args.repeat_message}")
        time_taken, symbols_sent, packets_sent = send_message(
            args.message, args.tos_mapping_bits, args.interval, 
            args.target_ip, args.port, args.packets_per_symbol,
            simple_coding=args.simple_coding
        )
        
        total_time += time_taken
        total_symbols += symbols_sent
        total_packets += packets_sent
        
        bits_sent = symbols_sent * args.tos_mapping_bits
        capacity = calculate_capacity(args.tos_mapping_bits, time_taken, symbols_sent)
        
        print(f"Sent {symbols_sent} symbols ({bits_sent} bits) in {time_taken:.2f} seconds")
        print(f"Used {packets_sent} packets total ({args.packets_per_symbol} per symbol)")
        print(f"Channel capacity: {capacity:.2f} bits/second")
        
        if i < args.repeat_message - 1:  
            time.sleep(1)
    
    if args.repeat_message > 1:
        avg_capacity = calculate_capacity(args.tos_mapping_bits, total_time, total_symbols)
        print(f"\nOverall statistics for {args.repeat_message} iterations:")
        print(f"Total symbols: {total_symbols}, Total packets: {total_packets}")
        print(f"Total time: {total_time:.2f} seconds")
        print(f"Average capacity: {avg_capacity:.2f} bits/second")

if __name__ == "__main__":
    main()