#!/usr/bin/env python3

import argparse
import socket
import time
import os
import sys
import struct
import binascii
import signal
from collections import Counter, deque
from scapy.all import sniff, IP, UDP

parser = argparse.ArgumentParser(description='TOS Covert Channel Receiver')
parser.add_argument('--tos-mapping-bits', type=int, default=3, 
                    help='Number of bits used in TOS field (1-8)')
parser.add_argument('--port', type=int, default=8888, 
                    help='UDP port to listen on')
parser.add_argument('--mode', choices=['live', 'experiment'], default='live',
                    help='Receiver mode: live decoding or experiment measurements')
parser.add_argument('--timeout', type=int, default=60,
                    help='Timeout in seconds to stop if no packets received')
parser.add_argument('--packets-per-symbol', type=int, default=1,
                    help='Expected packets per symbol (for redundancy)')
parser.add_argument('--log-file', type=str, default='tos_covert_receiver.log',
                    help='File to log results to in experiment mode')
parser.add_argument('--simple-coding', action='store_true',
                    help='Use simpler character-based decoding (for reliability)')

args = parser.parse_args()

class TOSCovertReceiver:
    def __init__(self, bits_per_symbol, port, packets_per_symbol=1, simple_coding=False):
        self.bits_per_symbol = bits_per_symbol
        self.port = port
        self.packets_per_symbol = packets_per_symbol
        self.max_value = (1 << bits_per_symbol) - 1
        self.simple_coding = simple_coding
        
        self.start_value = self.max_value - 1 if self.max_value > 1 else 1
        self.end_value = self.max_value if self.max_value > 1 else 0
        
        self.received_tos_values = []
        self.symbol_buffer = []
        self.message_buffer = []
        
        self.packets_received = 0
        self.symbols_received = 0
        self.start_time = None
        self.end_time = None
        self.last_packet_time = None
        self.state = "waiting"
        
        self.current_symbol_count = 0
        
        print(f"TOS Covert Receiver initialized with {bits_per_symbol} bits per symbol")
        print(f"Listening on UDP port {port}")
        print(f"Using {packets_per_symbol} packets per symbol for redundancy")
        print(f"Start marker: {self.start_value}, End marker: {self.end_value}")
        print(f"Simple coding mode: {self.simple_coding}")
    
    def packet_handler(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet[UDP].dport == self.port):
            return
        
        tos_value = packet[IP].tos
        
        print(f"Received packet with TOS: {tos_value}, Source: {packet[IP].src}")
        
        self.packets_received += 1
        current_time = time.time()
        self.last_packet_time = current_time
        
        if self.start_time is None:
            self.start_time = current_time
            
        if self.state == "waiting":
            if tos_value == self.start_value:
                print("Start marker detected, beginning to receive data")
                self.state = "receiving"
                self.received_tos_values = []
            
        elif self.state == "receiving":
            if tos_value == self.end_value:
                self.state = "complete"
                self.end_time = current_time
                self.process_received_data()
                return
                
            self.symbol_buffer.append(tos_value)
            self.current_symbol_count += 1
            
            if self.current_symbol_count >= self.packets_per_symbol:
                if self.packets_per_symbol > 1:
                    most_common_value = Counter(self.symbol_buffer).most_common(1)[0][0]
                    self.received_tos_values.append(most_common_value)
                else:
                    self.received_tos_values.append(tos_value)
                
                self.symbols_received += 1
                self.symbol_buffer = []
                self.current_symbol_count = 0
                
                if self.symbols_received % 10 == 0:
                    print(f"Received {self.symbols_received} symbols so far...")
    
    def decode_binary_to_message(self, tos_values):
        binary_string = ''
        for value in tos_values:
            binary = format(value, f'0{self.bits_per_symbol}b')
            binary_string += binary
        
        print(f"Binary string: {binary_string}")
        
        decoded_message = ''
        for i in range(0, len(binary_string), 8):
            if i + 8 <= len(binary_string):
                byte = binary_string[i:i+8]
                try:
                    char_code = int(byte, 2)
                    decoded_char = chr(char_code)
                    decoded_message += decoded_char
                    print(f"Byte: {byte}, Code: {char_code}, Char: {decoded_char}")
                except ValueError:
                    decoded_message += '?'
                    print(f"Invalid byte: {byte}")
                except Exception as e:
                    decoded_message += '?'
                    print(f"Error processing byte {byte}: {e}")
        
        return decoded_message
    
    def decode_simple_coding(self, tos_values):
        decoded_message = ''
        char_code = 0
        
        for value in tos_values:
            if value == self.start_value:
                continue
                
            if value == self.max_value:
                char_code += value
            else:
                char_code += value
                try:
                    decoded_message += chr(char_code)
                    print(f"Code: {char_code}, Char: {chr(char_code)}")
                except Exception as e:
                    decoded_message += '?'
                    print(f"Error with code {char_code}: {e}")
                char_code = 0
        
        return decoded_message
        
    def process_received_data(self):
        print(f"\nReceived {len(self.received_tos_values)} symbols ({self.packets_received} packets total)")
        
        print(f"Received TOS values: {self.received_tos_values}")
        
        if self.simple_coding:
            decoded_message = self.decode_simple_coding(self.received_tos_values)
        else:
            decoded_message = self.decode_binary_to_message(self.received_tos_values)
        
        print(f"Decoded message: '{decoded_message}'")
        self.message_buffer.append(decoded_message)
        
        transmission_time = self.end_time - self.start_time
        bits_received = len(self.received_tos_values) * self.bits_per_symbol
        capacity = bits_received / transmission_time if transmission_time > 0 else 0
        
        print(f"Transmission time: {transmission_time:.2f} seconds")
        print(f"Bits received: {bits_received}")
        print(f"Channel capacity: {capacity:.2f} bits/second")
        
        self.state = "waiting"
        
        return decoded_message, bits_received, transmission_time, capacity
    
    def start_capturing(self, timeout=60):
        print(f"Starting packet capture on UDP port {self.port} on interface eth0...")
        print(f"Will timeout after {timeout} seconds of inactivity")
        
        def handle_timeout(signum, frame):
            if self.state == "receiving" and self.received_tos_values:
                print("\nTimeout while receiving data, processing available data...")
                self.state = "complete"
                self.end_time = time.time()
                self.process_received_data()
            else:
                print("\nTimeout reached with no data received.")
            
            print("Capture stopped.")
            sys.exit(0)
        
        signal.signal(signal.SIGALRM, handle_timeout)
        signal.alarm(timeout)
        
        try:
            sniff(prn=self.packet_handler, filter=f"udp port {self.port}", iface="eth0", store=0)
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
            if self.state == "receiving" and self.received_tos_values:
                print("Processing available data...")
                self.state = "complete"
                self.end_time = time.time()
                self.process_received_data()

def run_experiment_mode():
    print("Running in experiment mode to collect performance metrics")
    
    log_file = open(args.log_file, 'w')
    log_file.write("bits_per_symbol,packets_per_symbol,packets_received,symbols_received,bits_received,transmission_time,capacity\n")
    
    receiver = TOSCovertReceiver(
        args.tos_mapping_bits, 
        args.port, 
        args.packets_per_symbol,
        args.simple_coding
    )
    
    messages = []
    
    def experiment_packet_handler(packet):
        receiver.packet_handler(packet)
        
        if receiver.state == "complete":
            message, bits, time_taken, capacity = receiver.process_received_data()
            messages.append(message)
            
            log_file.write(f"{args.tos_mapping_bits},{args.packets_per_symbol},"
                          f"{receiver.packets_received},{receiver.symbols_received},"
                          f"{bits},{time_taken:.6f},{capacity:.6f}\n")
            log_file.flush()
            
            receiver.state = "waiting"
    
    try:
        print(f"Starting experiment. Results will be logged to {args.log_file}")
        print("Press Ctrl+C to stop the experiment")
        
        sniff(prn=experiment_packet_handler, filter=f"udp port {args.port}", iface="eth0", store=0)
    
    except KeyboardInterrupt:
        print("\nExperiment stopped by user.")
        log_file.close()
        
        print(f"\nReceived {len(messages)} complete messages")
        if messages:
            print(f"First message: '{messages[0]}'")
            if len(messages) > 1:
                print(f"Last message: '{messages[-1]}'")

def main():
    if args.mode == 'experiment':
        run_experiment_mode()
    else:
        receiver = TOSCovertReceiver(
            args.tos_mapping_bits, 
            args.port, 
            args.packets_per_symbol,
            args.simple_coding
        )
        receiver.start_capturing(args.timeout)

if __name__ == "__main__":
    main()