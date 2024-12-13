import socket
import os
import sys
import struct
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading

# Function to check if the script is running with the necessary privileges (root on Linux/macOS)
def check_privileges():
    if os.name != 'nt':  # For Linux/macOS only
        if os.geteuid() != 0:
            print("[!] This script requires root privileges.")
            sys.exit(1)

# Function to create the TCP SYN packet
def create_syn_packet(target_ip, target_port):
    # IP Header
    ip_header = struct.pack('!BBHHHBBH4s4s', 4, 5, 20, 0, 0, 64, socket.IPPROTO_TCP, 0, socket.inet_aton("0.0.0.0"), socket.inet_aton(target_ip))

    # Pseudo header for checksum calculation
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton("0.0.0.0"), socket.inet_aton(target_ip), 0, socket.IPPROTO_TCP, 20)

    # TCP Header fields
    source_port = random.randint(1024, 65535)
    sequence = 0
    acknowledgment = 0
    offset_res_flags = (5 << 4) + 2  # Data offset (5) and SYN flag (0x02)
    window_size = socket.htons(5840)  # Maximum allowed window size
    checksum = 0  # Will be calculated
    urgent_pointer = 0

    # Packing the TCP header
    tcp_header = struct.pack('!HHLLBBHHH', source_port, target_port, sequence, acknowledgment, offset_res_flags, 255, window_size, checksum, urgent_pointer)

    # Calculate checksum
    checksum = calculate_checksum(pseudo_header + tcp_header)

    # Repack TCP header with correct checksum
    tcp_header = struct.pack('!HHLLBBHHH', source_port, target_port, sequence, acknowledgment, offset_res_flags, 255, window_size, checksum, urgent_pointer)

    # Final packet: IP header + TCP header
    return ip_header + tcp_header

# Function to calculate the checksum for the packet
def calculate_checksum(data):
    checksum = 0
    length = len(data)
    i = 0
    while length > 1:
        checksum += (data[i] << 8) + data[i + 1]
        checksum &= 0xFFFFFFFF
        i += 2
        length -= 2
    if length:
        checksum += data[i]
        checksum &= 0xFFFFFFFF
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

# Function to perform the SYN scan
def syn_scan(target, port, open_ports, closed_ports, filtered_ports, verbose=False):
    try:
        # Create a raw socket (requires root privileges)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(1)

        # Create SYN packet
        packet = create_syn_packet(target, port)

        # Send the SYN packet
        s.sendto(packet, (target, 0))

        # Wait for a response
        response = s.recv(1024)

        # Unpack the response to analyze the flags
        ip_header = response[:20]
        tcp_header = response[20:40]

        # Unpack IP header
        ip = struct.unpack('!BBHHHBBH4s4s', ip_header)
        source_ip = socket.inet_ntoa(ip[8])

        # Unpack TCP header
        tcp = struct.unpack('!HHLLBBHHH', tcp_header)
        response_flags = tcp[5]

        # Check if SYN-ACK (open port) or RST (closed port)
        if response_flags == 18:  # SYN-ACK
            open_ports.append(port)
            print(f"[+] Port {port} is open")
        elif response_flags == 4:  # RST (closed port)
            closed_ports.append(port)
            print(f"[-] Port {port} is closed")
        else:
            filtered_ports.append(port)
            print(f"[?] Port {port} is filtered or no response")

        s.close()

    except socket.timeout:
        filtered_ports.append(port)
        print(f"[?] Port {port} is filtered (timeout)")

    except Exception as e:
        filtered_ports.append(port)
        print(f"[?] Error scanning port {port}: {e}")

# Function to scan multiple ports concurrently
def scan_ports(target, start_port, end_port, output_file, verbose=False):
    print(f"\nScanning target: {target}")
    print(f"Scanning ports {start_port} to {end_port}...\n")
    print("-" * 50)

    # Record start time
    start_time = datetime.now()

    open_ports = []
    closed_ports = []
    filtered_ports = []

    # Use ThreadPoolExecutor to scan multiple ports concurrently
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(syn_scan, target, port, open_ports, closed_ports, filtered_ports, verbose)

    # Record end time
    end_time = datetime.now()

    # Output summary statistics
    print("\nScan completed in:", end_time - start_time)
    print(f"Total Open Ports: {len(open_ports)}")
    print(f"Total Closed Ports: {len(closed_ports)}")
    print(f"Total Filtered Ports: {len(filtered_ports)}")
    print("-" * 50)

    # Save results to file (if output_file is provided)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(f"Scan completed on {datetime.now()}\n")
            f.write(f"Target: {target}\n")
            f.write(f"Ports scanned: {start_port} to {end_port}\n\n")
            f.write("Open Ports:\n")
            for port in open_ports:
                f.write(f"{port}\n")
            f.write("\nClosed Ports:\n")
            for port in closed_ports:
                f.write(f"{port}\n")
            f.write("\nFiltered Ports:\n")
            for port in filtered_ports:
                f.write(f"{port}\n")
            f.write("\nScan completed in: " + str(end_time - start_time) + "\n")

            print(f"\nResults saved to {output_file}")

    print("-" * 50)

# Function to validate target
def validate_target(target):
    try:
        # Check if the target is a valid IP address or hostname
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        print(f"[-] Invalid target address: {target}")
        return False

def get_input(prompt, default=None, type_func=str):
    """Helper function to handle user input and ensure proper validation"""
    user_input = input(prompt + (f" (default: {default}): " if default else ": "))
    if not user_input and default is not None:
        return default
    try:
        return type_func(user_input)
    except ValueError:
        print(f"[!] Invalid input. Expected {type_func.__name__}.")
        return get_input(prompt, default, type_func)

if __name__ == "__main__":
    # Check for root/admin privileges (Linux/macOS only)
    check_privileges()

    # Interactive Input
    print("Welcome to the SYN Port Scanner!")
    target = get_input("Enter target IP address or domain")
    if not validate_target(target):
        exit(1)

    start_port = get_input("Enter starting port", default=1, type_func=int)
    end_port = get_input("Enter ending port", default=10000, type_func=int)  # Default set to 10000
    save_results = get_input("Do you want to save results to a file? (y/n)", default="n").lower() == "y"
    verbose = get_input("Do you want verbose output? (y/n)", default="n").lower() == "y"

    output_file = None
    if save_results:
        output_file = get_input("Enter the output filename", default="scan_results.txt")

    # Start scanning
    scan_ports(target, start_port, end_port, output_file, verbose)
