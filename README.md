import requests
from bs4 import BeautifulSoup
import pandas as pd
import re
import os
import csv
import random
import subprocess
import socket
from datetime import datetime
from colorama import Fore, Style
from scapy.all import *
import concurrent.futures

import time
import os

def loading():
    # Get terminal width
    terminal_width = os.get_terminal_size().columns
    print("\n\n\n\n\n\n\n\n")
    # Adjust banner to be centered
    banner = """
  _                    _ _                   
 | |    ___   __ _  __| (_)_ __   __ _       
 | |   / _ \ / _` |/ _` | | '_ \ / _` |      
 | |__| (_) | (_| | (_| | | | | | (_| |_ _ _ 
 |_____\___/ \__,_|\__,_|_|_| |_|\__, (_|_|_)
                                 |___/       
    """
    banner_lines = banner.strip().split('\n')
    centered_banner = '\n'.join([(terminal_width - len(line)) // 2 * ' ' + line for line in banner_lines])

    # Print empty lines for spacing
    spacing_lines = os.get_terminal_size().lines // 4
    print("\n" * spacing_lines)

    print("")
    print(centered_banner)
    
    bar_length = 45
    start_time = time.time()
    for i in range(101):
        num_blocks = int(i / (100 / bar_length))
        bar = '[' + '■' * num_blocks + '' * (bar_length - num_blocks) + ']'
        print(f"\t\r{bar} {i}%", end='', flush=True)
        # Pause at specific percentages
        if i == 20 or i == 70 or i == 99:
            time.sleep(3)
        else:
            # Adjust delay for the rest of the loading time
            elapsed_time = time.time() - start_time
            if elapsed_time < 3:
                time.sleep(3 / 100)  # Adjusting delay dynamically
            else:
                time.sleep(0.03)  # Remainder of the time at normal speed
    print("\r" + " " * (bar_length + 10), end='', flush=True)  # Clear loading bar
    print("\r Permission Granted!")  # Move to the next line
    clear_terminal()
    
    


def display_banner():
    version = "5.0"
    banner = """
 __    __ _                  _ 
/ / /\ \ (_)______ _ _ __ __| |
\ \/  \/ / |_  / _` | '__/ _` |
 \  /\  /| |/ / (_| | | | (_| |
  \/  \/ |_/___\__,_|_|  \__,_|
                               
    """
    print("\033[1m\033[95m" + banner)
    print("\033[1m\033[93mURL Extractor and Vulnerability Scanner\033[0m")
    print("\033[1mAuthor:\033[0m Philip Angwe")
    print("\033[1mVersion:\033[0m V" + version + "\n")

def rotate_proxy(proxy_list):
    return random.choice(proxy_list) if proxy_list else None

def crack_wifi_password(interface, channel, ssid_filter, password_file):
    # Placeholder for cracking WiFi password
    pass

def clear_terminal():
    """Clear the terminal."""
    os.system('cls' if os.name == 'nt' else 'clear')

def extract_website_info():
    clear_terminal()
    # Display the banner
    display_bannerer
    
    # Password verification
    password = input("Enter the admin password: ")
    if password != "admin":
        print("Incorrect password. Check 'admin.txt' for the correct password.")
        return

    # Prompt user for website and options
    website_name = input("Enter the website name (without 'https://www.'): ")
    keyword = input("Enter the keyword to search for: ")
    num_pages = int(input("Enter the number of pages to search (1 or more): "))
    tag_filter = input("Enter HTML tag to filter (optional, leave empty for all tags): ")
    save_to_csv = input("Save extracted data to CSV? (y/n): ").lower() == 'y'
    custom_output_dir = input("Enter custom output directory (leave empty for default): ").strip()
    timeout = int(input("Enter timeout for HTTP requests (in seconds): "))
    regex_search = input("Use regex search? (y/n): ").lower() == 'y'
    case_sensitive = input("Perform case-sensitive search? (y/n): ").lower() == 'y'
    whole_word = input("Search for whole words only? (y/n): ").lower() == 'y'
    proxy = input("Enter proxy server (optional, leave empty for none): ").strip()

    # Construct the full website URL
    website_url = f"https://www.{website_name}"

    # Create a directory to store extracted dataoutput_directory = custom_output_dir if custom_output_dir else "extracted_data"
    os.makedirs(output_directory, exist_ok=True)

    # Open a text file for writing extracted information
    output_file_path = os.path.join(output_directory, "extracted.txt")
    with open(output_file_path, 'w') as output_file:
        for page_num in range(1, num_pages + 1):
            page_url = f"{website_url}?page={page_num}" if page_num > 1 else website_url
            # Send a GET request to the URL
            session = requests.Session()
            proxies = {'http': proxy, 'https': proxy} if proxy else None
            response = session.get(page_url, headers={'User-Agent': 'URLExtractorBot/1.0'}, timeout=timeout, proxies=proxies)

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse the HTML content of the page
                soup = BeautifulSoup(response.content, 'html.parser')

                # Find all paragraphs on the page or filtered tag
                paragraphs = soup.find_all(tag_filter) if tag_filter else soup.find_all(['p', 'div', 'span'])

                # Extract data from each paragraph
                for i, paragraph in enumerate(paragraphs, 1):
                    # Perform regex search if enabled
                    if regex_search:
                        pattern = keyword if case_sensitive else keyword.lower()
                        if whole_word:
                            pattern = fr'\b{re.escape(pattern)}\b'
                        if re.search(pattern, paragraph.get_text(), flags=(0 if case_sensitive else re.IGNORECASE)):
                            # Write the paragraph to the output file
                            output_file.write(f"Page {page_num}, Paragraph {i}:\n{paragraph.get_text()}\n{'='*50}\n")
                            print(f"Page {page_num}, Paragraph {i}:\n{paragraph.get_text()}\n{'='*50}\n")
                    else:
                        # Check if the keyword is present in the paragraph
                        pattern = keyword if case_sensitive else keyword.lower()
                        if whole_word:
                            pattern = fr'\b{re.escape(pattern)}\b'
                        if re.search(pattern, paragraph.get_text(), flags=(0 if case_sensitive elsere.IGNORECASE)):
                            # Write the paragraph to the output file
                            output_file.write(f"Page {page_num}, Paragraph {i}:\n{paragraph.get_text()}\n{'='*50}\n")
                            print(f"Page {page_num}, Paragraph {i}:\n{paragraph.get_text()}\n{'='*50}\n")

                if save_to_csv:
                    # Save extracted data to CSV file
                    csv_file_path = os.path.join(output_directory, "extracted.csv")
                    with open(csv_file_path, 'a', newline='') as csv_file:
                        writer = csv.writer(csv_file)
                        for paragraph in paragraphs:
                            writer.writerow([paragraph.get_text(), page_url])

            else:
                print(f"Failed to retrieve content from page {page_num}. Status code: {response.status_code}")

def scan_and_sniff_ports(host):
    """Scan ports and sniff packets from open ports."""
    clear_terminal()
    
    def scan_port(port):
        """Scan a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((host, port))
                if result == 0:
                    return port, True
                else:
                    return port, False
        except Exception as e:
            print(f"An error occurred while scanning port {port}: {e}")
            return port, False

    def sniff_packets(port):
        """Sniff packets on the given port."""
        try:
            captured_packets = sniff(filter=f"port {port}", count=10)
            print(f"{Fore.YELLOW}[*] Sniffed packets on port {port}:{Style.RESET_ALL}")
            print(captured_packets.summary())
        except Exception as e:
            print(f"An error occurred while sniffing packets on port {port}: {e}")

    print(Fore.YELLOW + """
 _____                         
|   __|___ ___ ___ ___ ___ ___ 
|__   |  _| .'|   |   | -_|  _|
|_____|___|__,|_|_|_|_|___|_|_|_|___|_|  
                               
                               """ + Style.RESET_ALL)
    print("Author: Philip Angwe")
    print("Contact: +254732725352")
    print("Handle: phil legends (all platforms)")

    target_ip = socket.gethostbyname(host)

    print("-" * 50)
    print(f"{Fore.YELLOW}[*] Scanning Target {host} by IP: {target_ip}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Scanning started at: {datetime.now()}{Style.RESET_ALL}")
    print("-" * 50)

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_port = {executor.submit(scan_port, port): port for port in range(1, 7002)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result[1]:
                    open_ports.append(result[0])
                    print(f"{Fore.GREEN}[*] Open port found: {result[0]}{Style.RESET_ALL} (Total: {len(open_ports)})")
                    # Sniff packets from the open port
                    sniff_packets(result[0])
            except Exception as e:
                print(f"An error occurred while scanning port {port}: {e}")

    print("-" * 50)
    if open_ports:
        print(f"{Fore.GREEN}[*] Open ports found: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] No open ports found.{Style.RESET_ALL}")
    print("-" * 50)
    print(f"{Fore.GREEN}[*] Scan completed.{Style.RESET_ALL}")

def main():
    # Display the loading screen
    loading()
    
    # Display the banner
    display_banner()

    # Prompt user for operation choice
    operation_choice = input("\n 1. Web Scraping\n 2. Vulnerability Scanning\n 3. Crack WiFi Password: \n [+] Choose operation:  ")

    if operation_choice == '1':
        # Clear terminal before executing web scraping operation
        clear_terminal()
        extract_website_info()
    elif operation_choice == '2':
        # Run port scanning and packet sniffing operation
        host = input("[+] Enter the host name to scan: ")
        scan_and_sniff_ports(host)
    elif operation_choice == '3':
        # Crack WiFi password
        interface = input("[+] Enter wireless interface (e.g., wlan0): ")
        channel = input("[+] Enter channel to sniff on: ")
        ssid_filter = input("[+] Enter SSID of the target network: ")
        password_file = input("[+] Enter path to password file: ")
        crack_wifi_password(interface, channel, ssid_filter, password_file)
    else:
        print("\033[91m[!] Invalid choice or missing ZAP API key. Exiting...")

if __name__ == "__main__":
    main()