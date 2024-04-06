from scapy.all import *
import time
from io import BytesIO
import os

class colors:
    NEONPINK = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    PURPLE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
def process_user_input(input_str):
    #sudo iptables -A INPUT -s 203.0.113.51 -j DROP
    try:
        action, direction, target_type, target_value = input_str.split()
        with open("rules.txt", 'a') as file:  # Open in append mode
            file.write(f"{action} {direction} {target_type} {target_value}\n")
        print(f"Successfully added the rule to rules.txt.")
    except ValueError:
        print("Invalid input format. Please provide input in the format: "
              "<DROP/ACCEPT> <FROM/TO> <IP/PORT (word)> <IP address/PORT number>")

def snif_packets():
    packet_amount = input(colors.YELLOW + "How many packets do we sniff? " + colors.END) #how many do we need
    if (int(packet_amount) <= 0): #if input is invalid
        exit() #terminate
    packet_list = sniff(filter="ip", count=int(packet_amount))
    print(colors.CYAN + "Done" + colors.END)
    time.sleep(2)
    print("\033[H\033[J", end="")
    return packet_list,int(packet_amount)

def live_capture():
    while True:
        try:
            packet = sniff(filter="ip", count=1)
            pack_analysis(packet)
        except KeyboardInterrupt:
            # User pressed Ctrl+C to stop the capture
            print("Packet capture stopped by user.")
            break

def pack_analysis(packet_list):
    ports_dict,http_dict = load_data() #load descriptors

    for packet in packet_list:
        # We can get the attribute reflexively because python allows it
        ipsrc = getattr(packet["IP"], "src")
        ipdst = getattr(packet["IP"], "dst")
        print("IP source:", ipsrc, "IP destination:", ipdst)

        # If the packet has a TCP layer, print source and destination ports
        if "TCP" in packet:
            src_port = packet["TCP"].sport
            dst_port = packet["TCP"].dport
            print("Source Port:", src_port, "Destination Port:", dst_port)
            if src_port in ports_dict:
                print(f"Packet with port {src_port} is most likely used by {ports_dict[src_port]}\n")

            if dst_port in ports_dict:
                print(f"Packet with port {dst_port} is most likely used by {ports_dict[dst_port]}\n")

            flags = packet["TCP"].flags
            
            print("Flags:", flags)

        # If the packet has a UDP layer, print source and destination ports
        if "UDP" in packet:
            src_port = packet["UDP"].sport
            dst_port = packet["UDP"].dport
            print("Source Port:", src_port, "Destination Port:", dst_port)

            if src_port in ports_dict:
                print(f"Packet with port {src_port} is most likely used by {ports_dict[src_port]}\n")

            if dst_port in ports_dict:
                print(f"Packet with port {dst_port} is most likely used by {ports_dict[dst_port]}")

        if "HTML" in packet:
            code = packet["HTTP"].Status_Code
            if code in http_dict:
                print(f"Packet with port {code} is most likely used by {http_dict[code]}")
            else:
                print("Status code:", code)
            # print("Status code:", code)

        if "Ethernet" in packet:
            srcMac = packet["Ethernet"].dst
            print("Mac addr dst:",srcMac)

        # Print packet length
        packet_length = len(packet)
        print("Packet Length:", packet_length)

        # Print packet type (e.g., TCP, UDP, ICMP)
        packet_type = packet.summary().split()[0]
        print("Packet Type:", packet_type)

def load_data():

    with open('port-numbers.txt', 'r') as file:
        ports_data = file.readlines()

    ports_dict = {}
    for line in ports_data:
        port_number, description = line.strip().split(' ', 1)
        ports_dict[int(port_number)] = description


    with open('http-codes.txt', 'r') as file:
        http_responds = file.readlines()

    http_dict = {}
    for line in ports_data:
        http_respond, description = line.strip().split(' ', 1)
        http_dict[http_respond] = description  

    
    return ports_dict, http_dict

def read_filewall_rules():
    try:
        print("\033[H\033[J", end="")
        with open("rules.txt", 'r') as file:
            lines = file.readlines()
            for index, line in enumerate(lines):
                print(f"Rule {index + 1}: {line.strip()}")
    except FileNotFoundError:
        print(f"Rules were not found.")

    print(colors.CYAN + "Done" + colors.END)
    time.sleep(2)
    print("\033[H\033[J", end="")

def packets_to_text(packet_list):
    with open("packet_text_output.txt", 'w') as file:
        for packet in packet_list:
            a = packet.show(dump=True)
            print(type(a))
            print(a)
            file.write(a)
            file.write("\n")    

    print(colors.CYAN + "Done" + colors.END)
    time.sleep(2)
    print("\033[H\033[J", end="")    

def packets_to_pcap(packet_list):
    for packet in packet_list:
        wrpcap('filtered.pcap', packet, append=True)
        print(colors.CYAN + "Done" + colors.END)
        time.sleep(2)
        print("\033[H\033[J", end="")

def main():
    #Welcome part of the program
    print("\033[H\033[J", end="")
    print(colors.NEONPINK + "Artem Sharkota, CS4723 Spring 2024" + colors.END)
    print(colors.CYAN + "This is Final Project" + colors.END)

    #Initial Capture
    # print(colors.NEONPINK + "You don't have packets to work with" + colors.END)
    # packet_list, analyzed_packs = snif_packets()
    # print("\033[H\033[J", end="")
    packet_list = None
    analyzed_packs = 0

    while True:
        # Perform some action
        print(colors.UNDERLINE + "Type ""exit"" to exit\n" + colors.END)
        print(colors.NEONPINK + "[1] Sniff Packets" + colors.END)
        print(colors.NEONPINK + "[2] Analyse Packets" + colors.END)
        print(colors.NEONPINK + "[3] Live Capture" + colors.END)
        print(colors.NEONPINK + "[4] Add an iptable rule" + colors.END)
        print(colors.NEONPINK + "[5] List iptables rules" + colors.END)
        if (analyzed_packs > 0):
            print(colors.NEONPINK + "[6] Save packets to text" + colors.END)
            print(colors.NEONPINK + "[7] Save packets to pcap" + colors.END)
        
        action_choose = input(colors.CYAN + "Enter your action: " + colors.END)
        
        # if user wants to sniff n amount of packets and save them for later use
        if action_choose == "1":
            packet_list, analyzed_packs = snif_packets()
            print("\033[H\033[J", end="") #clear screen

        # if user want to analyse already recorded packets
        if action_choose == "2":
            if analyzed_packs == 0:
                print(colors.NEONPINK + "You don't have packets to work with" + colors.END)
                packet_list, analyzed_packs = snif_packets()
                print("\033[H\033[J", end="")

            print(f"We have {analyzed_packs} packets, do you want to record new packets?")
            action_choose = input(colors.CYAN + "Enter your action: " + colors.END)
            if action_choose.lower() == "no":
                pack_analysis(packet_list)
                continue

            if action_choose.lower() == "yes":
                packet_list, analyzed_packs = snif_packets()
                print("\033[H\033[J", end="") #clear screen

        #if user wants to see live capture
        if action_choose == "3":
            print("\033[H\033[J", end="")
            print(colors.RED + "You will not be able to turn the system off" + colors.END)
            print(colors.RED + "Do you want to proceed?" + colors.END)
            action_choose = input(colors.CYAN + "[Yes/No?] " + colors.END)
            if action_choose.lower() == "yes":
                live_capture()
            elif action_choose.lower() == "no":
                print("\033[H\033[J", end="")
                continue

        if action_choose == "4":
            # Example usage:
            print(colors.RED + "Example rule: ""DROP TO PORT 443""" + colors.END)
            newRule = input("Enter rule in format <DROP/ACCEPT> <FROM/TO> <IP/PORT> <IP number/PORT number>: ")
            process_user_input(newRule)

        if action_choose == "5":
            read_filewall_rules()

        if action_choose.lower() == "clear":
            print("\033[H\033[J", end="") #clear screen

        if action_choose.lower() == "exit":            
            print("\033[H\033[J", end="") #clear screen
            exit() #terminate the program

        if (analyzed_packs > 0 and action_choose == "6"):
            packets_to_text(packet_list)

        if (analyzed_packs > 0 and action_choose == "7"):
            packets_to_pcap(packet_list)

if __name__ == "__main__":
    main()

