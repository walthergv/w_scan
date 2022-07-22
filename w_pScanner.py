from scapy.all import *
from pwn import *
import argparse, time, signal, sys

def def_handler(sig, frame):
    print('\n\n[!] Exiting ...\n')
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)


def banner():
    print('''
   _      _          _____   _____   ______   _ _    _
  | |    | |        |  ___| |  ___| |   _  | | | |  | |
  | | -- | |        | |___  | |     |  |_| | | || | | |
  | |/  \| |        |___  | | |     |  __  | | | | || |  
  |   /\   |  _____  ___| | | |___  |  ||  | | |  | | |
  |__/  \__| /____/ |_____| |_____| |__||__| |_|   ||_|
  
          ''')

parser = argparse.ArgumentParser('TCP port scanner\n')
parser.add_argument('-ip', '--target', help='IP Address')
parser.add_argument('-p',  '--ports', type=int, nargs='+', help='Ports to scan 21 22 80 ...')

args=parser.parse_args()
ip = args.target

if args.ports:
    ports = args.ports
else:
    ports = range(1, 65535)

def tcp_scan(ip, ports):
    print(f'TCP scan ==> [IP] {ip} | [PORTS] {ports}')
    
    p1 = log.progress("Scanning Network ...")
    time.sleep(2)

    for port in ports:
        packet = sr1(IP(dst=ip)/TCP(dport=port, flags='S'), timeout=0.25, verbose=False)
        if packet != None:
            if packet.haslayer(TCP):
                if packet[TCP].flags =='SA':
                    out_ports(port,'Open')
                elif packet[TCP].flags == 'RA':
                    out_ports(port,'Close')
                else:
                    out_ports(port,'Filtered')
            else:
                out_ports(port, 'Unknown')
        else:
            out_ports(port, 'Unanswered')

def out_ports(port, state):
    print(f'\nPort {port} ==> {state}')

if __name__=='__main__':
    banner()
    tcp_scan(ip, ports)
