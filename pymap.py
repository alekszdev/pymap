import nmap
import os
from colorama import Fore, Style, init
import fade

def clear_screen():
    os.system("clear || cls")
clear_screen()



def port_scan():
    try:
        ip_to_scan = input("Enter an IP to scan: ")
        range_to_scan = input("Enter a range (1-20): ")
        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")

        scanner = nmap.PortScanner()
        scanner.scan(ip_to_scan, range_to_scan)

        state_host = scanner[f'{ip_to_scan}'].state()
        tcp_ports = scanner[f'{ip_to_scan}']['tcp'].keys()

        for host in scanner.all_hosts():
            print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST: {host}")
            for ip_host in scanner[host].all_protocols():
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST STATE: {state_host} ")
                for port in tcp_ports:
                    extrainfo = scanner[host][ip_host][port].get('extrainfo', 'N/A')
                    port_state = scanner[host][ip_host][port]['state']

                    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} PORT: {port} IS {port_state}")
                    if extrainfo:
                        print(f"{Fore.LIGHTMAGENTA_EX}[{Fore.RESET}+{Fore.LIGHTMAGENTA_EX}]{Fore.RESET} EXTRA INFO: {extrainfo}")
    except KeyError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")



def agresive_scan():
    try:
        ip_to_scan = input("Enter an IP to scan: ")
        range_to_scan = input("Enter a range (1-20): ")
        velocity_level = input("Enter a velocity and agresive to scan (1-5): ")
        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")

        scanner = nmap.PortScanner()
        scanner.scan(ip_to_scan, range_to_scan, f'-T{velocity_level} ')

        state_host = scanner[f'{ip_to_scan}'].state()
        tcp_ports = scanner[f'{ip_to_scan}']['tcp'].keys()

        for host in scanner.all_hosts():
            print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST: {host}")
            for ip_host in scanner[host].all_protocols():
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST STATE: {state_host} ")
                for port in tcp_ports:
                    extrainfo = scanner[host][ip_host][port].get('extrainfo', 'N/A')
                    port_state = scanner[host][ip_host][port]['state']

                    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} PORT: {port} IS {port_state}")
                    if extrainfo:
                        print(f"{Fore.LIGHTMAGENTA_EX}[{Fore.RESET}+{Fore.LIGHTMAGENTA_EX}]{Fore.RESET} EXTRA INFO: {extrainfo}")
    except nmap.nmap.PortScannerError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")



def os_detect():
    try:
        ip_to_scan = input("Enter an IP to scan: ")
        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")

        scanner = nmap.PortScanner()
        scanner.scan(ip_to_scan, arguments='-O')


        if 'osclass' in scanner[ip_to_scan]:
            for osclass in scanner[ip_to_scan]['osclass']:
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}✓{Fore.LIGHTBLUE_EX}]{Fore.RESET} OS Detected: {osclass['osfamily']}")
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} PROBABILITY: {osclass['accuracy']}%")
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} TYPE OS: {osclass['type']}")
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} VENDOR: {osclass['vendor']}")
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} GEN: {osclass['osgen']}")
        else:
            print("OS could not be detected")
    except KeyError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")



def sv_scann():
    try:
        ip_to_scan = input("Enter an IP to scan: ")
        range_to_scan = input("Enter a range (1-20): ")
        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")

        scanner = nmap.PortScanner()
        scanner.scan(ip_to_scan, range_to_scan, arguments='-sV')

        state_host = scanner[f'{ip_to_scan}'].state()
        tcp_ports = scanner[f'{ip_to_scan}']['tcp'].keys()

        for host in scanner.all_hosts():
            print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST: {host}")
            for ip_host in scanner[host].all_protocols():
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST STATE: {state_host} ")
                for port in tcp_ports:
                    extrainfo = scanner[host][ip_host][port].get('extrainfo', 'N/A')
                    port_state = scanner[host][ip_host][port]['state']

                    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} PORT: {port} IS {port_state}")
                    if extrainfo:
                        print(f"{Fore.LIGHTMAGENTA_EX}[{Fore.RESET}+{Fore.LIGHTMAGENTA_EX}]{Fore.RESET} EXTRA INFO: {extrainfo}")
    except KeyError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")



def udp_scan():
    try: 
        ip_to_scan = input("Enter an IP to scan: ")
        range_to_scan = input("Enter a range (1-20): ")

        scanner = nmap.PortScanner()
        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")
        scanner.scan(ip_to_scan, range_to_scan, arguments='-sU')
        state_host = scanner[f'{ip_to_scan}'].state()
        udp_ports = scanner[f'{ip_to_scan}']['udp'].keys()


        for host in scanner.all_hosts():
            print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST: {host}")
            
            for ip_host in scanner[host].all_protocols():
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST STATE: {state_host} ")

                for port in udp_ports:
                    extrainfo = scanner[host][ip_host][port].get('extrainfo', 'N/A')
                    port_state = scanner[host][ip_host][port]['state']
                    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} PORT: {port} IS {port_state}")
                    if extrainfo:
                        print(f"{Fore.LIGHTMAGENTA_EX}[{Fore.RESET}+{Fore.LIGHTMAGENTA_EX}]{Fore.RESET} EXTRA INFO: {extrainfo}")
    except KeyError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")



def try_again():
    try_another = input(f"You want to try another time (y/n): ")
    if try_another=='y':
        main_menu()



def select_option(option):
    actions = {
        1: port_scan,
        2: agresive_scan,
        3: os_detect,
        4: sv_scann,
        5: udp_scan
        }
    if option in actions:
        actions[option]()



def main_menu():
    clear_screen()
    print(fade.purpleblue(f"""
                          
 ██▓███ ▓██   ██▓ ███▄ ▄███▓ ▄▄▄       ██▓███  
▓██░  ██▒▒██  ██▒▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒
▓██░ ██▓▒ ▒██ ██░▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒
▒██▄█▓▒ ▒ ░ ▐██▓░▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒
▒██▒ ░  ░ ░ ██▒▓░▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░
▒▓▒░ ░  ░  ██▒▒▒ ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░
░▒ ░     ▓██ ░▒░ ░  ░      ░  ▒   ▒▒ ░░▒ ░     
░░       ▒ ▒ ░░  ░      ░     ░   ▒   ░░       
         ░ ░            ░         ░  ░         
         ░ ░
by alekszdev.                                   
          """))
    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}1{Fore.LIGHTBLUE_EX}]{Fore.RESET} NORMAL PORTS SCAN")
    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}2{Fore.LIGHTBLUE_EX}]{Fore.RESET} AGRESSIVE SCAN")
    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}3{Fore.LIGHTBLUE_EX}]{Fore.RESET} OS DETECT SCAN")
    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}4{Fore.LIGHTBLUE_EX}]{Fore.RESET} SERVICE AND SOFTWARE SCAN")
    print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}5{Fore.LIGHTBLUE_EX}]{Fore.RESET} UDP SCAN (User Datagram Protocol)")
    try:
        option = int(input("> "))
        select_option(option)
        try_again()
    except ValueError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")
        try_again()
main_menu()
