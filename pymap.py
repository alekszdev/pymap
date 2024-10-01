import nmap
import os
from colorama import Fore, Style, init
import fade

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
clear_screen()



def port_scan():
    try:
        ip_to_scan = input("Enter an IP to scan: ")
        range_to_scan = input("Enter a range (1-20): ")

        scanner = nmap.PortScanner()
        scanner.scan(ip_to_scan, range_to_scan)

        state_host = scanner[f'{ip_to_scan}'].state()
        tcp_ports = scanner[f'{ip_to_scan}']['tcp'].keys()

        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")

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

        scanner = nmap.PortScanner()
        scanner.scan(ip_to_scan, range_to_scan, f'-T{velocity_level} ')

        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")

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

        scanner = nmap.PortScanner()
        scanner.scan(ip_to_scan, arguments='-O')
        
        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")

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

        scanner = nmap.PortScanner()
        scanner.scan(ip_to_scan, range_to_scan, arguments='-sV')

        state_host = scanner[f'{ip_to_scan}'].state()
        tcp_ports = scanner[f'{ip_to_scan}']['tcp'].keys()

        print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} Scanning...")

        for host in scanner.all_hosts():
            print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST: {host}")
            for ip_host in scanner[host].all_protocols():
                print(f"{Fore.LIGHTBLUE_EX}[{Fore.RESET}+{Fore.LIGHTBLUE_EX}]{Fore.RESET} HOST STATE: {state_host} ")
                for port in tcp_ports:
                    extrainfo = scanner[host][ip_host][port].get('extrainfo', 'N/A')
                    port_state = scanner[host][ip_host][port]['state']

                    print(f"PORT: {port} IS {port_state}")
                    if extrainfo:
                        print(f"{Fore.LIGHTMAGENTA_EX}[{Fore.RESET}+{Fore.LIGHTMAGENTA_EX}]{Fore.RESET} EXTRA INFO: {extrainfo}")
    except KeyError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")


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
    try:
        option = int(input("> "))
        if option==1:
            port_scan()
            try_another = input(f"{Fore.CYAN}[{Fore.RESET}+{Fore.CYAN}]{Fore.RESET} You want to try another time (y/n): ")
            if try_another=='y':
                main_menu()
        elif option==2:
            agresive_scan()
            try_another = input(f"{Fore.CYAN}[{Fore.RESET}+{Fore.CYAN}]{Fore.RESET} You want to try another time (y/n): ")
            if try_another=='y':
                main_menu()
        elif option==3:
            os_detect()
            try_another = input(f"{Fore.CYAN}[{Fore.RESET}+{Fore.CYAN}]{Fore.RESET} You want to try another time (y/n): ")
            if try_another=='y':
                main_menu()
        elif option==4:
            sv_scann()
            try_another = input(f"{Fore.CYAN}[{Fore.RESET}+{Fore.CYAN}]{Fore.RESET} You want to try another time (y/n): ")
            if try_another=='y':
                main_menu()
    except ValueError as e:
        print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RESET} An error has ocurred: {e}")
        try_another = input(f"{Fore.CYAN}[{Fore.RESET}+{Fore.CYAN}]{Fore.RESET} You want to try another time (y/n): ")
        main_menu()
main_menu()