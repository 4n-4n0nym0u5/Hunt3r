import subprocess
import time
import nmap
from colorama import init,Fore,Back,Style
from cryptography.fernet import Fernet

init()

def generate_key():
    return Fernet.generate_key()

def save_key(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def load_key(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

def encrypt_file(filename, key):
    fernet = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(filename + ".encrypted", "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt_file(filename, key):
    fernet = Fernet(key)
    with open(filename, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(filename.replace(".encrypted", ""), "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)
        

def run_command(command, timeout=30):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Timeout: Command execution exceeded specified timeout."
    except Exception as e:
        return str(e)
        
        

def whois_scan(target):
    print("\n\033[92m" + "_"*100 + "\033[0m\n")
    print(f"{Fore.CYAN}\n\n[*] Performing whois scan...\n{Style.RESET_ALL}")
    f = open(f"{target}_scans.txt", "a")
    f.write("\n\033[92m" + "_"*100 + "\033[0m\n")
    f.write("\n\nWhois scan result: \n")
    f.close()
    target1 = target
    if(target1[:2]=='10' or target1[:3]== '172'or target1[:3]== '192'):
        print(f"{Fore.RED}\nSorry, You're Trying to scan Private IP Address\n{Style.RESET_ALL}")
        f = open(f"{target}_scans.txt", "a")
        f.write("No Report Availvale for this scan :)\n\n")
        f.close()
    else:  
        whois_result = run_command(f"whois {target}",timeout=15)
        if(whois_result==""):
            print(f"{Fore.RED}\nNo Result Available\n{Style.RESET_ALL}")
            f = open(f"{target}_scans.txt", "a")
            f.write("No Report Availvale for this scan :)\n\n")
            f.close()
        elif(whois_result[:7]=='Timeout'):
            print(f"{Fore.RED}\nTimed Out...\n{Style.RESET_ALL}")
            f = open(f"{target}_scans.txt", "a")
            f.write("No Report Availvale for this scan :)\n\n")
            f.close()
        else:            
            print(whois_result)
            f = open(f"{target}_scans.txt", "a")
            f.write("Information about domain names, IP addresses, and other resources registered with the Internet Corporation\n\n")
            f.write(whois_result)
            f.close()


def nsLookup_scan(target):
    print("\n\033[92m" + "_"*100 + "\033[0m\n")
    print(f"{Fore.CYAN}\n[*] Performing NsLookup scan...\n{Style.RESET_ALL}")
    f = open(f"{target}_scans.txt", "a")
    f.write("\n\033[92m" + "_"*100 + "\033[0m\n")
    f.write("\n\nNSlookup scan result: \n")
    f.close()
    target1 = target
    if(target1[:2]=='10' or target1[:3]== '172'or target1[:3]== '192'):
        print(f"{Fore.RED}\nSorry, You're Trying to scan Private IP Address\n{Style.RESET_ALL}")
        f = open(f"{target}_scans.txt", "a")
        f.write("No Report Availvale for this scan :)\n\n")
        f.close()
    else:  
        Ns_result = run_command(f"nslookup {target}",timeout=15)
        if(Ns_result==""):
            print(f"{Fore.RED}\nNo Result Available\n{Style.RESET_ALL}")
            f = open(f"{target}_scans.txt", "a")
            f.write("No Report Availvale for this scan :)\n\n")
            f.close()
        elif(Ns_result[:7]=='Timeout'):
            print(f"{Fore.RED}\nTimed Out...\n{Style.RESET_ALL}")
            f = open(f"{target}_scans.txt", "a")
            f.write("No Report Availvale for this scan :)\n\n")
            f.close()
        else:
            print(Ns_result)
            f = open(f"{target}_scans.txt", "a")
            f.write(" Obtained domain name or IP addresses \n\n")
            f.write(Ns_result)
            f.close()

    
    
    
def dnsRecon_scan(target):
    print("\n\033[92m" + "_"*100 + "\033[0m\n")
    print(f"{Fore.CYAN}[*] Performing dnsRecon scan...{Style.RESET_ALL}")
    f = open(f"{target}_scans.txt", "a")
    f.write("\n\033[92m" + "_"*100 + "\033[0m\n")
    f.write("\n\nDNSRecon scan result: \n")
    f.close()
    target1 = target
    if(target1[:2]=='10' or target1[:3]== '172'or target1[:3]== '192'):
        print(f"{Fore.RED}\nSorry, You're Trying to scan Private IP Address\n{Style.RESET_ALL}")
        f = open(f"{target}_scans.txt", "a")
        f.write("No Report Availvale for this scan :)\n\n")
        f.close()
    else:
        dnsRecon_result = run_command(f"dnsrecon -d {target}",timeout=20)                
        if(dnsRecon_result == ""):
            print(f"{Fore.RED}\nNo Result Available\n{Style.RESET_ALL}")
            f = open(f"{target}_scans.txt", "a")
            f.write("No Report Availvale for this scan :)\n\n")
            f.close()
        elif(dnsRecon_result[:7]=='Timeout'):
            print(f"{Fore.RED}\nTimed Out...\n{Style.RESET_ALL}")
            f = open(f"{target}_scans.txt", "a")
            f.write("No Report Availvale for this scan :)\n\n")
            f.close()
        else:
            print(dnsRecon_result)
            f = open(f"{target}_scans.txt", "a")
            f.write(" Obtained DNS Records and SRV Records\n\n")
            f.write(dnsRecon_result)
            f.close()
    
    
def sublister_scan(target):
    print("\n\033[92m" + "_"*100 + "\033[0m\n")
    print(f"{Fore.CYAN}[*] Performing sublist3r scan...{Style.RESET_ALL}")
    f = open(f"{target}_scans.txt", "a")
    f.write("\n\033[92m" + "_"*100 + "\033[0m\n")
    f.write("\n\nSublister scan result: \n")
    f.close()
    target1 = target
    if(target1[:2]=='10' or target1[:3]== '172'or target1[:3]== '192'):
        print(f"{Fore.RED}\nSorry, You're Trying to scan Private IP Address\n{Style.RESET_ALL}")
        f = open(f"{target}_scans.txt", "a")
        f.write("No Report Availvale for this scan :)\n\n")
        f.close()
    else:
        sub_result = run_command(f"sublist3r -d {target}",timeout=40)
        if(sub_result == ""):
            print(f"{Fore.RED}\nNo Result Available\n{Style.RESET_ALL}")
            f = open(f"{target}_scans.txt", "a")
            f.write("No Report Availvale for this scan :)\n\n")
            f.close()
        elif(sub_result[:7]=='Timeout'):
            print(f"{Fore.RED}\nTimed Out...\n{Style.RESET_ALL}")
            f = open(f"{target}_scans.txt", "a")
            f.write("No Report Availvale for this scan :)\n\n")
            f.close()
        else:
            print(sub_result)
            f = open(f"{target}_scans.txt", "a")
            f.write("\n\nSublister scan result: \n")
            f.write("Sub-Domains Found\n\n")
            f.write(sub_result)
            f.close()

def firewall_detect(target):
    print("\n\033[92m" + "_"*100 + "\033[0m\n")
    print(f"{Fore.CYAN}[*] Checking for Firewall ...\n{Style.RESET_ALL}")
    firewall_result = run_command(f"waf00f  {target}",timeout=30)
    print(firewall_result)
    f = open(f"{target}_scans.txt", "a")
    f.write(" Firewall Found \n\n")
    f.write(firewall_result)
    f.close()  

def gobuster_scan(target):
    print("\n\033[92m" + "_"*100 + "\033[0m\n")
    print(f"{Fore.CYAN}[*] Performing Directory enumeration...{Style.RESET_ALL}")
    f = open(f"{target}_scans.txt", "a")
    f.write("\n\033[92m" + "_"*100 + "\033[0m\n")
    f.write("\n\nGobuster scan result: \n")
    f.close()
    gobus_result = run_command(f"gobuster dir --wordlist=/usr/share/wordlists/dirb/big.txt  --url {target}",timeout=60)
    print(gobus_result)
    f = open(f"{target}_scans.txt", "a")
    f.write("\n\n\nObtained the following directories\n\n")
    f.write(gobus_result)
    f.close() 
    
   

char_to_find = ":"
v_lst = []  
final_lst=[]

def nmap_scan(target):
    # Initialize the port scanner
    print("\n\033[92m" + "_"*100 + "\033[0m\n")
    print(f"{Fore.CYAN}[*] Checking for Open Ports...\n{Style.RESET_ALL}")
    f = open(f"{target}_scans.txt", "a")
    f.write("\n\033[92m" + "_"*100 + "\033[0m\n")
    f.write("\n\nNmap scan result: \n")
    f.close()
    nmScan = nmap.PortScanner()

    # Scan the target
    nmScan.scan(target, arguments=' -sV')

    
    # Print and write the results
    output = ''
    a1 = ''
    a2 = ''
    a3 = ''
    for host in nmScan.all_hosts():
        output += 'Host : %s (%s)\n' % (host, nmScan[host].hostname())
        output += 'State : %s\n' % nmScan[host].state()
        for proto in nmScan[host].all_protocols():
            output += 'Protocol : %s\n' % proto
            lport = nmScan[host][proto].keys()
            for port in lport:
                output += 'Port : %s\tService : %s\tVersion : %s\tCPE : %s\n' % (port, nmScan[host][proto][port]['name'], nmScan[host][proto][port]['version'], nmScan[host][proto][port]['cpe'])          
                # v_lst.append(nmScan[host][proto][port]['name']+" "+nmScan[host][proto][port]['version'])
                v_lst.append(nmScan[host][proto][port]['cpe'])
                a = nmScan[host][proto][port]['cpe']
                index_of_third_colon = find_third_index(a, char_to_find)
                index_of_fourth_colon = find_fourth_index(a, char_to_find)   
                if(index_of_third_colon!=-1 & index_of_fourth_colon!=-1):
                    a1 = a[index_of_third_colon+1:index_of_fourth_colon-1]
                    a2 = a[index_of_fourth_colon+1:]
                elif(index_of_third_colon!=-1 & index_of_fourth_colon==-1):
                    a1 = a[index_of_third_colon+1:index_of_fourth_colon-1]
                # print("a1: ",a1)
                # print("a2: ",a2)
                
                if(index_of_third_colon!=-1 & index_of_fourth_colon!=-1):
                    a3 = a1+" "+a2
                    final_lst.append(a3)
                if(a3==""):
                    if(a1==""):
                        a3 = a
                        final_lst.append(a3)
                    else:
                        a3 = a1
                        final_lst.append(a3)
                
                # print("a3: ",a3)
                
    print(output)   

    # f= open(f"{target}_scans.txt", "a")
    # f.write(output)
    # f.close()
    with open(f"{target}_scans.txt", "a") as f:
        f.write("Open Ports Found\n\n")
        f.write(output) 
        f.close()  
        
def searchForExploits(target):
    print(f"{Fore.CYAN}\n\n\nFor Exploit searching...\n\n{Style.RESET_ALL}",final_lst)
    f = open(f"{target}_scans.txt", "a")
    f.write("\n\033[92m" + "_"*100 + "\033[0m\n")
    f.write("\n\nExploits found for the target: \n")
    f.close()
    print("CPE List: ",v_lst)
    print("\n")
    f = open(f"{target}_scans.txt", "a")
    for a in final_lst:
        print(a)
        f.write(a)

        #    f.write(f"Scanning results for {target}....\n")
        result = run_command(f"searchsploit {a}",timeout=5)
        print(result)
        if(result==""):
            f.write("No Exploits found\n")
        else:
            f.write("Exploits found:\n")
            f.write(result)
    f.close()

def find_third_index(text, char):
    count = 0
    for index, c in enumerate(text):
        if c == char:
            count += 1
            if count == 3:
                return index
    return -1  

def find_fourth_index(text, char):
    count = 0
    for index, c in enumerate(text):
        if c == char:
            count += 1
            if count == 4:
                return index
    return -1  

def check_connection(target):
    temp = run_command(f"ping -c 2 {target}",timeout=10)
    if(len(temp)>100):
        return 1
    else:
        return 0


def main():
    t1 = run_command(f"figlet Hunt3r",timeout=2)
    print("\033[94m"+t1+"\033[0m")
   # print(run_command(f"figlet Hunt3r",timeout=2))
   
    check = input(f"{Fore.GREEN}If you want to decrypt a report enter '-d'\nIf you want to scan a new target enter '-ns'\n: {Style.RESET_ALL}")
    if(check=='-d'):
        # Load the key from the file
        filename = input("Enter the file name: ")
        key = load_key("key.key")
	    # Decrypt a file
        decrypt_file(filename, key)
	
    elif(check=='-ns'):
        target = input(f"{Fore.RED}\nEnter the target domain or IP address: {Style.RESET_ALL}")
        if(check_connection(target)):
            print("\n")
            print("\033[92m"+"Target is up"+"\033[0m")
            f = open(f"{target}_scans.txt", "w")
            f.write(f"Scanning results for {target}....\n")
            f.close()
            whois_scan(target)
            nsLookup_scan(target)
            sublister_scan(target)
            dnsRecon_scan(target)  
            nmap_scan(target)
            gobuster_scan(target)
            searchForExploits(target)
            
            #print(f"{Fore.CYAN}\n\nReport File created as: {target}_scans.txt\n{Style.RESET_ALL}")
            # Generate a key
            key = generate_key()
            # Encrypt a file
            encrypt_file(f"{target}_scans.txt", key)
        	#Save the key to a file
            save_key(key, "key.key")
            run_command(f"rm {target}_scans.txt",timeout=5)
            print(f"{Fore.CYAN}\n\nEncoded Report File created as: {target}_scans.txt.encrypted\n{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}Target is not reachable.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}\nWrong option selected :({Style.RESET_ALL}")
    

if __name__ == "__main__":
    main()

