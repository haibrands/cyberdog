#! /usr/bin/env python3
import sys
import os
import os.path
import subprocess


###############################################################################################################
# [Title]: cyberdog.py
# [Author]: Katrina Tan + Brandon Hai
# [GitHub]: https://github.com/haibrands/cyberdog.git
###############################################################################################################
# [Details]:
# This script is meant as a capstone for the end of our Cal Poly Extended Education Cybersecurity Bootcamp by Fullstack Academy. It is a script intended for use on a local Linux box, geared toward assisting the user in reconnaissance and enumeration of any given box.
###############################################################################################################
# [Warning]:
# We may or may not decide to come back and brush up on this script at times, but it is by no means regularly updated for vulnerabilities/bugs. It is also 100% not the most efficient script out there for reconnaissance/enumeration. Use it for fun!
###############################################################################################################


def opening(): #Opening function with introduction of the script along with the various scans used.
    print ("\n\n       /^-^\        _____           _                     _____                      /^-----^\ \n      / o o \      / ____|         | |                   |  __ \                     V  o o  V \n     /   Y   \    | |       _   _  | |__     ___   _ __  | |  | |   ___     __ _      |  Y  | \n     V \ v / V    | |      | | | | | '_ \   / _ \ | '__| | |  | |  / _ \   / _` |      \ Q / \n       / - \      | |____  | |_| | | |_) | |  __/ | |    | |__| | | (_) | | (_| |      / - \ \n      /    |       \_____|  \__, | |_.__/   \___| |_|    |_____/   \___/   \__, |      |    \ \n(    /     |                 __/ |                                          __/ |      |     \     ) \n ===/___) ||                |___/                                          |___/       || (___\==== \n")
    print ("\n\nWelcome to Cyberdog! This is a box enumeration tool that utilizes the following scans: \n1) nmap \n2) nikto \n3) dirb")
    print ("\nThis program can take a long time! The UDP scan has been limited to the top 50 ports. You also have the option to disable the nikto scan which would take the longest.")
    print ("\nYou can find the final report at './report.txt' You can also find each individual scan in the './individual_scans' directory.")
    print ("\n\033[31mWarning: Previous reports will be overwritten! \033[0m\n")

def targetip(): #Input for target IP.
    target = input("What IP would you like to scan? ")
    return target

def ip_checker(ip): #Run against IP address to check for validity.
    if ip.count('.') != 3:
        return False
    split_ip = ip.split('.')
    if len(split_ip) != 4:
        return False
    for num in split_ip:
        if not num.isdigit():
            return False
        i = int(num)
        if i < 0 or i > 255:
            return False
    return True

def waiting(scan): #Lets user know the scan is running.
    return ("\033[96mPlease wait... " + scan + " scan running...\033[0m")

def individual_scans(input,scan): #Outputs each scan to a .txt file as well
    f = open("./individual_scans/" + scan + ".txt", "a+")
    f.write(input)
    f.close()

def web_server_check(ip): #Checks if port 80 is open.
    x = ''
    print ("\n\033[96mPlease wait... checking if a web server is running...\033[0m")
    cmd = "nmap -p 80 " + ip
    output = subprocess.check_output(cmd, shell = True)
    change_output = str(output)
    port_80_scan = change_output.replace('\\n','\n')
    if port_80_scan.find('open'):
        x = 'open'
    else:
        x = 'closed'
    return x

def nikto_ws():
    answer = input("Did you want to run a nikto scan if a web server is detected? This would take a long time. (Y/N): ")
    if answer.lower() == 'y':
        return 'y'
    elif answer.lower() == 'n':
        return 'n'

def nikto_checker(answer):
    if answer == 'y':
        return True
    elif answer == 'n':
        return True
    return False

def nmap_scan_synscan(ip): #SYN (Stealth) Scan, default and popular scan. It's quick, and is relatively unobtrusive and stealthy since it never completes TCP connections.
    scan = "nmap -sS"
    print ('\n' + waiting(scan))
    cmd = "nmap -sS " + ip
    output = subprocess.check_output(cmd, shell = True)
    change_output = str(output)
    x = change_output.replace('\\n','\n')
    individual_scans(x,"syn_scan")

def nmap_scan_allports(ip): #All Ports Scan, scans all ports.
    scan = "nmap -p-"
    print (waiting(scan))
    cmd = "nmap " + ip + " -p-"
    output = subprocess.check_output(cmd, shell = True)
    change_output = str(output)
    x = change_output.replace('\\n','\n')
    individual_scans(x,"all_ports_scan")

def nmap_scan_serviceversion(ip): #Service-version, Default Scripts, OS Scan, used to detect the OS and services running on open ports.
    scan = "nmap -sV -sC -O -p 111,222,333"
    print (waiting(scan))
    cmd = "nmap " + ip + " -sV -sC -O -p 111,222,333"
    output = subprocess.check_output(cmd, shell = True)
    change_output = str(output)
    x = change_output.replace('\\n','\n')
    individual_scans(x,"service_version_os_scan")

def nmap_scan_udp(ip): #UDP Scan, scans for UDP ports.
    scan = "nmap -sU"
    print (waiting(scan))
    cmd = "nmap --top-ports 50 " + ip + " -sU"
    output = subprocess.check_output(cmd, shell = True)
    change_output = str(output)
    x = change_output.replace('\\n','\n')
    individual_scans(x,"udp_scan")

def nmap_scan_tcp(ip): #TCP Scan, scans for TCP ports.
    scan = "nmap -sT"
    print (waiting(scan))
    cmd = "nmap " + ip + " -sT"
    output = subprocess.check_output(cmd, shell = True)
    change_output = str(output)
    x = change_output.replace('\\n','\n')
    individual_scans(x,"tcp_scan")

def nikto_scan(ip): #Nikto Scan, used for webservers to find dangerous files/CGIs, outdated server software and other problems.
    print (waiting("nikto"))
    cmd = "nikto -h http://" + ip
    output = subprocess.check_output(cmd, shell = True)
    change_output = str(output)
    x = change_output.replace('\\n','\n')
    individual_scans(x,"nikto_scan")

def dirb_scan(ip): #DirBuster Scan, directory buster scan for web servers. 
    print (waiting("dirb"))
    cmd = "dirb http://" + ip + " -r"
    output = subprocess.check_output(cmd, shell = True)
    change_output = str(output)
    x = change_output.replace('\\n','\n')
    individual_scans(x,"dirb_scan")

#def scan_report(): #Output scan results with the following information: DNS-Domain name, Host name, OS, Server, Kernel, Workgroup, Windows domain, ports open, services open
#Emphasize following ports in this order, with tips:
#21 - FTP, 22 - SSH, 25 - SMTP, 69 - UDP - TFTP, 110 - POP3, 111 - rpcbind, 135 - MSRPC, 143 - IMAP, 139/445 - SMB, 161/162 - SNMP, 554 - RTSP, 1521 - Oracle, 2049 - NFS, 2100 - Oracle XML DB, 3306 - MySQL, 3339 - Oracle Web Interface, 80 - Web Server, 443 - HTTPS


def main(): #Everything that you want the main function to do
    opening()
    isdir = os.path.isdir("./individual_scans")
    if isdir != True:
        path = "individual_scans"
        os.mkdir(path)
    target = targetip()
    while True:
        if ip_checker(target) == True:
            break
        else:
            print ("Sorry, please enter a valid IP address. \n")
            target = targetip()
    nikto_answer = nikto_ws()
    while True:
        if nikto_checker(nikto_answer) == True:
            break
        else:
            print ("Please answer with a Y or a N.\n")
            nikto_answer = nikto_ws()
    nmap_scan_synscan(target)
    nmap_scan_allports(target)
    nmap_scan_serviceversion(target)
    nmap_scan_udp(target)
    nmap_scan_tcp(target)
    port_80 = web_server_check(target)
    if port_80 == 'open':
        if nikto_answer == 'y':
            print ("\033[32mA web server was found, running nikto and dirb scans now...\n\033[0m")
            nikto_scan(target)
            dirb_scan(target)
        else:
            print ("\033[32mA web server was found, running dirb scan now...\n\033[0m")
            dirb_scan(target)
            if os.path.exists("./individual_scans/nikto_scan.txt"):
                os.remove("./individual_scans/nikto_scan.txt")
    else:
        print ("\033[31mNo web server found.\n\033[0m")
        if os.path.exists("./individual_scans/dirb_scan.txt"):
            os.remove("./individual_scans/dirb_scan.txt")
        if os.path.exists("./individual_scans/nikto_scan.txt"):
            os.remove("./individual_scans/nikto_scan.txt")
    print ("\nFinished.")


if __name__=='__main__':
    main()
