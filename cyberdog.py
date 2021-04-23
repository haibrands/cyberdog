#! /usr/bin/env python3
import sys
import os
import subprocess


###############################################################################################################
# [Title]: cyberdog.py
# [Author]: Katrina Tan + Brandon Hai
# [GitHub]: https://github.com/haibrands/cyberdog.git
###############################################################################################################
# [Details]:
# This script is meant as a capstone for the end of our Cal Poly Extended Education Cybersecurity Bootcamp by Fullstack Academy. It is a script intended to be executed locally on a Linux box geared toward assisting the user in reconnaissance and enumeration of any given box.
###############################################################################################################
# [Warning]:
# We may or may not decide to come back and brush up on this script at times, but it is by no means regularly updated for vulnerabilities/bugs. It is also 100% not the most efficient script out there for reconnaissance/enumeration. Use it for fun!
###############################################################################################################


def opening(): #Opening function with introduction of the script along with the various scans used.
    print ("\n\n       /^-^\        _____           _                     _____                      /^-----^\ \n      / o o \      / ____|         | |                   |  __ \                     V  o o  V \n     /   Y   \    | |       _   _  | |__     ___   _ __  | |  | |   ___     __ _      |  Y  | \n     V \ v / V    | |      | | | | | '_ \   / _ \ | '__| | |  | |  / _ \   / _` |      \ Q / \n       / - \      | |____  | |_| | | |_) | |  __/ | |    | |__| | | (_) | | (_| |      / - \ \n      /    |       \_____|  \__, | |_.__/   \___| |_|    |_____/   \___/   \__, |      |    \ \n(    /     |                 __/ |                                          __/ |      |     \     ) \n ===/___) ||                |___/                                          |___/       || (___\==== \n")
    print ("\n\nWelcome to Cyberdog! This is a box enumeration tool that will utilize the following scans: \n1) nmap \n2) nikto \n3) DirBuster (If a web server is running)")
    print ("\nA report will be generated in the same directory as this script, find it at './report.txt'")
    print ("If a web server is directed, a directory buster scan will be ran and the results can be found in the same directory as this script, find it at './dirbuster.txt'")
    print ("\033[31mWarning: Previous reports will be overwritten! \033[0m\n")

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
    return ('\033[96m''Please wait... ' + scan + ' scan running...' '\033[0m''')

def nmap_scan_synscan(): #SYN (Stealth) Scan (nmap -sS target), default and popular scan. It's quick, and is relatively unobtrusive and stealthy since it never completes TCP connections.
    print ('\n' + waiting('nmap -sS'))

def nmap_scan_allports(): #All Ports Scan (nmap target -p-), scans all ports.
    print (waiting('nmap -p-'))

def nmap_scan_serviceversion(): #Service-version, Default Scripts, OS Scan (nmap target -sV -sC -O -p 111,222,333), used to detect the OS and services running on open ports.
    print (waiting('nmap -sV -sC -O -p 111,222,333'))

def nmap_scan_udp(): #UDP Scan (nmap target -sU), scans for UDP ports.
    print (waiting('nmap -sU'))

def nmap_scan_tcp(): #TCP Scan (nmap target -sT), scans for TCP ports.
    print (waiting('nmap -sT'))

def nikto_scan(): #Nikto Scan (-h http://target), used for webservers to find dangerous files/CGIs, outdated server software and other problems.
    print (waiting('nikto'))

def dirb_scan(): #DirBuster Scan (http://target -r -o dirbuster.txt), directory buster scan for web servers. 
    print (waiting('DirBuster'))

#def scan_report(): #Output scan results with the following information: DNS-Domain name, Host name, OS, Server, Kernel, Workgroup, Windows domain, ports open, services open
#Emphasize following ports in this order, with tips:
#21 - FTP, 22 - SSH, 25 - SMTP, 69 - UDP - TFTP, 110 - POP3, 111 - rpcbind, 135 - MSRPC, 143 - IMAP, 139/445 - SMB, 161/162 - SNMP, 554 - RTSP, 1521 - Oracle, 2049 - NFS, 2100 - Oracle XML DB, 3306 - MySQL, 3339 - Oracle Web Interface, 80 - Web Server, 443 - HTTPS


def main(): #Everything that you want the main function to do
    opening()
    target = targetip()
    while True:
        if ip_checker(target) == True:
            break
        else:
            print ("Sorry, please enter a valid IP address. \n")
            target = targetip()
    nmap_scan_synscan()
    nmap_scan_allports()
    nmap_scan_serviceversion()
    nmap_scan_udp()
    nmap_scan_tcp()
    if ():#If port 80, a web server, is open, then run nikto and dirbuster scan
        print ("\nPort 80 is open, running nikto and dirbuster scans.")
        nikto_scan()
        dirb_scan()
    print ("\nFinished.")


if __name__=='__main__':
    main()
