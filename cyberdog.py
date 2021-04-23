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

def opening(): #Opening function with introduction of the script along with the various scans used
    print ("       /^-^\        _____           _                     _____                      /^-----^\ \n      / o o \      / ____|         | |                   |  __ \                     V  o o  V \n     /   Y   \    | |       _   _  | |__     ___   _ __  | |  | |   ___     __ _      |  Y  | \n     V \ v / V    | |      | | | | | '_ \   / _ \ | '__| | |  | |  / _ \   / _` |      \ Q / \n       / - \      | |____  | |_| | | |_) | |  __/ | |    | |__| | | (_) | | (_| |      / - \ \n      /    |       \_____|  \__, | |_.__/   \___| |_|    |_____/   \___/   \__, |      |    \ \n(    /     |                 __/ |                                          __/ |      |     \     ) \n ===/___) ||                |___/                                          |___/       || (___\==== \n")
    print ("Welcome to Cyberdog! This is a box enumeration tool that will utilize the following scans: \n 1) nmap \n -TCP port scan \n -UDP port scan \n -OS detection \n 2) nikto \n 3) DirBuster (If a web server is running) \n")
    print ("A report will be generated in the same directory as this script, find it at './report.txt'")
    print ("\033[31mWarning: Previous reports will be overwritten! \033[0m\n")

def targetip(): #Input for target IP
    target = input("What IP would you like to scan? ")
    return target

def ip_checker(ip): #Run against IP address to check for validity
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

def waiting(scan): #Lets user know the scan is running
    return ('\033[96m''Please wait... a(n)' + scan + ' scan is running...' '\033[0m''\n')

def nmap_scan(ip):
    print (waiting(nmap))
    cmd = 'nmap -sV' + ip
    output = subprocess.check_output(cmd, shell=True)
    change_output = str(output)
    x = change_output.replace('\\n','\n')
    return x

def port_scan(nmap_file):
    print (waiting(port_scan))
    for line in nmap_file.splitlines():
        port_types = ['tcp', 'udp', 'PORT']
        open_ports = any(ele in line for ele in port_types)
        if open_ports == True:
            print (line)

def another_scan():

def another2_scan():

def another3_scan():

def report

def main(): #Everything that you want the main function to do
    opening()
    target = targetip()
    while True:
        if ip_checker(target) == True:
            break
        else:
            print ("Sorry, please enter a valid IP address. \n")
            target = targetip()
    nmap_scan()
    port_scan()



if __name__=='__main__':
    main()
