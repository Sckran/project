import hashlib
from netfilterqueue import NetfilterQueue
from scapy.all import *
import json
import os
from web3 import Web3

##############################################################
##                      Blockchain Info                     ##
blockchainNetworkIP = "HTTP://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(blockchainNetworkIP))
jsonArray = '[{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"Activate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_addr","type":"address"},{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_hash_id","type":"string"},{"internalType":"string","name":"_ip","type":"string"},{"internalType":"string","name":"_mac","type":"string"}],"name":"add_device","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_hash_id","type":"string"}],"name":"authFunc","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"deActivate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_Name","type":"string"}],"name":"displayByName","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"_addr","type":"address"}],"name":"displayInfo","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"}]'
abi = json.loads(jsonArray)
contractAddress = "0xD4032A5DB73FA760492631b8201a06AF8747B16D"
address = web3.toChecksumAddress(contractAddress)
contract = web3.eth.contract(address=address, abi=abi)
web3.eth.defaultAccount = web3.eth.accounts[0] #choose transaction account
##                                                        ##
############################################################


def addDevice(ip_src, mac_src):
    deviceCount = contract.functions.getCount().call()
    iplist = ""
    deviceID = ""
    deviceName = ""
    addr = ""
    with open("ip_list.txt","r") as fr:
        iplist = fr.read()
        with open("ip_list.txt","w") as fw:
            while True:
                if ip_src not in iplist:
                    if len(iplist) == 0: 
                        iplist = iplist + ip_src 
                    else: 
                        iplist = iplist + "," + ip_src
                    fw.write(iplist)
                    addr = web3.eth.accounts[deviceCount+1] # return the new address
                    deviceName = input("Enter device Name: ") # get device name
                    deviceID = hashlib.md5((ip_src + mac_src + "saltValue").encode('utf-8')).hexdigest()# calculate the id
                    tx_hash = contract.functions.add_device(addr, deviceName, deviceID, ip_src, mac_src).transact() # store the id to the blockchain
                    web3.eth.waitForTransactionReceipt(tx_hash)
                    print ("\n----------------\n<++ [ADDED!] ++>\n----------------\n")
                    display_by_name(deviceName)
                    reboot = input(" <++[NOTE!] ++>\nYou must reboot the BlockChanger in order to allow new settings to take action \nDo you want to reboot now? y/n: ")
                    if reboot == "y": os.system("sudo reboot")
                    #packet.drop()
                    return
                else: 
                    print(f"The connected device [{ip_src}] [{mac_src}] is already exists!")
                    return
                    
def display_by_name(name):
    info = contract.functions.displayByName(name).call()
    deviceCount = contract.functions.getCount().call()    
    if info[1] == "":
        print("\n[*] This device does not exists!\n")
    else:
        if info[5] == 0: state = "Active"
        else: state = "Down"
        print(f"""Device {deviceCount}:
        Address: {info[0]}
        Name: {info[1]}
        ID: {info[2]}
        IP: {info[3]}
        MAC: {info[4]}
        State: {state}""")

def displayAll():
    deviceCount = contract.functions.getCount().call()
    #accounts = contract.functions.signed_addresses().call() 
    accounts = web3.eth.accounts
    if deviceCount == 0: print ("\n-----------------\nEmpty Blockchain!\n-----------------")
    count = 1
    for i in accounts[1:deviceCount+1]:  # for loop to display addresses from device mapping in the smart contract.
        info = contract.functions.displayInfo(i).call()
        if info[1] == "":
            print("\n[*] This device does not exists!\n")
        else:
            if info[5] == 0: state = "Active"
            else: state = "Down"
            print(f"""Device {deviceCount}:
            Address: {info[0]}
            Name: {info[1]}
            ID: {info[2]}
            IP: {info[3]}
            MAC: {info[4]}
            State: {state}""")
        count += 1
    print(f"Total number of devices: {deviceCount}")

dontRepeatIP =  []
def detect_IP_and_mac(packet):
     # store repeated the incoming ips
    pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string
    if IP in pkt and pkt[IP].src not in dontRepeatIP:
        ip_src = pkt[IP].src
        #mac_src = packet.get_hw() #function by nfqueue gives hex data
        mac_src = getmacbyip(str(ip_src)) #funtion by scapy
        dontRepeatIP.append(ip_src)
        print ("\n[NOTE] the traffic on the network will be on hold while you are running this function!")
        print ("[*] press Ctrl + C to exit this function!")
        print ("[*] waiting for device to be connected!")
        print ("-----------------------------------------------------------------------------------------")
        print("\n****************************************************************")
        print (f"[*] Device Detected!: [{str(ip_src)}] [{mac_src}]")
        print("****************************************************************\n")
        choice = input(f"\n[*] Do you want to add the device to the Blockchain? y/n: ")
        print("\n")
        if choice == "y":
            addDevice(ip_src, mac_src)
        else: return
        #packet.drop()
        #print("[*] exiting...")  
        #exit(0)
    else:
        print("[*] looking for another device...")
    # add "else" here to throw an error if the packet is not an IP packet.
    

def detect_device():
    netmask = getNetmask()
    os.system("sudo iptables -F")
    os.system(f"sudo iptables -I INPUT -s {netmask} -m state --state NEW,RELATED,ESTABLISHED -j NFQUEUE --queue-num 2")
    addnfqueue = NetfilterQueue()
    addnfqueue.bind(2, detect_IP_and_mac)
    try:
        addnfqueue.run()
        
    except KeyboardInterrupt:
        os.system("sudo iptables -F")
        addnfqueue.unbind()
        print("\n[*] exiting...")

def activate_device():
    print("\n[Note] if you do not know the exact name of the meant device, you can get it from display all devices ")
    name = input("Enter device name: ")
    contract.functions.Activate(name).transact()
    info = contract.functions.displayByName(name).call()
    if info[5] == 0:
        print (f"\n[*] {name} is activated!")
    else: print("[*] device is not activated!\n[*] The device name is not exists or entered wrong!")

def deactivate_device():
    print("\n[Note] if you do not know the id of the meant device, you can get it from display all devices")    
    name = input("Enter device name: ")
    contract.functions.deActivate(name).transact()
    info = contract.functions.displayByName(name).call()
    if info[5] == 1:
        print (f"\n[*] {name} is deactivated!")
    else: print("[*] device is not deactivated!\nSomething went wrong!")

# code to get the host ip address and turn the last oct to 0 with netmask
def getNetmask(): #change the interface to the appropriate one 
    #interface = "eth0"
    IPAddress = os.popen('ip addr show wlan0  | grep "\<inet\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
    netmask = IPAddress
    netmask = netmask[:netmask.rfind('.')+1] + '0' + "/24"
    #print (f"\n[*] network mask: {netmask}")
    return netmask

def _exit():
    os.system("sudo iptables -F")
    print("Exiting...")
    exit(0)

def main():
    choice = ""
    while choice != 6:
        print("\n-----------------------------\n<++ BlockChanger Settings ++>\n-----------------------------")
        print("[1] Add new device\n[2] Activate device\n[3] Deactivate device\n[4] Display device information by name\n[5] Display all devices information\n[6] Exit.")
        choice = int(input("\n[*] Choose number from the menu to proceed: "))
        if choice == 1:
            detect_device()
        elif choice == 2:
            activate_device()
        elif choice == 3:
            deactivate_device()
        elif choice == 4:
            deviceName = input("enter device name: ")
            display_by_name(deviceName)
        elif choice == 5:
             displayAll()
        elif choice == 6:
            _exit()
        else: print("Wrong entry!")


