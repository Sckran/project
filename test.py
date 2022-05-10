from sre_parse import State
from flask import *
from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify
from datetime import timedelta
#-----------------------SECRET KEY-------------------------
app = Flask(__name__)
app.secret_key = "M7NK"
app.permanent_session_lifetime = timedelta(days=5)
#------------------------------------------------------------
##############################################################
##                      Blockchain Info                     ##
blockchainNetworkIP = "HTTP://127.0.0.1:7545"
#web3 = Web3(Web3.HTTPProvider(blockchainNetworkIP))
jsonArray = '[{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"Activate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_addr","type":"address"},{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_hash_id","type":"string"},{"internalType":"string","name":"_ip","type":"string"},{"internalType":"string","name":"_mac","type":"string"}],"name":"add_device","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_hash_id","type":"string"}],"name":"authFunc","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"deActivate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_Name","type":"string"}],"name":"displayByName","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"_addr","type":"address"}],"name":"displayInfo","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"}]'
abi = json.loads(jsonArray)
contractAddress = "0xD4032A5DB73FA760492631b8201a06AF8747B16D"
#address = web3.toChecksumAddress(contractAddress)
#contract = web3.eth.contract(address=address, abi=abi)
#web3.eth.defaultAccount = web3.eth.accounts[0] #choose transaction account
##                                                        ##
############################################################

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        session.permanent = True
        user= request.form["user"]
        session["user"] = user
        flash(f"Login sucess, {user}") #POP UP  
        return redirect(url_for("user"))
    else:
        if "user" in session:
            flash("already logged 7ge")
            return redirect(url_for("user"))
        return render_template("login.html")

@app.route("/user") 
def user():
    if "user" in session:
        user = session["user"]
        return render_template("user.html", user=user)
    
    else:
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    if "user" in session:
        user = session["user"]
        flash(f"logging out, {user}", "info")
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/add_device", methods =["POST", "GET"])
def addDevice():
    if request.method == "POST":
        
        with open("ip_list.txt","r") as fr:
                iplist = fr.read()
                with open("ip_list.txt","w") as fw:
                    new_ip = request.form.get("new_ip")
                    if new_ip not in iplist: 
                        if len(iplist) == 0 : iplist = iplist + new_ip
                        else: iplist = iplist + "," + new_ip
                        flash("The IP: "+ new_ip +" was added successfully!")
                        return redirect(request.url)
                    else:
                        flash("The enterd IP exist!")
                        return redirect(request.url)
    else:
        return render_template("add_device.html")
        
@app.route("/activate_device", methods=["POST","GET"])
def activate_device():
    if request.method == "POST":
        
        name = request.form.get("device_name")
        return redirect(request.url)

        #contract.functions.Activate(name).transact()
        #info = contract.functions.displayByName(name).call()
        # if info[5] == 0:
        #     flash ("[*]"+ name +"is activated!")
        # else: flash ("[*] device is not activated!\n[*] The device name does not exist or entered wrong!")        
    else:
        return render_template("/activate_device.html")

@app.route("/deactivate_device", methods=["POST","GET"])
def deactivate_device():
    if request.method == "POST":
        # print("\n[Note] if you do not know the id of the meant device, you can get it from display all devices")    
        name = request.form.get("device_name")
        # contract.functions.deActivate(name).transact()
        # info = contract.functions.displayByName(name).call()
        # if info[5] == 1:
            # flash (" "+name+" is deactivated!")
        # else: flash("device is not deactivated!\nSomething went wrong!")
        return redirect(request.url)
    else: return render_template("/deactivate_device.html")

@app.route("/displayall", methods=["POST","GET"]) 
def displayAll():
    if request.method == "POST":
                
        # deviceCount = contract.functions.getCount().call()
        #accounts = contract.functions.signed_addresses().call() 
        # accounts = web3.eth.accounts
        # if deviceCount == 0: flash ("Empty Blockchain!")
        # count = 1
        # for i in accounts[1:deviceCount+1]:  # for loop to display addresses from device mapping in the smart contract.
            # info = contract.functions.displayInfo(i).call()
            # if info[1] == "":
                flash("This device does not exists!")
            # else:
                # if info[5] == 0: state = "Active"
                # else: state = "Down"
                ("Device" + deviceCount+ ":"+
                "Address:"+ info[0]+
                "Name:" + info[1] +
                "ID:" +info[2] +
                "IP:" +info[3]+
                "MAC:"  +info[4]+
                "State:" +state)
            # count += 1
        # dontRepeatIP =  []
        # flash("Total number of devices:" +deviceCount )
    else: return render_template("/displayall.html")               

@app.route("/settings", methods=["POST","GET"])
def settings():
        if request.method == "GET":
            return render_template("settings.html")

@app.route("/pihole", methods=["POST","GET"])
def pihole():
        if request.method == "GET":
            return render_template("pihole.html")
    
@app.route("/homeassis", methods=["POST","GET"])
def homeassis():
        if request.method == "GET":
            return render_template("homeassis.html")
    


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







if __name__=="__main__":
    app.run(debug=True)


