
import random
import ifaddr
import time, os, subprocess, sys
import socket

def add_dummy_address():

    please_add_list_for_me = True
    mac_address = get_interface().get("Physicaladdress")

    user_response = ask_add_or_delete()
    if user_response == "add":
        please_add_list_for_me = True
    elif user_response == "delete":
        please_add_list_for_me = False

    if please_add_list_for_me == False:
        target = delete_all_or()
        delete_address(target)
    else:
        adding_list = how_many_blacklist()
        if adding_list == "0":
            print("Skip adding blacklist")
        else:
            with_client = include_client()
            if with_client == True:
                add_position = client_first_or_last()
            else:
                add_position = "none"
            generate_address(adding_list,"blacklist",with_client,mac_address,add_position)

        adding_list = how_many_whitelist()
        if adding_list == "0":
            print("Skip adding whitelist")
        else:
            with_client = include_client()
            if with_client == True:
                add_position = client_first_or_last()
            else:
                add_position = "none"
            generate_address(adding_list,"whitelist",with_client,mac_address,add_position)
    toggle_wifi_restart()


#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def generate_address(adding_list,check_for,with_client,mac_address,add_position):
    if with_client == True and add_position == "last":
        print("Add dummy MAC addresses with the device MAC last")
        for i in range(int(adding_list)-1):
            mac = [ 0x1a, 0x2b, 0x3c,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff) ]
            dummy_mac_address = ':'.join(map(lambda x: "%02x" % x, mac))
            if "blacklist" in check_for:
                shell("dx -c wlan.blacklist -t " + str(i) + " TestBlackList" + str(i) + "," + dummy_mac_address)
                blacklist = shell("dx wlan.blacklist -t " + str(i))
                if "No records" in blacklist:
                    print("Failed to add dummy mac address")
            if "whitelist" in check_for:
                shell("dx -c wlan.whitelist -t " + str(i) + " TestWhiteList" + str(i) + "," + dummy_mac_address)
                whitelist = shell("dx wlan.whitelist -t " + str(i))
                if "No records" in whitelist:
                    print("Failed to add dummy mac address")
        if "blacklist" in check_for:
            shell("dx -c wlan.blacklist -t " + str(int(adding_list)-1) + " Device_MAC," + mac_address)
            blacklist = shell("dx wlan.blacklist -t " + str(int(adding_list)-1))
            if "No records" in blacklist:
                print("Failed to add dummy mac address")
        if "whitelist" in check_for:
            shell("dx -c wlan.whitelist -t " + str(int(adding_list)-1) + " Device_MAC," + mac_address)
            whitelist = shell("dx wlan.whitelist -t " + str(int(adding_list)-1))
            if "No records" in whitelist:
                print("Failed to add dummy mac address")

    elif with_client == True and add_position == "first":
        print("Add dummy MAC addresses with the device MAC first")
        for i in range(1,int(adding_list)):
            mac = [ 0x1a, 0x2b, 0x3c,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff) ]
            dummy_mac_address = ':'.join(map(lambda x: "%02x" % x, mac))
            if "blacklist" in check_for:
                shell("dx -c wlan.blacklist -t " + str(i) + " TestBlackList" + str(i) + "," + dummy_mac_address)
                blacklist = shell("dx wlan.blacklist -t " + str(i))
                if "No records" in blacklist:
                    print("Failed to add dummy mac address")
            if "whitelist" in check_for:
                shell("dx -c wlan.whitelist -t " + str(i) + " TestWhiteList" + str(i) + "," + dummy_mac_address)
                whitelist = shell("dx wlan.whitelist -t " + str(i))
                if "No records" in whitelist:
                    print("Failed to add dummy mac address")
        if "blacklist" in check_for:
            shell("dx -c wlan.blacklist -t 0 Device_MAC," + mac_address)
            blacklist = shell("dx wlan.blacklist -t 0")
            if "No records" in blacklist:
                print("Failed to add dummy mac address")
        if "whitelist" in check_for:
            shell("dx -c wlan.whitelist -t 0 Device_MAC," + mac_address)
            whitelist = shell("dx wlan.whitelist -t 0")
            if "No records" in whitelist:
                print("Failed to add dummy mac address")
    else:
        print("Add dummy MAC addresses")
        for i in range(int(adding_list)):
            mac = [ 0x1a, 0x2b, 0x3c,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff) ]
            dummy_mac_address = ':'.join(map(lambda x: "%02x" % x, mac))
            if "blacklist" in check_for:
                shell("dx -c wlan.blacklist -t " + str(i) + " TestBlackList" + str(i) + "," + dummy_mac_address)
                blacklist = shell("dx wlan.blacklist -t " + str(i))
                if "No records" in blacklist:
                    print("Failed to add dummy mac address")
                else:
                    print(blacklist)
            if "whitelist" in check_for:
                shell("dx -c wlan.whitelist -t " + str(i) + " TestWhiteList" + str(i) + "," + dummy_mac_address)
                whitelist = shell("dx wlan.whitelist -t " + str(i))
                if "No records" in whitelist:
                    print("Failed to add dummy mac address")
                else:
                    print(whitelist)

def ask_add_or_delete():
    while True:
        options = ["add","delete"]
        user_response = raw_input("Do you want to add or delete all list? (add/delete): ")
        if str(user_response) not in options:
            print("wrong answer, try again :)")
        else:
            break
    return str(user_response)

def delete_all_or():
    while True:
        options = ["all","blacklist","whitelist"]
        user_response = raw_input("Which list to you want to delete? (all/blacklist/whitelist): ")
        if str(user_response) not in options:
            print("wrong answer, try again :)")
        else:
            break
    return str(user_response)

def how_many_blacklist():
    options=[]
    max_amount = int(get_max_client_number())
    print("Maximum allowed list is " + str(max_amount))
    for i in range(0, max_amount+1):
        option = i
        options.append(option)
    options=''.join(map(str,options))
    while True:
        user_response = raw_input("How many address do you want to add to blacklist? (up to " + str(max_amount) + "): ")
        if str(user_response) not in options:
            print("wrong answer, try again :)")
        else:
            break
    return str(user_response)

def how_many_whitelist():
    options=[]
    max_amount = int(get_max_client_number())
    print("Maximum allowed list is " + str(max_amount))
    for i in range(0, max_amount+1):
        option = i
        options.append(option)
    options=''.join(map(str,options))
    while True:
        user_response = raw_input("How many address do you want to add to whitelist? (up to " + str(max_amount) + "): ")
        if str(user_response) not in options:
            print("wrong answer, try again :)")
        else:
            break
    return str(user_response)

def include_client():
    while True:
        options = ["yes","no"]
        user_response = raw_input("Do you want to add your own MAC address? (yes/no): ")
        if str(user_response) not in options:
            print("wrong answer, try again :)")
        else:
            break
    if str(user_response) == "yes":
        with_client = True
    elif str(user_response) == "no":
        with_client = False

    return with_client

def client_first_or_last():
    while True:
        options = ["first","last"]
        user_response = raw_input("Do you want to add your MAC address first of last? (first/last): ")
        if str(user_response) not in options:
            print("wrong answer, try again :)")
        else:
            break

    if str(user_response) == "first":
        add_position = "first"
    elif str(user_response) == "last":
        add_position = "last"

    return add_position

def delete_address(target):
    if target == "all":
        print("Deleting all lists")
        shell("dx wlan.blacklist -d -z -y")
        shell("dx wlan.whitelist -d -z -y")
    elif target == "blacklist":
        print("Deleting blacklist")
        shell("dx wlan.blacklist -d -z -y")
    elif target == "whitelist":
        print("Deleting whitelist")
        shell("dx wlan.whitelist -d -z -y")

def get_interface():
    resp = subprocess.check_output("netsh wlan show interfaces")
    resp = resp.split('\r\n')
    resp_n = []
    tmp2 = ""
    for i in resp:
        if i:
            tmp = i.split(":") 
            tmp[0] = tmp[0].replace(" ", "").replace("(Mbps)", "")
            if tmp[0] == "Physicaladdress" or tmp[0] == "BSSID":
                mac = ""
                for i in range (1, len(tmp)):
                    mac = mac + tmp[i] + ":"
                tmp[1] = mac[1:-1]
                resp_n.append(tmp)
            elif tmp[0] == "SoftwareOn" or tmp[0] == "SoftwareOff":
                tmp2 = tmp[0]
            else:
                tmp[1] = tmp[1][1:]
                resp_n.append(tmp)

    wifi_interface = {}
    for item in resp_n:
        if item[0] == "Radiostatus":
            item[1] = item[1],tmp2
        wifi_interface[item[0]] = item[1]
    return wifi_interface

def shell(*args):

        cmd = " ".join(args)
        print("adb shell %s" % cmd)
        output = subprocess.check_output(["adb", "shell", cmd])

        if output == "":
            return None
        else:
            if "dx" in cmd:
                output = output.split("\r\r\n")
                if "-A" in cmd:
                    return output
                else:
                    return output[0]
            else:
                output = output.replace("\r\r\n", "\r\n")
                return output

def toggle_wifi_restart():
    print("Restarting wifi...")
    shell("dx -c wlan.wifirestart 1")
    time.sleep(5)
    wifi_state = shell("dx wlan.wifistate")
    timer = 0
    while(wifi_state != "Started"):
        wifi_state = shell("dx wlan.wifistate")
        timer += 1
        if timer > 2: # this case is for M1, since it takes longer than M5 to restart
            time.sleep(5)
        if timer == 10:
            print("timeout!")
            break
    if wifi_state == "Started":
        print("Wifi restart successfully")
    elif wifi_state == "Stopped":
        print("Wifi didn't restart")

def get_max_client_number():
    # check device max clients number
    max_clients_number = shell("dx wlan.blacklist")
    max_clients_number = "".join(i for i in max_clients_number if i.isdigit())
    return max_clients_number

if __name__ == '__main__':
    add_dummy_address()
