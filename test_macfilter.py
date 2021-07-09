
import os
import subprocess
import time
import sys
import pytest
import logging
import random
import ifaddr


def test_macfilter_func(dut,logger):

    test_result = [
                    True, "Case 1: Access control disabled, client can to connect to wifi, ping pass",
                    True, "Case 2: Blacklist, client is blacklisted, client cannot connect to wifi, ping fail",
                    True, "Case 3: Blacklist, no entry in blacklist, client can connect to wifi, ping pass",
                    True, "Case 4: Blacklist, entry without client, client can connect to wifi, ping pass",
                    True, "Case 5: Whitelist, client is whitelisted, client can connect to wifi, ping pass",
                    True, "Case 6: Whitelist, no entry in whitelist, client can connect to wifi, ping pass",
                    True, "Case 7: Whitelist, entry without client, client cannot connect to wifi, ping fail"
                    ]

    setup_result = [
                    True, "Saving initial state",
                    True, "Disable USB interface",
                    True, "Restoring initial state",
                    True, "Re-enable USB interface"
                    ]

    # gather device informations
    sleep_time = 2
    ssid = dut.adb.shell("dx wlan.ssid")
    passphrase = dut.adb.shell("dx wlan.passphrase")
    guest_ssid = dut.adb.shell("dx guest.guestSSID")
    guest_passphrase = dut.adb.shell("dx guest.guestpassphrase")
    mac_address = dut.wifi.get_interface().get("Physicaladdress")

    # check swiabort crash file
    check_swiabort(dut,logger,"start")

    adapters = ifaddr.get_adapters()
    ethernet_name = "Ethernet"
    for adapter in adapters:
        for ip in adapter.ips:
            if 'Ethernet' in ip.nice_name and '192.168.1.4' in ip.ip:
                ethernet_name = "\"%s\"" % ip.nice_name
    logger.info("USB Interface: " + ethernet_name)
    temp = "".join(i for i in ethernet_name if i.isdigit())
    if temp == "":
        logger.info("This test started with USB interface disabled")
        no_usb_interface = True
    else:
        no_usb_interface = False
    
    max_clients_number = get_max_client_number(dut,logger)
    initial_accesscontrol,saved_blacklist,saved_whitelist,setup_result = check_initial_state(dut,logger,max_clients_number,setup_result)

    case = 0
    disconnect_from_wifi(dut,logger)

    if no_usb_interface == True:
        setup_result[3] += " - Skipped because test started without USB interface enabled" 
    else:
        setup_result = usb_interface(dut,logger,ethernet_name,"disable",setup_result)

    clear_list(dut,logger,"all",test_result,case)
    
    

    logger.info("CASE 1: Access control disabled, client can connect to wifi and ping pass")
    case = 1
    dut.adb.shell("dx -c wlan.accesscontrol None")
    test_result = check_list(dut,logger,"accessNone",test_result,case)
    if test_result[0] == False:
        logger.info("Skipping test case 1")
        logger.info(test_result[1])
    else:
        test_result = toggle_wifi_restart(dut,logger,test_result,case)
        if test_result[0] == False:
            logger.info("Skipping test case 1")
            logger.info(test_result[1])
        else:
            wifi_ip,test_result = connect_to_wifi(dut,logger,ssid,True,"accessNone",test_result,case)
            if test_result[0] == False:
                logger.info("Skipping test case 1")
                logger.info(test_result[1])
            else:
                test_result = ping_test(dut,logger,wifi_ip,True,test_result,case)
                if test_result[0] == False:
                    logger.info(test_result[1])
    disconnect_from_wifi(dut,logger)

    logger.info("CASE 2: Blacklist enabled, client is blacklisted, client cannot to connect to wifi and ping fail")
    case = 2
    dut.adb.shell("dx -c wlan.accesscontrol Black")
    test_result = check_list(dut,logger,"accessBlack",test_result,case)
    if test_result[2] == False:
        logger.info("Skipping test case 2")
        logger.info(test_result[3])
    else:
        dut.adb.shell("dx -c wlan.blacklist -t 0 Device_MAC," + mac_address)
        test_result = check_list(dut,logger,"blacklist",test_result,case)
        if test_result[2] == False:
            logger.info("Skipping test case 2")
            logger.info(test_result[3])
        else:
            test_result = toggle_wifi_restart(dut,logger,test_result,case)
            if test_result[2] == False:
                logger.info("Skipping test case 2")
                logger.info(test_result[3])
            else:
                wifi_ip,test_result = connect_to_wifi(dut,logger,ssid,False,"blacklist",test_result,case)
                if test_result[2] == False:
                    logger.info("Skipping test case 2")
                    logger.info(test_result[3])
                else:
                    test_result = ping_test(dut,logger,wifi_ip,False,test_result,case)
                    if test_result[2] == False:
                        logger.info(test_result[3])
    time.sleep(sleep_time)

    logger.info("CASE 3: Blacklist enabled, no entry in blacklist, client can connect to wifi and ping pass")
    case = 3
    test_result = clear_list(dut,logger,"onlyblacklist",test_result,case)
    if test_result[4] == False:
        logger.info("Skipping test case 3")
        logger.info(test_result[5])
    else:
        test_result = toggle_wifi_restart(dut,logger,test_result,case)
        if test_result[4] == False:
            logger.info("Skipping test case 3")
            logger.info(test_result[5])
        else:
            wifi_ip,test_result = connect_to_wifi(dut,logger,ssid,True,"noblacklist",test_result,case)
            if test_result[4] == False:
                logger.info("Skipping test case 3")
                logger.info(test_result[5])
            else:
                test_result = ping_test(dut,logger,wifi_ip,True,test_result,case)
                if test_result[4] == False:
                    logger.info(test_result[5])
    disconnect_from_wifi(dut,logger)
    time.sleep(sleep_time)

    logger.info("CASE 4: Blacklist enabled, entry without client, client can connect to wifi and ping pass")
    case = 4
    test_result = clear_list(dut,logger,"onlyblacklist",test_result,case)
    if test_result[6] == False:
        logger.info("Skipping test case 4")
        logger.info(test_result[7])
    else:
        test_result = add_dummy_mac_address(dut,logger,mac_address,1,False,"blacklist",test_result,case)
        if test_result[6] == False:
            logger.info("Skipping test case 4")
            logger.info(test_result[7])
        else:
            test_result = toggle_wifi_restart(dut,logger,test_result,case)
            if test_result[6] == False:
                logger.info("Skipping test case 4")
                logger.info(test_result[7])
            else:
                wifi_ip,test_result = connect_to_wifi(dut,logger,ssid,True,"noblacklist",test_result,case)
                if test_result[6] == False:
                    logger.info("Skipping test case 4")
                    logger.info(test_result[7])
                else:
                    test_result = ping_test(dut,logger,wifi_ip,True,test_result,case)
                    if test_result[6] == False:
                        logger.info(test_result[7])
    disconnect_from_wifi(dut,logger)
    time.sleep(sleep_time)

    case = 0
    clear_list(dut,logger,"onlyblacklist",test_result,case)

    logger.info("CASE 5: Whitelist enabled, client is whitelisted, client can connect to wifi and ping pass")
    case = 5
    dut.adb.shell("dx -c wlan.accesscontrol White")
    test_result = check_list(dut,logger,"accessWhite",test_result,case)
    if test_result[8] == False:
        logger.info("Skipping test case 5")
        logger.info(test_result[9])
    else:
        dut.adb.shell("dx -c wlan.whitelist -t 0 Device_MAC," + mac_address)
        test_result = check_list(dut,logger,"whitelist",test_result,case)
        if test_result[8] == False:
            logger.info("Skipping test case 5")
            logger.info(test_result[9])
        else:
            test_result = toggle_wifi_restart(dut,logger,test_result,case)
            if test_result[8] == False:
                logger.info("Skipping test case 5")
                logger.info(test_result[9])
            else:
                wifi_ip,test_result = connect_to_wifi(dut,logger,ssid,True,"whitelist",test_result,case)
                if test_result[8] == False:
                    logger.info("Skipping test case 5")
                    logger.info(test_result[9])
                else:
                    test_result = ping_test(dut,logger,wifi_ip,True,test_result,case)
                    if test_result[8] == False:
                        logger.info(test_result[9])

    disconnect_from_wifi(dut,logger)
    time.sleep(sleep_time)

    logger.info("CASE 6: Whitelist enabled, no entry in whitelist, client can connect to wifi and ping pass")
    case = 6 
    test_result = clear_list(dut,logger,"onlywhitelist",test_result,case)
    if test_result[10] == False:
        logger.info("Skipping test case 5")
        logger.info(test_result[11])
    else:
        test_result = toggle_wifi_restart(dut,logger,test_result,case)
        if test_result[10] == False:
            logger.info("Skipping test case 5")
            logger.info(test_result[11])
        else:
            wifi_ip,test_result = connect_to_wifi(dut,logger,ssid,True,"nowhitelist",test_result,case)
            if test_result[10] == False:
                logger.info("Skipping test case 5")
                logger.info(test_result[11])
            else:
                test_result = ping_test(dut,logger,wifi_ip,True,test_result,case)
                if test_result[10] == False:
                    logger.info(test_result[11])

    disconnect_from_wifi(dut,logger)
    time.sleep(sleep_time)

    logger.info("CASE 7: Whitelist enabled, entry without client, client cannot connect to wifi and ping fail")
    case = 7
    test_result = clear_list(dut,logger,"onlywhitelist",test_result,case)
    if test_result[12] == False:
        logger.info("Skipping test case 5")
        logger.info(test_result[13])
    else:
        test_result = add_dummy_mac_address(dut,logger,mac_address,1,False,"whitelist",test_result,case)
        if test_result[12] == False:
            logger.info("Skipping test case 5")
            logger.info(test_result[13])
        else:
            test_result = toggle_wifi_restart(dut,logger,test_result,case)
            if test_result[12] == False:
                logger.info("Skipping test case 5")
                logger.info(test_result[13])
            else:
                wifi_ip,test_result = connect_to_wifi(dut,logger,ssid,False,"maxwhitelist",test_result,case)
                if test_result[12] == False:
                    logger.info("Skipping test case 5")
                    logger.info(test_result[13])
                else:
                    test_result = ping_test(dut,logger,wifi_ip,False,test_result,case)
                    if test_result[12] == False:
                        logger.info(test_result[13])
    time.sleep(sleep_time)

    case = 0
    clear_list(dut,logger,"onlywhitelist",test_result,case)
	
    # restoring initial states
    setup_result = restoring_initial_state(dut,logger,initial_accesscontrol,saved_blacklist,saved_whitelist,setup_result)
    toggle_wifi_restart(dut,logger,test_result,case)
    if no_usb_interface == True:
        setup_result[7] += " - Skipped because test started without USB interface enabled" 
    else:
        setup_result = usb_interface(dut,logger,ethernet_name,"enable",setup_result)
    
    # check swiabort crash file
    swiapp_found,directory = check_swiabort(dut,logger,"end")

    logger.info("============================================== Test Result ============================================")


    for i in range(0, len(setup_result),2):
        if setup_result[i] == True:
            logger.info("Setup case passed - " + setup_result[i+1])
        else:
            logger.info("Setup case failed - " + setup_result[i+1])

    test = ""
    for i in range(0, len(test_result),2):
        if test_result[i] == True:
            logger.info("Test case passed - " + test_result[i+1])
        else:
            logger.info("Test case failed - " + test_result[i+1])
            test = "failed"

    if swiapp_found == True:
        logger.info("Swiabort file found in " + directory)
    else:
        logger.info("No swiabort file found in " + directory)

    if test == "failed":
        pytest.fail("At least 1 test case failed")
    else:
        logger.info("All test case passed")
   
#++++++++++++++++++++++ below are helper functions for the script +++++++++++++++++++++++++++++
def connect_to_wifi(dut,logger,ssid,connect_expect,check_for,test_result,case):
    # This function will connect to wifi and check for the correct response
    # if it should be able to connect, but failed to do so, it will retry upto 5 times
    # if it shouldn't be be able to connect, but it did connect, test case will failed
    # if it connects to wifi but there's no IP, test case will failed
    if connect_expect == True:
        max_retry = 5
    else:
        max_retry = 1
    count = 0
    i,j = check_case(case)
    while count < max_retry:
        logger.info("Connecting to " + ssid + "...")
        connect_response = subprocess.check_output("netsh wlan connect " + ssid)
        time.sleep(20)
        logger.info(connect_response)
        wifi_ip = dut.wifi.get_wifi_ip()

        if check_for == "blacklist": #case 2
            # Device shouldn't be able to connect to wifi
            if ssid in subprocess.check_output("netsh wlan show interfaces"):
                logger.info("Successfully connected to " + ssid)
                test_result[i] = False
                test_result[j] += " - Blacklisted client is able to connect to wifi"
                logger.error("Blacklisted client is able to connect to wifi")
            else:
                count += 1
                logger.info("Blacklisted device blocked successfully")

        elif check_for == "whitelist": #case 5
            # Device should be able to connect to wifi"
            if ssid in subprocess.check_output("netsh wlan show interfaces"):
                logger.info("Successfully connected to " + ssid)
                logger.info("Whitelisted device connect successfully")
                if "192.168" not in wifi_ip:
                    test_result[i] = False
                    test_result[j] += " - Client is connected to wifi, but there's no IP"
                break
            else:
                count += 1
                logger.warn('Failed to connect %s times to %s' % (count, ssid))
                if count == max_retry:
                    test_result[i] = False
                    test_result[j] += " - Whitelisted device is unable to connect to wifi"
                    logger.error("Whitelisted device is unable to connect to wifi")

        elif check_for == "noblacklist": #case 3 and 4
            # Device should be able to connect to wifi
            if ssid in subprocess.check_output("netsh wlan show interfaces"):
                logger.info("Successfully connected to " + ssid)
                if "192.168" not in wifi_ip:
                    test_result[i] = False
                    test_result[j] += " - Client is connected to wifi, but there's no IP"
                break
            else:
                count += 1
                logger.warn('Failed to connect %s times to %s' % (count, ssid))
                if count == max_retry:
                    test_result[i] = False
                    test_result[j] += " - Client is unable to connect to wifi"
                    logger.error("Client is unable to connect to wifi")

        elif check_for == "nowhitelist": #case 6
            # Device should be able to connect to wifi
            if ssid in subprocess.check_output("netsh wlan show interfaces"):
                logger.info("Successfully connected to " + ssid)
                if "192.168" not in wifi_ip:
                    test_result[i] = False
                    test_result[j] += " - Client is connected to wifi, but there's no IP"
                break
            else:
                count += 1
                logger.warn('Failed to connect %s times to %s' % (count, ssid))
                if count == max_retry:
                    test_result[i] = False
                    test_result[j] += " - Device is unable to connect to wifi"
                    logger.error("Device is unable to connect to wifi")

        elif check_for == "maxwhitelist": #case 7
            # Device shouldn't be able to connect to wifi
            if ssid in subprocess.check_output("netsh wlan show interfaces"):
                test_result[i] = False
                test_result[j] += " - Non whitelisted device is able to connect to wifi"
                logger.error("Non whitelisted device is able to connect to wifi")
            else:
                count += 1
                logger.info("Non whitelisted device is unable to connect to wifi")

        elif check_for == "accessNone": #case 1
            # Device should be able to connect to wifi
            if ssid in subprocess.check_output("netsh wlan show interfaces"):
                logger.info("Successfully connected to " + ssid)
                if "192.168" not in wifi_ip:
                    test_result[i] = False
                    test_result[j] += " - Client is connected to wifi, but there's no IP"
                break
            else:
                count += 1
                logger.warn('Failed to connect %s times to %s' % (count, ssid))
                if count == max_retry:
                    test_result[i] = False
                    test_result[j] += " - Client is unable to connect to wifi"
                    logger.error("Client is unable to connect to wifi")

    return wifi_ip,test_result

def disconnect_from_wifi(dut,logger):
    # this function disconnect computer from wifi
	# it will retry up to 2 times if the status doesn't change to disconnected
    count = 0
    max_retry = 2
    while count < max_retry:
        logger.info('Disconnecting from wifi...')
        connect_response = subprocess.Popen(["netsh", "wlan", "disconnect"],
                                            stdout=subprocess.PIPE).stdout.read()
        time.sleep(10)
        connection_state = dut.wifi.get_interface().get("State")
        if "disconnect" in connection_state:
            logger.info(connect_response)
            break
        else:
            count += 1
            if count == max_retry:
                logger.info("Failed to disconnect wifi")

def add_dummy_mac_address(dut,logger,mac_address,max_clients_number,with_client,check_for,test_result,case):
    # this function will generate and add dummy mac address to the list
    # the number of list is controlled by max_clients_number
    # if it includes the client MAC, it will be added last
    i,j = check_case(case)
    if with_client == True:
        logger.info("Add dummy MAC addresses with the client MAC last")
        for k in range(max_clients_number-1):
            mac = [ 0x1a, 0x2b, 0x3c,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff) ]
            dummy_mac_address = ':'.join(map(lambda x: "%02x" % x, mac))
            if check_for == "blacklist":
                dut.adb.shell("dx -c wlan.blacklist -t %s TestBlackList%s,%s" %(k,k,dummy_mac_address))
                blacklist = dut.adb.shell("dx wlan.blacklist -t %s" %k)
                if "No records" in blacklist:
                    test_result[i] = False
                    test_result[j] += " - Failed to add dummy mac address"
                    logger.error("Failed to add dummy mac address")
            elif check_for == "whitelist":
                dut.adb.shell("dx -c wlan.whitelist -t %s TestWhiteList%s,%s" %(k,k,dummy_mac_address))
                whitelist = dut.adb.shell("dx wlan.whitelist -t %s" %k)
                if "No records" in whitelist:
                    test_result[i] = False
                    test_result[j] += " - Failed to add dummy mac address"
                    logger.error("Failed to add dummy mac address")
        if check_for == "blacklist":
            dut.adb.shell("dx -c wlan.blacklist -t %s Device_MAC,%s" %((max_clients_number-1),Device_MAC))
            blacklist = dut.adb.shell("dx wlan.blacklist -t %s" %(max_clients_number-1))
            if "No records" in blacklist:
                test_result[i] = False
                test_result[j] += " - Failed to add client mac address"
                logger.error("Failed to add client mac address")
        elif check_for == "whitelist":
            dut.adb.shell("dx -c wlan.whitelist -t %s Device_MAC,%s" %((max_clients_number-1),Device_MAC))
            whitelist = dut.adb.shell("dx wlan.whitelist -t %s" %(max_clients_number-1))
            if "No records" in whitelist:
                test_result[i] = False
                test_result[j] += " - Failed to add client mac address"
                logger.error("Failed to add client mac address")
    else:
        logger.info("Add dummy MAC addresses")
        for k in range(max_clients_number):
            mac = [ 0x1a, 0x2b, 0x3c,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff) ]
            dummy_mac_address = ':'.join(map(lambda x: "%02x" % x, mac))
            if check_for == "blacklist":
                dut.adb.shell("dx -c wlan.blacklist -t %s TestBlackList%s,%s" %(k,k,dummy_mac_address))
                blacklist = dut.adb.shell("dx wlan.blacklist -t %s" %k)
                if "No records" in blacklist:
                    test_result[i] = False
                    test_result[j] += " - Failed to add dummy mac address"
                    logger.error("Failed to add dummy mac address")
            elif check_for == "whitelist":
                dut.adb.shell("dx -c wlan.whitelist -t %s TestWhiteList%s,%s" %(k,k,dummy_mac_address))
                whitelist = dut.adb.shell("dx wlan.whitelist -t %s" %k)
                if "No records" in whitelist:
                    test_result[i] = False
                    test_result[j] += " - Failed to add dummy mac address"
                    logger.error("Failed to add dummy mac address")

    return test_result

def check_list(dut,logger,check_for,test_result,case):
    # this function verify whether access control setting is changed properly
	# it also check if the single entry is cleared properly or not
    i,j = check_case(case)
    time.sleep(2)
    if check_for == "accessNone":
        accesscontrol = dut.adb.shell("dx wlan.accesscontrol")
        if accesscontrol != "None":
            test_result[i] = False
            test_result[j] += " - Failed to disable access control"
            logger.error("Failed to disable access control")

    if check_for == "accessBlack":
        accesscontrol = dut.adb.shell("dx wlan.accesscontrol")
        if accesscontrol != "Black":
            test_result[i] = False
            test_result[j] += " - Failed to enable blacklist"
            logger.error("Failed to enable blacklist")

    if check_for == "accessWhite":
        accesscontrol = dut.adb.shell("dx wlan.accesscontrol")
        if accesscontrol != "White":
            test_result[i] = False
            test_result[j] += " - Failed to enable whitelist"
            logger.error("Failed to enable whitelist")

    if check_for == "blacklist":
        blacklist = dut.adb.shell("dx wlan.blacklist -t 0")    
        if "No records" in blacklist:
            test_result[i] = False
            test_result[j] += " - Failed to add device MAC"
            logger.error("Failed to add device MAC")

    if check_for == "whitelist":
        whitelist = dut.adb.shell("dx wlan.whitelist -t 0")
        if "No records" in whitelist:
            test_result[i] = False
            test_result[j] += " - Failed to add device MAC"
            logger.error("Failed to add device MAC")

    return test_result

def toggle_wifi_restart(dut,logger,test_result,case):
    # restarting device wifi
    i,j = check_case(case)
    logger.info("Restarting wifi...")
    dut.adb.shell("dx -c wlan.wifirestart 1")
    time.sleep(5)
    wifi_state = dut.adb.shell("dx wlan.wifistate")
    timer = 0
    for timer in range(0,30):
        if wifi_state == "Started":
            break
        wifi_state = dut.adb.shell("dx wlan.wifistate")
        time.sleep(1)

    if wifi_state == "Started":
        logger.info("Wifi restart successfully")
    elif wifi_state == "Stopped":
        test_result[i] = False
        test_result[j] += " - Wifi didn't restart after 30 seconds"
        logger.error("Wifi didn't restart after 30 seconds")
    elif wifi_state == "Restarting":
        test_result[i] = False
        test_result[j] += " - Wifi is still restarting after 30 seconds"
        logger.error("Wifi is still restarting after 30 seconds")
    return test_result

def get_max_client_number(dut,logger):
    # check device max clients number
    max_clients_number = dut.adb.shell("dx wlan.blacklist")
    max_clients_number = "".join(i for i in max_clients_number if i.isdigit())
    return int(max_clients_number)

def usb_interface(dut,logger,ethernet_name,check_for,setup_result):
    # this function will disable or enable the specific Ethernet adaptor that device is using
    # also, in order for re-enable to work, the script must be started with the adaptor enabled
    # if it failed to disable/enable when it should, it will retry up to 2 times

    # convert unicode to string
    ethernet_number = "".join(i for i in ethernet_name if i.isdigit())
    ethernet_name = "Ethernet " + ethernet_number
    
    if check_for == "disable":
        count = 0
        max_retry = 2
        temp = True
        check_disable = True
        while(count < max_retry):
            logger.info("Disabling USB interface...")
            subprocess.call("netsh interface set interface " + '"' + ethernet_name + '"' + " disable", shell=True)
            time.sleep(10)
            adapters = ifaddr.get_adapters()
            for adapter in adapters:
                for ip in adapter.ips:
                    if ethernet_name in ip.nice_name:
                        temp = False
            if temp == False:
                count += 1
                logger.error("Failed to disable " + ethernet_name + " " + str(count) + " times ")
                if count == max_retry:
                    check_disable = False
            else:
                break

        if check_disable == True:
            logger.info(ethernet_name + " disabled successfully")
        else:
            setup_result[2] = False
            setup_result[3] += " - Failed to disable " + ethernet_name
            logger.error("Failed to disable " + ethernet_name)
        
    elif check_for == "enable":
        count = 0
        max_retry = 2
        temp = False
        check_enable = True
        while(count < max_retry):
            logger.info("Enabling USB interface...")
            subprocess.call("netsh interface set interface " + '"' + ethernet_name + '"' + " enable", shell=True)
            time.sleep(10)
            adapters = ifaddr.get_adapters()
            for adapter in adapters:
                for ip in adapter.ips:
                    if ethernet_name in ip.nice_name and '192.168.1.4' in ip.ip:
                        check_enable = True
                        temp = True
                    else:
                        continue
            if temp == True:
                break
            else:
                count += 1
                logger.error("Failed to enable " + ethernet_name + " " + str(count) + " times")
                if count == max_retry:
                    check_enable = False

        if check_enable == True:
            logger.info(ethernet_name + " enabled successfully")
        else:
            setup_result[6] = False
            setup_result[7] += " - Failed to enable " + ethernet_name
            logger.error("Failed to enable " + ethernet_name)
    interface_log = subprocess.Popen(["netsh","interface","show","interface"], stdout=subprocess.PIPE).stdout.read()
    logger.info(interface_log)
    return setup_result

def ping_test(dut,logger,wifi_ip,ping_expect,test_result,case):
    # this function will ping to google to test internet connection
    # if PDP type is set to IPv4v6, it will do both
    # if the ping result is not as expected, test case will fail
    i,j = check_case(case)
    PDP_type = dut.adb.shell("dx profile.connectionType").strip()
    ping = True
    if "None" in PDP_type:
        logger.info("Data not connected, PDP type is None")
        test_result[i] = False
        test_result[j] += " - Data not connected, PDP type is None"
    if "IPv4" in PDP_type:
        logger.info("Pinging with IPv4...")
        try:
            dut.wifi.ping_from_source("www.google.com",wifi_ip)
        except:
            ping = False
        if ping != ping_expect:
            ipv4_address = dut.adb.shell("dx ds.IPv4Addr")
            logger.info("Unexpected ping results occurred - IPv4 address: " + ipv4_address)
            test_result[i] = False
            test_result[j] += " - Ping IPv4 failed, unable to browse"
            logger.error("Ping IPv4 failed, unable to browse")
    if "IPv6" in PDP_type:
        logger.info("Pinging with IPv6...")
        try:
            dut.wifi.ping_6("www.google.com")
        except:
            ping = False
        if ping != ping_expect:
            ipv6_address = dut.adb.shell("dx ds.IPv6Addr")
            logger.info("Unexpected ping results occurred - IPv6 address: " + ipv6_address)
            test_result[i] = False
            test_result[j] += " - Ping IPv6 failed, unable to browse"
            logger.error("Ping IPv6 failed, unable to browse")
    return test_result

def check_initial_state(dut,logger,max_clients_number,setup_result):
    # saving the device state and list before running the test
    saved_blacklist = []
    saved_whitelist = []
    logger.info("Initial state is")
    initial_accesscontrol = dut.adb.shell("dx wlan.accesscontrol")
    initial_blacklist = dut.adb.shell("dx wlan.blacklist -f")
    initial_whitelist = dut.adb.shell("dx wlan.whitelist -f")
    if "No records" in initial_blacklist:
        setup_result[1] += " - no initial blacklist to save"
        logger.info("There is no blacklist to save")
    elif "tag:" in initial_blacklist:
        for i in range(max_clients_number):
            saving_blacklist = dut.adb.shell("dx wlan.blacklist -t %s" %i)
            if "Error:" in saving_blacklist:
                continue
            else:
                saved_blacklist.append(saving_blacklist)
    if "No records" in initial_whitelist:
        setup_result[1] += " - no initial whitelist to save"
        logger.info("There is no whitelist to save")
    elif "tag:" in initial_whitelist:
        for i in range(max_clients_number):
            saving_whitelist = dut.adb.shell("dx wlan.whitelist -t %s" %i)
            if "Error:" in saving_whitelist:
                continue
            else:
                saved_whitelist.append(saving_whitelist)
    if "Error" in saved_blacklist: 
        setup_result[0] = False
        setup_result[1] += " - an error occurred while saving blacklist"
    if "Error" in saved_whitelist:
        setup_result[0] = False
        setup_result[1] += " - an error occurred while saving whitelist"

    return initial_accesscontrol,saved_blacklist,saved_whitelist,setup_result

def restoring_initial_state(dut,logger,initial_accesscontrol,saved_blacklist,saved_whitelist,setup_result):
    # restoring all the initial states
    # if the restored list doesn't match the saved, it will log as error
    # if the restored list didn't get added properly, it will also log as error
    logger.info("Restoring initial state...")
    dut.adb.shell("dx -c wlan.accesscontrol " + initial_accesscontrol)
    if "no blacklist" in saved_blacklist:
        logger.info("no blacklist to restore")
    else:
        for i in range(len(saved_blacklist)):
            dut.adb.shell("dx -c wlan.blacklist -t " + str(i) + " " + '"' + saved_blacklist[i] + '"')
            blacklist = dut.adb.shell("dx wlan.blacklist -t %s" %i)
            if blacklist == saved_blacklist[i]:
                continue
            elif blacklist != saved_blacklist[i]:
                setup_result[4] = False
                setup_result[5] += " - Restored list doesn't match the initial state"
                logger.error("Restored list doesn't match the initial state")
            elif "No records" in blacklist:
                setup_result[4] = False
                setup_result[5] += " - Failed to add mac address"
                logger.error("Failed to add mac address")
    if "no whitelist" in saved_blacklist:
        logger.info("no whitelist to restore")
    else:
        for i in range(len(saved_whitelist)):
            dut.adb.shell("dx -c wlan.whitelist -t " + str(i) + " " + '"' + saved_whitelist[i] + '"')
            whitelist = dut.adb.shell("dx wlan.whitelist -t %s" %i)
            if whitelist == saved_whitelist[i]:
                continue
            elif whitelist != saved_whitelist[i]:
                setup_result[4] = False
                setup_result[5] += " - Restored list doesn't match the initial state"
                logger.error("Restored list doesn't match the initial state")
            elif "No records" in whitelist:
                setup_result[4] = False
                setup_result[5] += " - Failed to add mac address"
                logger.error("Failed to add mac address")
    time.sleep(5)

    return setup_result

def clear_list(dut,logger,check_for,test_result,case):
    i,j = check_case(case)
    if check_for == "all":
        logger.info("Clearing all lists...")
        dut.adb.shell("dx wlan.blacklist -d -z -y")
        dut.adb.shell("dx wlan.whitelist -d -z -y")
        check_blacklist_entries = dut.adb.shell("dx wlan.blacklist -f")
        check_whitelist_entries = dut.adb.shell("dx wlan.whitelist -f")
        if "No records" in check_blacklist_entries and check_whitelist_entries:
            logger.info("All entries cleared successfully")
        else:
            test_result[i] = False
            test_result[j] += " - Entries cleared unsuccessfully"
            logger.error("Entries cleared unsuccessfully") 
    elif check_for == "onlyblacklist":
        logger.info("Clearing blacklist...")
        dut.adb.shell("dx wlan.blacklist -d -z -y")
        check_blacklist_entries = dut.adb.shell("dx wlan.blacklist -f")
        if "No records" in check_blacklist_entries:
            logger.info("Blacklist entries cleared successfully")
        else:
            test_result[i] = False
            test_result[j] += " - Entries cleared unsuccessfully"
            logger.error("Entries cleared unsuccessfully")

    elif check_for == "onlywhitelist":
        logger.info("Clearing whitelist...")
        dut.adb.shell("dx wlan.whitelist -d -z -y")
        check_whitelist_entries = dut.adb.shell("dx wlan.whitelist -f")
        if "No records" in check_whitelist_entries:
            logger.info("Whitelist entries cleared successfully")
        else:
            test_result[i] = False
            test_result[j] += " - Entries cleared unsuccessfully"
            logger.error("Entries cleared unsuccessfully")
    time.sleep(5)
    return test_result

def check_swiabort(dut,logger,status):
    # check if the swiabort or swiapp file exist
	# if exist in the beginning, remove it before running the test
	# and check again at the end, report if found
    device_sku = dut.adb.shell("dx versions.productsku")
    directory = ""
    file_found = False
    if "MR5" or "MR1" in device_sku:
        directory = "/mnt/userrw/swiabort/"
    elif "MR2" in device_sku:
        directory = "/custdata/swiabort"
    swiabort_directory = dut.adb.shell("ls %s" %directory)
    if status == "start":
        if "swiapp" in swiabort_directory:
            logger.info("Swiabort file found in %s" %directory)
            logger.info("Removing existing file before running the test...")
            dut.adb.shell("rm -r %s" %directory)
        else:
            logger.info("No swiabort file found in %s" %directory)
    elif status == "end":
        if "swiapp" in swiabort_directory:
            logger.info("Swiabort file found in %s" %directory)
            file_found = True
        else:
            logger.info("No swiabort file found in %s" %directory)

    return file_found,directory

def check_case(case):
    # for assigning the right idex for each test case
    # case 0 is for all the setup, not related to the test cases
    switcher = {
    0: [14,15],
    1: [0,1],
    2: [2,3],
    3: [4,5],
    4: [6,7],
    5: [8,9],
    6: [10,11],
    7: [12,13]
    }
    result = switcher.get(case)

    return result[0],result[1]

if __name__ == '__main__':
    pytest.main(args=[os.path.abspath(__file__), "--repeat", "100"])
