
import os
import subprocess
import time
import sys
import pytest
import logging
import ifaddr
import shutil

def test_eject_insert_Ethernet_LM(dut,logger,count):

	# test_result is for logging each steps
	test_result = [
		True, "Step 1: Disable Ethernet interface",
		True, "Step 2: Check for IPs, IP shouldn't enumerate",
		True, "Step 3: Ping Web UI, ping fail",
		True, "Step 4: Ping internet, ping fail",
		True, "Step 5: Re-enable Ethernet interface",
		True, "Step 6: Check for IPs, IP should enumerate",
		True, "Step 7: Ping Web UI, ping pass",
		True, "Step 8: Ping internet, ping pass",
		True, "Step 9: Check for swiabort at /custdata/swiabort",
		True, "Step 0: for setup process and will not be printed"
	]

	# set the path for folder
	current_path = os.getcwd()
	swiabort_folder = "%s/swiabort_log" %(current_path)
	# create a folder to save log to, only create in the first loop
	if count == 1:
		if os.path.exists(swiabort_folder):
			shutil.rmtree(swiabort_folder)
		if not os.path.exists(swiabort_folder):
			os.mkdir(swiabort_folder)

	# check which mode device is in
	mode = check_mode(dut,logger)
	# check swiabort at the beginning
	swiabort_start = ""
	test_result,swiabort_start = check_swiabort(dut,logger,"start",swiabort_start,test_result,0)
	# check connection type is IPv4v6, it means that data is enabled and PDP is good
	ipv4,ipv6 = set_apn(dut,logger)
	# get usb interface
	usb_name = check_ETH_interface(dut,logger,"usb",mode)
	# disable usb interface
	logger.info("Disabling USB interface...")
	toggle_ETH_interface(dut,logger,usb_name,ipv4,"disable",mode,test_result,0)
	# get ethernet interface
	ethernet_name = check_ETH_interface(dut,logger,"eth",mode)

	# +++++++++++++++++++++++++++++++++ Test start here ++++++++++++++++++++++++++++++++++++++
	# step 1
	logger.info("Disabling Ethernet interface...")
	test_result = toggle_ETH_interface(dut,logger,ethernet_name,ipv4,"disable",mode,test_result,1)
	# step 2
	test_result = check_ipconfig(dut,logger,False,mode,test_result,2)
	# step 3
	test_result = ping_webui(dut,logger,mode,False,test_result,3)
	# step 4
	test_result = ping_internet(dut,logger,ipv4,ipv6,False,mode,test_result,4)
	# step 5
	logger.info("Enabling Ethernet interface...")
	test_result = toggle_ETH_interface(dut,logger,ethernet_name,ipv4,"enable",mode,test_result,5)
	# step 6
	test_result = check_ipconfig(dut,logger,True,mode,test_result,6)
	# step 7
	test_result = ping_webui(dut,logger,mode,True,test_result,7)
	# step 8
	test_result = ping_internet(dut,logger,ipv4,ipv6,True,mode,test_result,8)
	# step 9
	test_result,swiabort_start = check_swiabort(dut,logger,"end",swiabort_start,test_result,9)

	# enabling usb interface
	logger.info("Enabling USB interface...")
	toggle_ETH_interface(dut,logger,usb_name,ipv4,"usb_enable",mode,test_result,0)

	# printing result
	logger.info("============================== Test result ==============================")
	logger.info("Device is in %s mode" %mode)
	test_temp2 = ""
	for i in range(0,len(test_result)-2,2):
		if test_result[i] == True:
			test_temp = "Passed"
		else:
			test_temp = "Failed"
			test_temp2 = "Failed"
		logger.info("%s: %s" %(test_temp,test_result[i+1]))

	if test_temp2 == "Failed":
		pytest.fail("At least 1 step failed")
	else:
		logger.info("All steps passed")

#++++++++++++++++++++++++++++++++ below are helper functions for the script +++++++++++++++++++++++++++++++
def check_mode(dut,logger):
	# check if device is in bridge mode or router mode
	# if IPT is 1, then bridge mode
	# if IPT is 0, then router mode
	mode = dut.adb.shell("/custapp/usr/bin/dx network.IPPassThroughEnabled")
	if mode == "1":
		mode = "bridge"
		logger.info("Device is in Bridge mode")
	else:
		mode = "router"
		logger.info("Device is in Router mode")
	return mode

def set_apn(dut,logger):
	# check the connection type, if None, then internet is not connected
	# if it's not IPv4v6, then create a new APN with IPv4v6
	# obtain ipv4 and ipv6
	ipv4 = "None"
	ipv6 = "None"
	connection_type = dut.adb.shell("/custapp/usr/bin/dx profile.connectiontype")
	if "None" in connection_type:
		logger.error("Data is not connected, please enable data connection before running the test")
	elif "IPv4AndIPv6" not in connection_type:
		logger.info("Adding new APN with PDP IPv4v6 ")
		dut.adb.shell("/custapp/usr/bin/dx -c profile.profile -t TestPDP TestPDP,0,3,0.0.0.0,lteinternet.apn,0,,,0,0,3,0,0,0,0")
		check_apn = dut.adb.shell("/custapp/usr/bin/dx profile.profile -t TestPDP")
		# switch apn
		if "Error" not in check_apn:
			dut.adb.shell("/custapp/usr/bin/dx -c profile.dataprofile TestPDP")
		else:
			dut.adb.shell("/custapp/usr/bin/dx -c profile.dataprofile lteinternet.apn")			
		time.sleep(30)
		# check if connectype is ipv4v6
		check_connectiontype = dut.adb.shell("/custapp/usr/bin/dx profile.connectiontype")
		if "IPv4AndIPv6" in check_connectiontype:
			logger.info("APN is set to IPv4v6")
			ipv4 = dut.adb.shell("/custapp/usr/bin/dx ds.IPv4Addr")
			ipv6 = dut.adb.shell("/custapp/usr/bin/dx ds.IPv6Addr")
		elif "IPv4Only" in check_connectiontype:
			logger.info("APN is still IPv4 only")
			ipv4 = dut.adb.shell("/custapp/usr/bin/dx ds.IPv4Addr")
		elif "IPv6Only" in check_connectiontype:
			logger.info("APN is still IPv6 only")
			ipv6 = dut.adb.shell("/custapp/usr/bin/dx ds.IPv6Addr")
	else:
		ipv4 = dut.adb.shell("/custapp/usr/bin/dx ds.IPv4Addr")
		ipv6 = dut.adb.shell("/custapp/usr/bin/dx ds.IPv6Addr")

	return ipv4,ipv6

def check_ipconfig(dut,logger,ip_expect,mode,test_result,step):
	# ip_expect tell function if IP is expected or not
	# test_result is for logging the test step
	# step variable is for assigning the index for the test step
	# if device is in bridge mode, 25.XXX.XXX.XXX should enumerate, if 192.168.5.1 enumerate, data might be disconnected
	# if device is in router mode, 192.168.5.X should enumerate
	i,j = check_step(step)
	ip = True
	error_message = ""
	try:
		dut.check_LM_ip(mode)
	except Exception as error_message:
		ip = False
		logger.info(error_message)
	if mode == "bridge":
		if '192.168.5.x IP found in ipconfig for bridge mode' in error_message:
			connection_state = dut.adb.shell("/custapp/usr/bin/dx ds.connectionState")
			if connection_state != "Connected":
				logger.error("Data is no longer connected")
	if ip != ip_expect:
		if ip_expect == True:
			test_result[i] = False
			test_result[j] += " - IP didn't enumerate properly"
		elif ip_expect == False:
			test_result[i] = False
			test_result[j] += " - IP enumerated when shouldn't"

	return test_result

def check_ETH_interface(dut,logger,check_for,mode):
	# get the USB interface or Ethernet interface
	# check_for variable tell function which interface you want to find
	temp_ip = dut.ethernet.get_eth_ip()
	adapters = ifaddr.get_adapters()
	ethernet_name = "Ethernet"
	for adapter in adapters:
		if check_for == "usb":
			# usb interface is usually name Remote NDIS
			if "NDIS" in adapter.nice_name or "ndis" in adapter.nice_name:
				for ip in adapter.ips:
					if 'Ethernet' in ip.nice_name:
						ethernet_name = ip.nice_name
						break

		elif check_for == "eth":
			for ip in adapter.ips:
				if 'Ethernet' in ip.nice_name and temp_ip in ip.ip:
					ethernet_name = ip.nice_name

	if check_for == "usb":
		logger.info("USB interface is %s" %ethernet_name)
	else:
		logger.info("Ethernet interface is %s" %ethernet_name)
	# ethernet_name is a unicode type
	return ethernet_name

def toggle_ETH_interface(dut,logger,ethernet_name,ipv4,check_for,mode,test_result,step):
	# ethernet_name variable is for checking which interface you want to disable/enable
	# check_for variable tells the script you want to enable or disable, or when trying to enable usb
	# test_result is for logging the test step
	# step variable is for assigning the index for the test step
	# this function will disable or enable the specific Ethernet interface that you passed in
	# if it failed to disable/enable when it should, it will retry up to 3 times
	i,j = check_step(step)

	if mode == "bridge":
		temp_ip = ipv4
	elif mode == "router":
		temp_ip = "192.168.5"

	count = 0
	max_retry = 3
	check_disable = True
	check_enable = True

	if check_for == "disable":
		temp = True
		while (count < max_retry):
			subprocess.call("netsh interface set interface " + '"' + ethernet_name + '"' + " disable", shell=True)
			time.sleep(10)
			adapters = ifaddr.get_adapters()
			for adapter in adapters:
				for ip in adapter.ips:
					if ethernet_name in ip.nice_name:
						temp = False
			if temp == False:
				count += 1
				logger.error("Failed to disable %s %s times" %(ethernet_name,count))
				if count == max_retry:
					check_disable = False
			else:
				break
		if check_disable == True:
			logger.info(ethernet_name + " disabled successfully")
		else:
			logger.error("Failed to disable %s after %s times" %(ethernet_name,max_retry))
			test_result[i] = False
			test_result[j] += " - Failed to disable %s after %s times" %(ethernet_name,max_retry)
	else:
		temp = False
		while(count < max_retry):
			subprocess.call("netsh interface set interface " + '"' + ethernet_name + '"' + " enable", shell=True)
			time.sleep(10)
			adapters = ifaddr.get_adapters()
			for adapter in adapters:
				for ip in adapter.ips:
					if check_for == "enable":
						if ethernet_name in ip.nice_name and temp_ip in ip.ip:
							check_enable = True
							temp = True
					elif check_for == "usb_enable":
						if ethernet_name in ip.nice_name:
							check_enable = True
							temp = True

			if temp == True:
				break
			else:
				count += 1
				logger.error("Failed to enable %s %s times" %(ethernet_name,count))
				if count == max_retry:
					check_enable = False
		if check_enable == True:
			logger.info(ethernet_name + " enabled successfully")
		else:
			test_result[i] = False
			test_result[j] += " - Failed to enable %s after %s times" %(ethernet_name,max_retry)
			logger.error("Failed to enable %s after %s times" %(ethernet_name,max_retry))

	interface_log = subprocess.Popen(["netsh","interface","show","interface"], stdout=subprocess.PIPE).stdout.read()
	logger.info(interface_log)
	return test_result

def ping_internet(dut,logger,ipv4,ipv6,ping_expect,mode,test_result,step):
	# ping_expect variable tell function if ping is expected to pass or not
	# test_result is for logging the test step
	# step variable is for assigning the index for the test step
	# if ping result doesn't match ping expected, the step fail
	i,j = check_step(step)

	temp_ip = dut.ethernet.get_eth_ip()

	logger.info("Pinging internet...")
	PDP_type = dut.adb.shell("/custapp/usr/bin/dx profile.connectionType").strip()
	ping = True
	if "None" in PDP_type:
		logger.info("Data not connected, PDP type is None")
		test_result[i] = False
		test_result[j] += " - Data not connected, PDP type is None"
	if "IPv4" in PDP_type:
		logger.info("Pinging with IPv4...")
		try:
			dut.ethernet.ping_from_source("www.google.com",temp_ip)
		except:
			ping = False
		if ping != ping_expect:
			if ping_expect == True:
				logger.info("Unexpected ping results occurred - IPv4 address: %s" %ipv4)
				test_result[i] = False
				test_result[j] += " - Ping IPv4 failed, unable to browse"
				logger.error("Ping IPv4 failed, unable to browse")
			elif ping_expect == False:
				logger.info("Unexpected ping results occurred - IPv4 address: %s" %ipv4)
				test_result[i] = False
				test_result[j] += " - Ping IPv4 passed when it shouldn't"
				logger.error("Ping IPv4 passed when it shouldn't")
	ping = True
	if "IPv6" in PDP_type:
		logger.info("Pinging with IPv6...")
		try:
			dut.ethernet.ping_6("www.google.com")
		except:
			ping = False
		if ping != ping_expect:
			if ping_expect == True:
				logger.info("Unexpected ping results occurred - IPv6 address: %s" %ipv6)
				test_result[i] = False
				test_result[j] += " - Ping IPv6 failed, unable to browse"
				logger.error("Ping IPv6 failed, unable to browse")
			elif ping_expect == False:
				logger.info("Unexpected ping results occurred - IPv6 address: %s" %ipv6)
				test_result[i] = False
				test_result[j] += " - Ping IPv6 passed when it shouldn't"
				logger.error("Ping IPv6 passed when it shouldn't")
	return test_result

def ping_webui(dut,logger,mode,ping_expect,test_result,step):
	# ping_expect variable tell function if ping is expected to pass or not
	# test_result is for logging the test step
	# step variable is for assigning the index for the test step
	# if ping result doesn't match ping expected, the step fail
	i,j = check_step(step)
	ping = True
	ipv4 = dut.ethernet.get_eth_ip()

	logger.info("Pinging Web UI...")
	gateway_ip = dut.adb.shell("/custapp/usr/bin/dx router.GwIpAddr")
	try:
		dut.ethernet.ping_from_source(gateway_ip,ipv4)
	except:
		ping = False
	if ping != ping_expect:
		if ping_expect == True:
			logger.info("Unable to ping Web UI")
			test_result[i] = False
			test_result[j] += " - Unable to ping Web UI"
		elif ping_expect == False:
			logger.info("Able to ping Web UI when shouldn't")
			test_result[i] = False
			test_result[j] += " - Able to ping Web UI when shouldn't"
	return test_result

def check_swiabort(dut,logger,status,swiabort_start,test_result,step):
	# status variable is for checking before the test or at the end
	# swiabort_start is for checking if swiapp exist in the beginning and compare it to the end
	# test_result is for logging the test step
	# step variable is for assigning the index for the test step
	i,j = check_step(step)
	file_to_pull = []

	device_sku = dut.adb.shell("/custapp/usr/bin/dx versions.productsku")
	directory = ""
	if "LM" in device_sku:
		directory = "/custdata/swiabort/"
	swiabort_directory = dut.adb.shell("ls %s" %directory)
	# split files in to array for counting
	swiabort_list = swiabort_directory.split()
	if status == "start":
		if "swiapp" in swiabort_directory:
			swiabort_start = len(swiabort_list)
			logger.info("Swiabort file found in %s at beginning of the test" %directory)
		else:
			logger.info("No swiabort file found in %s at beginning of the test" %directory)
	elif status == "end":
		if "swiapp" in swiabort_directory:
			swiabort_end = len(swiabort_list)
			# if len of array at the end is not the same as the beginning, new swiapp files are found
			if swiabort_end != swiabort_start:
				current_path = os.getcwd()
				file_differences = swiabort_end-swiabort_start
				for file in range(1,file_differences+1):
					# pull the new swiapp and move file to swiabort_log
					subprocess.check_output(["adb", "pull", "%sswiapp_%s.txt" %(directory,(swiabort_end-file))])
					shutil.move("%s/swiapp_%s.txt" %(current_path,(swiabort_end-file)), "%s/swiabort_log" %(current_path))
					file_to_pull.append(swiabort_end-file)
				# format the array for printing
				file_to_pull_str = str(file_to_pull).strip('[]')
				file_to_pull_str = file_to_pull_str.replace(", ","/")

				logger.info("New swiabort file found swiapp_%s.txt" %file_to_pull_str)
				test_result[i] = False
				test_result[j] += " - New swiabort file swiapp_%s.txt" %file_to_pull_str
			else:
				logger.info("No new swiabort file found")
		else:
			logger.info("No swiabort file found")

	return test_result,swiabort_start

def check_step(step):
	# for assigning the right index for each test case
	# case 0 is for all the setup, not related to the test cases
	switcher = {
		0: [18,19],
		1: [0,1],
		2: [2,3],
		3: [4,5],
		4: [6,7],
		5: [8,9],
		6: [10,11],
		7: [12,13],
		8: [14,15],
		9: [16,17]}

	result = switcher.get(step)
	return result[0],result[1]

if __name__ == '__main__':
	pytest.main(args=[os.path.abspath(__file__),"--repeat","100"])
