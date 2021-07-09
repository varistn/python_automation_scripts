import os
import subprocess
import time
import sys
import pytest
import logging
import ifaddr
import shutil

def test_repetitive_WU_LM(dut,logger,count):

	# test_result is for logging each steps
	test_result = [
		True, "Step 1: Webupdate download",
		True, "Step 2: Webupdate update",
		True, "Step 3: Check for IPs",
		True, "Step 4: Ping Web UI, ping pass",
		True, "Step 5: Ping internet, ping pass",
		True, "Step 6: Check for swiabort at /custdata/swiabort",
		True, "Step 0: for setup process and will not be printed"
	]
	

	logger.info("Repetitive Webupdater Test")
	# check which mode device is in
	mode = check_mode(dut,logger)
	# set the path for folder
	current_path = os.getcwd()
	swiabort_folder = "%s/swiabort_log" %(current_path)
	# create a folder to save log to, only create in the first loop
	if count == 1:
		if os.path.exists(swiabort_folder):
			shutil.rmtree(swiabort_folder)
		if not os.path.exists(swiabort_folder):
			os.mkdir(swiabort_folder)
	# check swiabort at the beginning
	swiabort_start = ""
	test_result,swiabort_start = check_swiabort(dut,logger,"start",swiabort_start,test_result,0)
	# check connection type is IPv4v6, it means that data is enabled and PDP is good
	ipv4,ipv6 = set_apn(dut,logger)
	# get usb interface
	usb_name = check_ETH_interface(dut,logger,"usb")
	ethernet_name = check_ETH_interface(dut,logger,"eth")
	# disable usb interface
	logger.info("Disabling USB interface...")
	toggle_ETH_interface(dut,logger,usb_name,ipv4,"disable",mode)

	# +++++++++++++++++++++++++++++++++ Test start here ++++++++++++++++++++++++++++++++++++++
	# trigger WU check
	# since WU package is critical, it will auto download and auto update
	logger.info("Checking for update...")
	dut.adb.shell("/custapp/usr/bin/dx -c fota.WebupdaterCheckNow 1")
	time.sleep(3)
	# step 1
	test_result = webupdate_download(dut,logger,test_result,1)
	# step 2
	test_result = webupdate_update(dut,logger,test_result,2)

	# recheck mode because device return to bridge mode after successful WU
	mode = check_mode(dut,logger)
	# toggle ethernet interface to make sure IPv6 enumerate
	logger.info("Toggling ethernet interface to make sure IPv6 enumerate")
	logger.info("Disabling Ethernet interface...")
	toggle_ETH_interface(dut,logger,ethernet_name,ipv4,"disable",mode)
	logger.info("Enabling Ethernet interface...")
	toggle_ETH_interface(dut,logger,ethernet_name,ipv4,"enable",mode)
	time.sleep(3)
	
	# step 3
	test_result = check_ipconfig(dut,logger,True,mode,test_result,3)
	# step 4
	test_result = ping_webui(dut,logger,mode,True,test_result,4)
	# step 5
	test_result = ping_internet(dut,logger,ipv4,ipv6,True,mode,test_result,5)
	# step 6
	test_result,swiabort_start = check_swiabort(dut,logger,"end",swiabort_start,test_result,6)

	# enabling usb interface
	logger.info("Enabling USB interface...")
	toggle_ETH_interface(dut,logger,usb_name,ipv4,"usb_enable",mode)

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
		logger.info("Adding new APN with PDP IPv4v6...")
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

def check_ETH_interface(dut,logger,check_for):
	# get the USB interface or Ethernet interface
	# check_for variable tell function which interface you want to find
	temp_ip = dut.ethernet.get_eth_ip()
	if temp_ip == None:
		temp_ip = adb_shell_value_only("ds.IPv4Addr")
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

def toggle_ETH_interface(dut,logger,ethernet_name,ipv4,check_for,mode):
	# ethernet_name variable is for checking which interface you want to disable/enable
	# check_for variable tells the script you want to enable or disable, or when trying to enable usb
	# this function will disable or enable the specific Ethernet interface that yoy passed in
	# if it failed to disable/enable when it should, it will retry up to 3 times
	if mode == "bridge":
		temp_ip = ipv4
	elif mode == "router":
		temp_ip = "192.168.5"

	count = 0
	max_retry = 2
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
				# ipv4 might have change after device rebooting, update the IP
				ipv4 = dut.ethernet.get_eth_ip()
				if ipv4 != None:
					temp_ip = ipv4
				if count == max_retry:
					check_enable = False
		if check_enable == True:
			logger.info(ethernet_name + " enabled successfully")
		else:
			logger.error("Failed to enable %s after %s times" %(ethernet_name,max_retry))

	interface_log = subprocess.Popen(["netsh","interface","show","interface"], stdout=subprocess.PIPE).stdout.read()
	logger.info(interface_log)
	return

def webupdate_download(dut,logger,test_result,step):
	# this function will catch the FotaState of the device during download process and output message respectively
	# successful WU download FotaState should go from 1-2-3-4, however, the script might only able to catch 3 and 4
	# the download process will have a 300 seconds timeout, declared download failed if timeout is reached
	# some FotaState will need a reboot to be able to continue
	i,j = check_step(step)
	fota_state,fota_message = check_fotastate(dut,logger)
	start = time.time()
	timeout = 30 # should be 30
	while int(fota_state) < 6:
		if fota_state == "0": # fota feature is disabled
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			wu_error_code = adb_shell_value_only("fota.WebupdaterErrCode")
			wu_error_detail = adb_shell_value_only("fota.WebupdaterErrDetail")
			test_result[i] = False
			test_result[j] += " - FotaState is %s, %s, WebupdaterErrCode is %s: %s" %(fota_state,fota_message,wu_error_code,wu_error_detail)
			return test_result
		if fota_state == "1": # update not found
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			wu_error_code = adb_shell_value_only("fota.WebupdaterErrCode")
			wu_error_detail = adb_shell_value_only("fota.WebupdaterErrDetail")
			if time.time() > start + timeout:
				logger.info("FotaState is %s, unable to find update after %s seconds, WebupdaterErrCode is %s: %s" %(fota_state,timeout,wu_error_code,wu_error_detail))
				logger.info("Please ensure the update path is set before running the test")
				test_result[i] = False
				test_result[j] += " - FotaState is %s, unable to find update after %s seconds, WebupdaterErrCode is %s: %s" %(fota_state,timeout,wu_error_code,wu_error_detail)
				logger.info("Rebooting device...")
				dut.adb.shell("reboot")
				test_result = check_device_return(dut,logger,test_result,step)
				return test_result
		if fota_state == "2": # update found
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			wu_error_code = adb_shell_value_only("fota.WebupdaterErrCode")
			wu_error_detail = adb_shell_value_only("fota.WebupdaterErrDetail")
			if time.time() > start + timeout:
				logger.info("FotaState is %s, update found but unable to download after %s seconds, WebupdaterErrCode is %s: %s" %(fota_state,timeout,wu_error_code,wu_error_detail))
				logger.info("Please ensure the update path is set to critical package before running the test")
				test_result[i] = False
				test_result[j] += " - FotaState is %s, update found but unable to download after %s seconds, WebupdaterErrCode is %s: %s" %(fota_state,timeout,wu_error_code,wu_error_detail)
				return test_result
		if fota_state == "3": # downloading
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			start_download_time = time.time()
			dl_timeout = 300
			while time.time() < start_download_time + dl_timeout:
				fota_state,fota_message = check_fotastate(dut,logger)
				wu_error_code = adb_shell_value_only("fota.WebupdaterErrCode")
				wu_error_detail = adb_shell_value_only("fota.WebupdaterErrDetail")
				download_progress = adb_shell_value_only("fota.FotaDownlProg")
				current_download_time = time.time()
				logger.info("%s, %s%% [%ss]" %(fota_message,download_progress,round(current_download_time-start_download_time,2)))
				time.sleep(1)
				if fota_state != "3" or download_progress == "100":
					logger.info("Download completed")
					break
			else:
				connection_type = dut.adb.shell("/custapp/usr/bin/dx profile.connectiontype")
				test_result[i] = False
				if connection_type == "None":
					logger.info("Download is canceled because device is not connected to internet, timeout after %s seconds, WebupdaterErrCode is %s: %s" %(dl_timeout,wu_error_code,wu_error_detail))
					test_result[j] += " - Download is canceled because device is not connected to internet, timeout after %s seconds, WebupdaterErrCode is %s: %s" %(dl_timeout,wu_error_code,wu_error_detail)
				else:
					logger.info("Downloading process might be stuck or canceled, timeout after %s seconds, WebupdaterErrCode is %s: %s" %(dl_timeout,wu_error_code,wu_error_detail))
					test_result[j] += " - Downloading process might be stuck or canceled, timeout after %s seconds, WebupdaterErrCode is %s: %s" %(dl_timeout,wu_error_code,wu_error_detail)
				# Device need to reboot and start again
				logger.info("Rebooting device...")
				dut.adb.shell("reboot")
				test_result = check_device_return(dut,logger,test_result,step)
				return test_result
		if fota_state == "4": # download completed
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			wu_error_code = adb_shell_value_only("fota.WebupdaterErrCode")
			wu_error_detail = adb_shell_value_only("fota.WebupdaterErrDetail")
			if time.time() > start + timeout:
				logger.info("FotaState is %s, download completed but unable to start update after %s seconds, WebupdaterErrCode is %s: %s" %(fota_state,timeout,wu_error_code,wu_error_detail))
				test_result[i] = False
				test_result[j] += " - FotaState is %s, download completed but unable to start update after %s seconds, WebupdaterErrCode is %s: %s" %(fota_state,timeout,wu_error_code,wu_error_detail)
				return test_result				
		if fota_state == "5": # download error
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			wu_error_code = adb_shell_value_only("fota.WebupdaterErrCode")
			wu_error_detail = adb_shell_value_only("fota.WebupdaterErrDetail")
			test_result[i] = False
			test_result[j] += " - FotaState is %s, %s, WebupdaterErrCode is %s: %s" %(fota_state,fota_message,wu_error_code,wu_error_detail)
			logger.info("Rebooting device...")
			dut.adb.shell("reboot")
			test_result = check_device_return(dut,logger,test_result,step)
			return test_result
		# update fotastate
		fota_state,fota_message = check_fotastate(dut,logger)
	return test_result

def webupdate_update(dut,logger,test_result,step):
	# this function will catch the FotaState of the device during update process and output message respectively
	# successful WU update FotaState should go from 9-10
	# the update process will have a 300 seconds timeout, declared update failed if timeout is reached
	# some FotaState will need a reboot to be able to continue
	i,j = check_step(step)
	fota_state,fota_message = check_fotastate(dut,logger)
	if int(fota_state) < 6:
		logger.info("Download was not completed, skipping update")
		test_result[i] = False
		test_result[j] += " - FotaState is %s, download was not completed, skipping update" %fota_state
	else:
		logger.info("Starting update...")
	start = time.time()
	timeout = 30
	while int(fota_state) > 5:
		if fota_state == "6" or fota_state == "7" or fota_state == "8":
			# 6: expecting UI answer to update 7: expecting user to connect modem to charger 8: user postpone update
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			if time.time() > start + timeout:
				test_result[i] = False
				test_result[j] += " - FotaState is %s, %s" %(fota_state,fota_message)
				return test_result
		if fota_state == "9": # update in progress
			# update usually took around 70 - 80 seconds
			update_timeout = 300
			start_update_time = time.time()
			while time.time() < start_update_time + update_timeout:
				fota_state,fota_message = check_fotastate(dut,logger)
				current_update_time = time.time()
				logger.info("FotaState is %s, %s [%ss]" %(fota_state,fota_message,round(current_update_time-start_update_time, 2)))
				time.sleep(2)
				if fota_state != "9":
					break
			else:
				logger.info("FotaState is %s, the update did not completed with in the time period of %s seconds" %(fota_state,update_timeout))
				test_result[i] = False
				test_result[j] += " - FotaState is %s, the update did not completed with in the time period of %s seconds" %(fota_state,update_timeout)
		if fota_state == "10": # update completed
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			logger.info("The device will start rebooting...")
			# device should be rebooting, check for device to return
			test_result = check_device_return(dut,logger,test_result,step)
			return test_result
		if fota_state == "11": # update error
			logger.info("FotaState is %s, %s" %(fota_state,fota_message))
			test_result[i] = False
			test_result[j] += " - FotaState is %s, %s" %(fota_state,fota_message)
			# device might need reboot to bring it back to normal state for next loop
			logger.info("Rebooting device...")
			dut.adb.shell("reboot")
			test_result = check_device_return(dut,logger,test_result,step)
			return test_result

		# update fotastate
		fota_state,fota_message = check_fotastate(dut,logger)
	return test_result

def check_device_return(dut,logger,test_result,step):
	# check if device return after reboot
	# if device reboot but could not be found, retry up to 2 times
	i,j = check_step(step)
	retry = 0
	max_retry = 2
	while retry < max_retry:
		try:
			dut.check_devret()
		except Exception as error_message:
			retry += 1
			logger.info("Device couldn't be found, retrying %s times" %retry)
			if retry == max_retry:
				logger.info("Device still couldn't be found after %s retries" %max_retry)
				test_result[i] = False
				test_result[j] += " - Device still couldn't be found after %s retries" %max_retry
				return test_result
			dut.adb.shell("reboot")
		else:
			break
	return test_result

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
	# split files it to array for counting
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

def check_fotastate(dut,logger):
	# check dx fota.fotastate and return the right message
	fota_state = adb_shell_value_only("fota.FotaState")
	if fota_state == '':
		fota_message = "FotaState not found, device might be rebooting"
		logger.info(fota_message)
	else:
		fota_state_int = int(fota_state)
		switcher = {
			0: "Fota is disabled",
			1: "No update available",
			2: "Update available",
			3: "Downloading update package",
			4: "Download update package completed",
			5: "Download error",
			6: "Expecting UI answer to update",
			7: "Expecting user to connect modem to charger",
			8: "User postponing the update",
			9: "Update in progress",
			10: "Update completed",
			11: "Update error"
			}
		fota_message = switcher.get(fota_state_int)
	return fota_state,fota_message

def adb_shell_value_only(dx_item):
	# this function will return only
	dx_value = subprocess.check_output(["adb","shell","custapp/usr/bin/dx %s" %dx_item], shell=True)
	dx_value = dx_value.split("\r\r\n")
	return dx_value[0]

def check_step(step):
	# for assigning the right index for each test case
	# case 0 is for all the setup, not related to the test cases
	switcher = {
		0: [14,15],
		1: [0,1],
		2: [2,3],
		3: [4,5],
		4: [6,7],
		5: [8,9],
		6: [10,11],
		7: [12,13]}

	result = switcher.get(step)
	return result[0],result[1]

if __name__ == '__main__':
	pytest.main(args=[os.path.abspath(__file__),"--repeat","100"])