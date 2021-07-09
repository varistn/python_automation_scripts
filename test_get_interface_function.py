
import subprocess

def test_get_interface_function():
    mac_address = get_interface().get("Physicaladdress")
    profile = get_interface().get("Profile")
    wifi_channel = get_interface().get("Channel")
    print("Profile: %s" %profile)
    print("MAC address: %s" %mac_address)
    print("Wifi channel: %s" %wifi_channel)


def get_interface():
    interface_fields = subprocess.check_output("netsh wlan show interface")
    interface_fields = interface_fields.decode().split("\r\n")
    interface_fields_n = []
    temp2 = ""
    for i in interface_fields:
        if i:
            temp = i.split(":")
            temp[0] = temp[0].replace(" ", "").replace("(Mbps)", "")
            if temp[0] == "Physicaladdress" or temp[0] == "BSSID":
                address = ""
                for i in range (1, len(temp)):
                    address = address + temp[i] + ":"
                temp[1] = address[1:-1]
                interface_fields_n.append(temp)
            elif temp[0] == "SoftwareOn" or temp[0] == "SoftwareOff":
                temp2 = temp[0]
            else:
                temp[1] = temp[1][1:]
                interface_fields_n.append(temp)

    wifi_interface = {}
    for item in interface_fields_n:
        if item[0] == "Radiostatus":
            item[1] = item[1],temp[2]
        wifi_interface[item[0]] = item[1]
    return wifi_interface

if __name__ == '__main__':
    test_get_interface_function()