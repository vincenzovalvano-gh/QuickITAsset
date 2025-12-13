from scapy.all import conf
mac = "FF:FF:FF:FF:FF:FE" 
vendor = conf.manufdb._get_manuf(mac)
print(f"MAC: {mac}, Vendor: '{vendor}'")
