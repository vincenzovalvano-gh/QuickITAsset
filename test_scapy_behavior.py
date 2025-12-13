from scapy.all import conf
mac = "00:11:22:33:44:55" # Likely unknown
vendor = conf.manufdb._get_manuf(mac)
print(f"MAC: {mac}, Vendor: '{vendor}'")

mac2 = "00:50:56:C0:00:08" # VMware
vendor2 = conf.manufdb._get_manuf(mac2)
print(f"MAC: {mac2}, Vendor: '{vendor2}'")
