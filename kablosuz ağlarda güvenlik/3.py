from scapy.all import *

def capture_handshake(interface, target_bssid, output_file):
    # Yakalanan her paketi işlemek için kullanılan fonksiyon
    def packet_handler(packet):
        # Eğer paket bir EAPOL (WPA el sıkışması) içeriyorsa
        if packet.haslayer(EAPOL):
            print(f"Handshake captured for BSSID: {target_bssid}")
            # Yakalanan el sıkışmayı .pcap dosyasına kaydediyoruz.
            wrpcap(output_file, packet, append=True)

    # WPA el sıkışmasını yakalamak için belirtilen arabirimde dinleme yapılıyor.
    print(f"Capturing WPA Handshake on interface {interface}")
    # sniff() fonksiyonu ile WPA el sıkışmasını yakalıyoruz.
    sniff(iface=interface, prn=packet_handler, stop_filter=lambda x: x.haslayer(EAPOL))

if __name__ == "__main__":
    interface = "wlan0mon"  # Monitor modunda çalışacak olan ağ arabirimi
    target_bssid = "AA:BB:CC:DD:EE:FF"  # Hedef AP'nin MAC adresi
    output_file = "handshake.pcap"  # El sıkışmanın kaydedileceği dosya
    capture_handshake(interface, target_bssid, output_file)
