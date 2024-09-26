from scapy.all import *

def scan_network(interface):
    # Yakalanan her paketi işlemek için kullanılan fonksiyon
    def packet_handler(packet):
        # Eğer paket bir beacon çerçevesiyse (yani bir Wi-Fi ağının SSID'sini yayımlayan bir paket)
        if packet.haslayer(Dot11Beacon):
            # SSID (Wi-Fi adı) bilgisini alıyoruz.
            ssid = packet[Dot11Elt].info.decode()
            # BSSID (erişim noktası MAC adresi) bilgisini alıyoruz.
            bssid = packet[Dot11].addr2
            # Kanal numarasını alıyoruz.
            channel = int(ord(packet[Dot11Elt:3].info))
            # Bulunan ağ bilgilerini ekrana yazdırıyoruz.
            print(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")

    # Belirtilen ağ arabiriminde taramayı başlatıyoruz.
    print(f"Scanning on interface {interface}")
    # sniff() fonksiyonu ile belirtilen arabirimdeki paketleri yakalıyoruz.
    try:
        sniff(iface=interface, prn=packet_handler, timeout=10)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    interface = "wlan0mon"  # Monitor modunda çalışacak olan ağ arabirimi
    scan_network(interface)
