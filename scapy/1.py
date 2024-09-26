#! /usr/bin/python
# Bu satır, Python betiğinin Unix/Linux sistemlerinde çalıştırılabilir bir komut dosyası olarak kullanılmasını sağlar.
# 'usr/bin/python' kısmı, Python yorumlayıcısının sistemde nerede bulunduğunu belirtir.

import sys
# 'sys' modülü, komut satırı argümanlarıyla çalışmak ve betiği sonlandırmak için kullanılır.

from scapy.all import *
# Scapy'nin tüm işlevlerini kullanmak için 'scapy.all' modülü içe aktarılır.
# Scapy, ağ paketleri oluşturmak, göndermek, almak ve analiz etmek için kullanılan güçlü bir kütüphanedir.

def main(argv):
    # Bu, betiğin ana fonksiyonudur ve komut satırı argümanlarını alır.

    try:
        # Kullanıcıdan ağ arayüzünü (interface) girmesini ister.
        interface = input("Interface: ")

        # Kullanıcıdan taramak istediği IP aralığını girmesini ister.
        ips = input("IP Range: ")

    except KeyboardInterrupt:
        # Kullanıcı betiği Ctrl+C ile sonlandırmak isterse bu blok çalışır.
        print("QUITTING...")
        sys.exit(1)  # Programı hatasız bir şekilde sonlandırır.

    # Scapy'nin varsayılan olarak çok detaylı çıktılar üretmesini engellemek için verbose modu kapatılır.
    conf.verb = 0

    # srp() fonksiyonu, 2. katman (Ethernet) paketlerini gönderir ve yanıtlarını toplar.
    # Ether() fonksiyonu ile Ethernet başlığı oluşturulur ve hedef MAC adresi yayın (broadcast) adresi olan "ff:ff:ff:ff:ff:ff" olarak ayarlanır.
    # ARP() fonksiyonu ile ARP başlığı oluşturulur ve pdst alanı taranacak IP aralığını içerir.
    ans, unans = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
        timeout=4,  # Cevap bekleme süresi (4 esaniye) olarak ayarlanır.
        iface=interface,  # Kullanıcının belirttiği ağ arayüzü kullanılır.
        inter=0.05  # Paketler arasında 50 ms gecikme ayarlanır.
    )

    # Elde edilen MAC ve IP adreslerini kullanıcıya gösterir.
    print("MAC - IP:")
    for snd, rcv in ans:
        # Her alınan cevap için, gönderilen paket (snd) ve alınan paket (rcv) arasında eşleme yapılır.
        # Alınan paketten kaynağın MAC adresi ve IP adresi alınır ve ekrana yazdırılır.
        print(rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))

if __name__ == "__main__":
    # Eğer bu betik doğrudan çalıştırılırsa (import edilmezse), main() fonksiyonu çalıştırılır.
    main(sys.argv[1 :])
