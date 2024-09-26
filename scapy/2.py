#! /usr/bin/python

# Gerekli modüller içe aktarılıyor.
import sys    # Komut satırı argümanlarını işlemek için 'sys' modülü.
import os     # Dosya işlemleri için 'os' modülü.
from scapy.all import *  # Scapy'nin tüm işlevlerini kullanmak için 'scapy.all' modülü içe aktarılıyor.

def main(argv):
    # Komut satırı argümanlarının yeterli olup olmadığını kontrol ediyoruz
    if len(argv) != 2:
        print("Usage: python script.py <domain> <wordlist>")
        sys.exit(1)

    domain = argv[0]  # Domain adı, komut satırı argümanı olarak verilir.
    wd = argv[1]      # Wordlist dosyasının yolu, komut satırı argümanı olarak verilir.

    # Wordlist dosyası açılır ve satırları okunur.
    try:
        with open(wd, 'r') as wd_file:  # Belirtilen dosya yolu açılır.
            wd_list = wd_file.readlines()  # Dosyadaki tüm satırlar okunur ve bir listeye alınır.
    except IOError:
        print(f"Error: File {wd} not found or cannot be opened.")
        sys.exit(1)

    # Wordlist'teki her bir alt domain için DNS sorgusu gerçekleştirilir.
    for i in wd_list:
        # Alt domain adı oluşturulur.
        host = i.strip() + "." + domain  # Her satırdaki alt domain ismi alınır ve domainle birleştirilir.

        # DNS sorgusu gerçekleştirilir.
        try:
            answer = sr1(
                IP(dst="8.8.8.8") /  # Google'ın DNS sunucusuna (8.8.8.8) IP paketi gönderilir.
                UDP(dport=53) /      # UDP üzerinden DNS sorgusu gerçekleştirilir (Port 53).
                DNS(rd=1, qd=DNSQR(qname=str(host))),  # DNS sorgusu, belirtilen alt domain için yapılır.
                verbose=0  # Sadece gerekli çıktılar gösterilir, ayrıntılı bilgi bastırılmaz.
            )

            # DNS sorgusunun sonucuna göre ekrana çıktı verilir.
            if answer and answer.haslayer(DNS) and len(answer[DNS].summary().strip()) > 0:
                # Eğer bir DNS cevabı geldiyse, bu cevap ekrana yazdırılır.
                print(f"{host} ---> {answer[DNS].summary().strip()}")

        except Exception as e:
            print(f"Error querying {host}: {e}")

# Eğer bu betik doğrudan çalıştırılırsa (import edilmezse), main() fonksiyonu çalıştırılır.
if __name__ == "__main__":
    main(sys.argv[1:])  # Komut satırı argümanları main() fonksiyonuna aktarılır.
