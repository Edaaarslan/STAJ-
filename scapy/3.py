#! /usr/bin/python

# Gerekli modüller içe aktarılıyor
import sys  # Komut satırı argümanlarını işlemek için 'sys' modülü.
from scapy.all import *  # Scapy'nin tüm işlevlerini kullanmak için 'scapy.all' modülü içe aktarılıyor.

def main(argv):
    # Kullanıcıdan gerekli bilgileri alıyoruz
    ip = input("Enter Destination IP: ")  # Hedef IP adresi.
    pdu_type = input("Enter PDU Type (set or get): ")  # PDU türü: 'set' ya da 'get'.
    com_string = input("Enter Community String: ")  # SNMP topluluk dizesi (community string).
    ver = input("Enter Version of SNMP: ")  # SNMP versiyonu (örneğin, 1 veya 2).
    oid = input("Enter OID: ")  # Yönetilecek nesnenin OID'si (Object Identifier).

    # PDU türüne göre paket oluşturuluyor
    if pdu_type == "get":
        # 'get' türü bir PDU için SNMP get-request paketi oluşturulur
        p = IP(dst=ip) / UDP(dport=161) / SNMP(
            version=int(ver),
            community=com_string,
            PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))])
        )
    elif pdu_type == "set":
        # 'set' türü bir PDU için SNMP set-request paketi oluşturulur
        p = IP(dst=ip) / UDP(dport=161) / SNMP(
            version=int(ver),
            community=com_string,
            PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ip + ".config")])
        )
    else:
        # Eğer geçerli bir PDU türü girilmezse, hata mesajı gösterilir ve script sonlandırılır
        print("This script is only used for get or set PDU types. QUITTING!")
        exit(1)

    # Paket gönderilip cevap beklenir
    sr(p)

# Eğer bu betik doğrudan çalıştırılırsa (import edilmezse), main() fonksiyonu çalıştırılır
if __name__ == "__main__":
    main(sys.argv[1:])  # Komut satırı argümanları main() fonksiyonuna aktarılır.
