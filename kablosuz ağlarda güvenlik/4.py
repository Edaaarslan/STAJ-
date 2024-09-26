import hashlib
import os

def crack_password(hash, wordlist):
    # Wordlist dosyasının tam yolunu al
    if not os.path.isfile(wordlist):
        print(f"File not found: {wordlist}")
        return None

    # Wordlist dosyasını aç
    with open(wordlist, 'r') as file:
        # Her satırı tek tek okuyoruz
        for word in file:
            # Her satırdaki parolayı al ve boşlukları temizle
            word = word.strip()
            # Parolanın hash'ini oluştur
            hash_attempt = hashlib.sha1(word.encode()).hexdigest()
            # Eğer oluşturulan hash, hedef hash ile eşleşiyorsa
            if hash_attempt == hash:
                print(f"Password found: {word}")  # Parolayı yazdır
                return word  # Parolayı döndür
    print("Password not found.")  # Parola bulunamadıysa
    return None

if __name__ == "__main__":
    handshake_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"  # Kırılacak olan hash (örnek hash)
    wordlist = "C:\\path\\to\\your\\rockyou.txt"  # Sözlük dosyasının tam yolu
    crack_password(handshake_hash, wordlist)
