import hashlib  # Hashing işlemleri için hashlib kütüphanesini kullanıyoruz.

def generate_md5_hash(text):
    # MD5 hash objesi oluşturuyoruz ve metni encode ederek hashliyoruz.
    hash_object = hashlib.md5(text.encode())
    return hash_object.hexdigest()  # Hashin hexadecimal temsilini döndürüyoruz.

# Kullanım
plain_text = "Bu bir staj projesidir."  # Hashlemek istediğimiz metin
md5_hash = generate_md5_hash(plain_text)
print(f"{plain_text} için MD5 Hash:", md5_hash)  # Hashlenmiş metni yazdırıyoruz.
