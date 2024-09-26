import hashlib  # Hashing işlemleri için hashlib kütüphanesini kullanıyoruz.

def generate_sha256_hash(text):
    # SHA-256 hash objesi oluşturuyoruz ve metni encode ederek hashliyoruz.
    hash_object = hashlib.sha256(text.encode())
    return hash_object.hexdigest()  # Hashin hexadecimal temsilini döndürüyoruz.

# Kullanım
plain_text = "Bu bir staj projesidir."  # Hashlemek istediğimiz metin
sha256_hash = generate_sha256_hash(plain_text)
print(f"{plain_text} için SHA-256 Hash:", sha256_hash)  # Hashlenmiş metni yazdırıyoruz.
