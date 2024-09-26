def xor_encrypt_decrypt(data, key):
    # XOR işlemi ile şifreleme ve şifre çözme aynı şekilde yapılır.
    # Data ile key'i eşleştirip, her karakter için XOR işlemi yapıyoruz.
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key * (len(data) // len(key)) + key[:len(data) % len(key)]))

# Kullanım
plain_text = "Bu bir staj projesidir."  # Şifrelemek istediğimiz metin
key = "anahtar"  # Şifreleme ve şifre çözme için kullanılacak anahtar

encrypted_text = xor_encrypt_decrypt(plain_text, key)
print("Şifrelenmiş Metin:", encrypted_text)  # Şifrelenmiş metni yazdırıyoruz.

decrypted_text = xor_encrypt_decrypt(encrypted_text, key)
print("Çözülmüş Metin:", decrypted_text)  # Deşifre edilmiş metni yazdırıyoruz.
