def ceasar_cipher(text, shift):
    encrypted_text = ""  # Şifrelenmiş metni saklamak için boş bir string oluşturuyoruz.

    for char in text:  # Metindeki her karakteri tek tek ele alıyoruz.
        if char.isalpha():  # Sadece alfabetik karakterleri şifrelemek istiyoruz.
            shift_char = ord(char) + shift  # Karakterin ASCII değerini alıp, kaydırma değeri ekliyoruz.

            if char.islower():  # Küçük harflerle karşılaşırsak:
                if shift_char > ord('z'):  # Eğer 'z' harfinden öteye kaydıysa:
                    shift_char -= 26  # Tekrar alfabenin başına döndürmek için 26 çıkartıyoruz.
                encrypted_text += chr(shift_char)  # Şifrelenmiş karakteri metne ekliyoruz.
            elif char.isupper():  # Büyük harflerle karşılaşırsak:
                if shift_char > ord('Z'):  # Eğer 'Z' harfinden öteye kaydıysa:
                    shift_char -= 26  # Tekrar alfabenin başına döndürmek için 26 çıkartıyoruz.
                encrypted_text += chr(shift_char)  # Şifrelenmiş karakteri metne ekliyoruz.
        else:
            encrypted_text += char  # Eğer karakter alfabetik değilse, olduğu gibi bırakıyoruz.

    return encrypted_text  # Şifrelenmiş metni döndürüyoruz.

def ceasar_decipher(cipher_text, shift):
    # Deşifreleme işlemi için, şifreleme işlemini tersine çeviriyoruz.
    return ceasar_cipher(cipher_text, -shift)

# Kullanım
plain_text = "Bu bir staj projesidir. Ve sifreleme saglanmalidir. "  # Şifrelemek istediğimiz metin
shift_value = 3  # Her karakteri alfabede 3 harf sağa kaydırıyoruz.

encrypted_text = ceasar_cipher(plain_text, shift_value)
print("Şifrelenmiş Metin:", encrypted_text)  # Şifrelenmiş metni yazdırıyoruz.

decrypted_text = ceasar_decipher(encrypted_text, shift_value)
print("Çözülmüş Metin:", decrypted_text)  # Deşifre edilmiş metni yazdırıyoruz.
