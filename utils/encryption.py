from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#AES 32 -> 256, 16 -> 128
def generate_key(bytes=32):
    return  get_random_bytes(bytes)

def store_key(key):
    try:
        with open(".venv", "wb") as f:
            f.write(key)
            return 0
    except Exception as err:
        print(err)
        return 1

def read_key():  
    try:
        with open(".venv", "rb") as f:
            key = f.read()
            return key
    except Exception as err:
        print(err)
        return 1  


#returns a cipher
def enc_cipher(key, mode=AES.MODE_CTR):
    cipher =  AES.new(key, mode)   
    return cipher

def dec_cipher(key, nonce, mode=AES.MODE_CTR):
    decrypt_cipher = AES.new(key, mode, nonce=nonce)
    return decrypt_cipher

#returns ciphertext and nonce
def custom_encrypt(cipher, data):
    data = bytes(data, 'utf-8')
    cipher_text = cipher.encrypt(data)
    nonce = cipher.nonce
    return (cipher_text, nonce)

def custom_decrypt(cipher, cipher_text):
    plain_text = cipher.decrypt(cipher_text)
    return bytes.decode(plain_text, 'utf-8')

''' 
key = generate_key()
print(key)
store_key(key)
key = read_key()
print(key)
cipher = enc_cipher(key)
print(cipher)
ct, n = custom_encrypt(cipher, "hello")
print(ct)
print(n)
dc = dec_cipher(key,n)
print(dc)
pt = custom_decrypt(dc, ct)
print(pt)
'''