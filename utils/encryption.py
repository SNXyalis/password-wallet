from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#AES 32 -> 256, 16 -> 128
def generate_key(bytes=32):
    return  get_random_bytes(bytes)

def generate_nonce(bytes=8):
    return get_random_bytes(bytes)

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
def enc_cipher(key, nonce, mode=AES.MODE_CTR):
    cipher =  AES.new(key, mode, nonce=nonce)   
    return cipher

def dec_cipher(key, nonce, mode=AES.MODE_CTR):
    decrypt_cipher = AES.new(key, mode, nonce=nonce)
    return decrypt_cipher

#returns ciphertext and nonce
def custom_encrypt(cipher, data):
    data = bytes(data, 'utf-8')
    cipher_text = cipher.encrypt(data)
    return cipher_text

def custom_decrypt(cipher, cipher_text):
    plain_text = cipher.decrypt(cipher_text)
    return bytes.decode(plain_text, 'utf-8')

'''
#KEY-RESET
key = generate_key()
store_key(key)

#ENCRYPTION
n = generate_nonce()
key = read_key()
#needs key, plaintext
cipher = enc_cipher(key, n)
ct = custom_encrypt(cipher, "hello")
message = n + ct

###DECRYPTION
#needs key, nonce, ciphertext
print(message[:8]) # nonce
print(message[8:]) # ciphertext
dc = dec_cipher(key,n)
pt = custom_decrypt(dc, ct)
print(pt)
'''