#ceaser cipher
import string

#MD5 and SHA256
import hashlib

#AES
import base64 
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def encryption_via_cipher(message):
    shift=int(input("Select a number of shifts (preferrably 5+): "))
    alphabet=string.ascii_lowercase
    shifted=alphabet[shift:]+alphabet[:shift]
    table=str.maketrans(alphabet, shifted)
    encrypted=message.translate(table)
    return encrypted
    #print(f"Original Message: {password} , Encrypted Message: {encrypted}")

def encryption_via_md5(message):
    encrypted=hashlib.md5(message.encode()).hexdigest()
    return encrypted
    #print (f"Original Message: {password} , Encrypted Message via MD5: {encrypted}")

def encryption_via_sha256(message):
    encrypted=\
    hashlib.sha256(message.encode()).hexdigest()
    return encrypted
    #print (f"Original Message: {password} , Encrypted Message via SHA 256: {encrypted}")


def encryption_via_aes(message):
    key=get_random_bytes(16)
    initVector=get_random_bytes(16)
    cipher=AES.new(key, AES.MODE_EAX, nonce=initVector)
    enc=cipher.encrypt(message.encode())
    encrypted2=base64.b64encode(initVector+enc).decode('utf-8')
    return encrypted2
    #print (f"Original Message: {password} , Encrypted Message via AES: {encrypted2}")



def encryption_via_base64(message):
    message_bytes=message.encode("ascii")
    base64_bytes=base64.b64encode(message_bytes)
    base64_string=base64_bytes.decode("ascii")
    return base64_string
    #print (f"Original Message: {password} , Encrypted Message via Base 64: {base64_string}")

def encryption_via_each(message):
    print("\n----- Encrypting using all methods -----\n")
    encrypted = encryption_via_cipher(message)
    print(f"Caesar Cipher: {encrypted}")
    encrypted = encryption_via_md5(message)
    print(f"MD5: {encrypted}")
    encrypted = encryption_via_sha256(message)
    print(f"SHA256: {encrypted}")
    encrypted = encryption_via_aes(message)
    print(f"AES: {encrypted}")
    encrypted = encryption_via_base64(message)
    print(f"Base64: {encrypted}")
    print("\n----- All encryptions completed -----\n")

def encryption_via_all(message):
    print("\n----- Encrypting sequentially using all methods -----\n")
    encrypted = encryption_via_cipher(message)
    print(f"After Caesar Cipher: {encrypted}")
    
    encrypted = encryption_via_md5(encrypted)
    print(f"After MD5: {encrypted}")
    
    encrypted = encryption_via_sha256(encrypted)
    print(f"After SHA256: {encrypted}")
    
    encrypted = encryption_via_aes(encrypted)
    print(f"After AES: {encrypted}")
    
    encrypted = encryption_via_base64(encrypted)
    print(f"After Base64: {encrypted}")
    
    print("\n----- All encryptions completed -----\n")
    return encrypted


password=input("Please enter the password/message you want to encrypt: ")

print("\nChoose what type of encryption you want to use?\n")
print("(1) for encyryption via CEASER CIPHER")
print("(2) for encryption via MD5")
print("(3) for encryption via SHA256")
print("(4) for encryption via AES")
print("(5) for encryption via BASE65")
print("(6) shows encryption for each method")
print("(7) encrypts your message using all methods\n")

method=input("Enter only the number: ")

if method == "1":
    result = encryption_via_cipher(password)
    print(f"Original Message: {password} , Encrypted Message: {result}")
elif method == "2":
    result = encryption_via_md5(password)
    print (f"Original Message: {password} , Encrypted Message via MD5: {result}")
elif method == "3":
    result = encryption_via_sha256(password)
    print (f"Original Message: {password} , Encrypted Message via SHA 256: {result}")
elif method == "4":
    result = encryption_via_aes(password)
    print (f"Original Message: {password} , Encrypted Message via AES: {result}")
elif method == "5":
    result = encryption_via_base64(password)
    print (f"Original Message: {password} , Encrypted Message via Base 64: {result}")
elif method == "6":
    result = encryption_via_each(password)
elif method == "7":
    result = encryption_via_all(password)
    print(f"Original Message: {password} , Final Encyrpted Message: {result}")
else: 
    print("\n------------------------")
    print("Invalid Method Selected")
    print("------------------------\n")



