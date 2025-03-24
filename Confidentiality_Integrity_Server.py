import socket
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
def receiver(n, g):
    y = random.randint(2, 10)
    k2 = pow(g, y, n)
    return k2, y
def shared_key_receiver(k1, y, n):
    return pow(k1, y, n)
def aes_decrypt(encrypted_message, key):
    iv = encrypted_message[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size)
    return decrypted.decode()

def check_for_integirty(decrypted_message):
    return hashlib.sha512(decrypted_message.encode()).hexdigest()

def server():
    n = int(input("Enter the value of n: "))
    g = int(input("Enter the primitive root g: "))
    k2, y = receiver(n, g)
    print("Receiver's public key:", k2)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server is waiting for a connection...")
    client_socket, addr = server_socket.accept()
    print(f"Connection established with {addr}")
    client_socket.send(str(k2).encode())
    public_sender = int(client_socket.recv(1024).decode())
    shared_key = shared_key_receiver(public_sender, y, n)
    print(f"Shared secret key: {shared_key}")
    aes_key = hashlib.sha512(str(shared_key).encode()).digest()[:16]
    hash_enc_msg = client_socket.recv(1024)
    encrypted_msg,hash_code=hash_enc_msg.split(b"***")
    decrypted_message = aes_decrypt(encrypted_msg, aes_key)
    print(f"Decrypted message: {decrypted_message}")
    print(f"Received hash code:{hash_code.decode()}")
    if(hash_code.decode() ==check_for_integirty(decrypted_message)):
        print("Integrity and Confidentiality are achieved!")
    client_socket.close()
    server_socket.close()
server()
