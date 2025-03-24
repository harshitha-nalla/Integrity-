import hashlib

msg=input("Enter the message to be hashed:")
hash_res=hashlib.sha512(msg.encode())
print("The hashed value is:",hash_res.hexdigest())