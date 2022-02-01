# cli programm  to save and load files encrypted with AES

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import hashlib
import re
import json


def encrypt(key, source, encode=True):
    if source is None:
        return None
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data


def decrypt(key, source, decode=True):
    if source is None:
        return None
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")
    return data[:-padding]


def append_key(key, value):
    data["vault"][encrypt(my_password, name.encode())] = encrypt(my_password, value.encode())
    with open("vault.json", "w") as outfile:
        json.dump(data, outfile, indent=4)


def load_key(key):
    return None


data = json.load(open("vault.json"))

if data["password"]:
    my_password = input("Enter password: ").encode()
    while hashlib.sha256(my_password).hexdigest() != data["password"]:
        print("Wrong password")
        my_password = input("Enter password: ").encode()
else:
    my_password = input("Select password for the Vault: ").encode()
    data["password"] = hashlib.sha256(my_password).hexdigest()
    json.dump(data, open("vault.json", "w"), indent=4)

print("commands: store, load, delete, quit")
print("You have {0} keys in your vault".format(len(data["vault"])))
while True:
    command = input("secure-save> ").strip()
    if '"' in command:
        command = re.split(r' (?=")', command)
        for i in range(len(command)):
            command[i] = command[i].replace('"', '')
    else:
        command = command.split(" ")
    if command[0] == "store":
        if len(command) != 3:
            print("usage: store <name> <password>")
            continue
        name, password = command[1:]
        if load_key(name):
            if input("Key already exists. Overwrite? (y/n) ").lower() != "y":
                continue
        append_key(name, password)
    elif command[0] == "load":
        if len(command) != 1:
            print("usage: load")
            continue
        decrypted_name = []
        for key, value in data["vault"].items():
            decrypted_name.append([decrypt(my_password, key).decode(), decrypt(my_password, value).decode()])
        if len(decrypted_name) > 0:
            max_1 = max([len(x[0]) for x in decrypted_name]) + 2
            max_2 = max([len(x[1]) for x in decrypted_name]) + 2
            print("{:<{}}  {:<{}}".format("Name", max_1, "Value", max_2))
            for entry in decrypted_name:
                print("{:<{}}  {:<{}}".format(entry[0], max_1, entry[1], max_2))

    elif command[0] == "delete":
        if len(command) != 2:
            print("delete <name>")
            continue
        name = command[1]
        if name in data["vault"]:
            del data["vault"][name]
            with open("vault.json", "w") as outfile:
                json.dump(data, outfile, indent=4)
            continue
        print("Name not found")
    elif command[0] == "quit":
        print("ByeBye!")
        break
    else:
        print("Unknown command")
