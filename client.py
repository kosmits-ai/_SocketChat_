import socket
import threading
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import json
from colorama import Fore, Back, Style
import getpass
import struct

username = None

load_dotenv()
key = os.getenv("FERNET_KEY")

if not key:
    raise RuntimeError("Missing FERNET_KEY in environment.")

fernet = Fernet(key.encode())


def send_msg(sock, payload: bytes):
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_exact(sock, n:int) -> bytes:       #In TCP streams order of data bytes is guaranteed but how many are sent in each chunk is not. Maybe in kernel will be 100 bytes available or 30. That's why i use this loop.To be sure that whole length can be handled.
    buf = b""                               #n determines message length
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf

def recv_msg(sock):
    (ln, ) = struct.unpack("!I", recv_exact(sock, 4)) #receive exact the 4 byte header and unpack it.
    if ln > 1_000_000:
        raise ValueError(f"Message too large: {ln}")    #securty check for malicious big headers
    return recv_exact(sock, ln)     #can receive the true length


def send_encrypted(shock, data):
    json_msg = json.dumps(data).encode("utf-8")
    encrypted_msg = fernet.encrypt(json_msg)
    send_msg(shock, encrypted_msg)

def receive(shock):
    while True:
        try:
            msg = recv_msg(shock)
            if not msg:
                print(Fore.RED + "Server closed the connection." + Style.RESET_ALL)
                break

            try:
                decrypted_json = fernet.decrypt(msg).decode()
                parsed = json.loads(decrypted_json)
                user = parsed["user"]
                message = parsed["msg"]
                print(Fore.YELLOW + f"\n[{user}]: {message}" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"Decryption or JSON parsing failed: {e}" + Style.RESET_ALL)
                break

        except ConnectionResetError as e:
            print(Fore.RED + f"Server forcibly closed the connection: {e}" + Style.RESET_ALL)
            break
        except Exception as e:
            print(Fore.RED + f"Receive thread error: {e}" + Style.RESET_ALL)
            break

    shock.close()


def set_username():
    name = input(Fore.BLUE + "\nWhats your username? " + Style.RESET_ALL) 
    return name
    
def set_password():
    password = getpass.getpass(Fore.BLUE + "\nWhats your password? " + Style.RESET_ALL) 
    return password
    
    


def send(shock):
    global username
    while True:
        msg = input("\n")

        if msg  == "/createaccount":
            username = set_username()
            password = set_password()
            connect_data = {
                "user": username,
                "msg": "/createaccount",
                "password": password
            }
            send_encrypted(shock, connect_data)

        elif msg == "/login":
            username = set_username()
            password = set_password()
            login_data = {
                "user": username,
                "msg": "/login",
                "password": password
            }
            send_encrypted(shock, login_data)
        elif msg == "/quit":
            data = {
                "user": username or "client",
                "msg": "/quit"
            }
            send_encrypted(shock, data)
            shock.close()
            break
        elif msg =="/help":
            data = {
                "user": username or "client",
                "msg": "/help"
            }
            send_encrypted(shock, data)
        elif msg == "/users":
            data ={
                "user" : username or "client",
                "msg" : "/users"
            }
            send_encrypted(shock, data)
        else:
            if not username:
                print("Please /login first.")
                continue
            data = {
                "user": username,
                "msg": msg
            }
            send_encrypted(shock, data)
            
           
        

shock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
shock.connect(("127.0.0.1", 1234))

threading.Thread(target = receive, args = (shock, )).start() #multi-threads for receiving messages

threading.Thread(target= send, args = (shock, )).start() #multi-threads for sending messages

#we use threads as recv() and input() in receive and send funcs are blocking calls.
#in order to be able to receive and send messages we must use threads or asyncio.

#add hash for server side password security JSON?
#test it
#see other fixes
#push to github
#mini showcasee vjdek
#what i learn?
