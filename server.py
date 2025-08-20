import socket
import threading
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import json
import bcrypt
load_dotenv()
from colorama import Fore,Style
import struct


MAX_ATTEMPTS = 5

key = os.getenv("FERNET_KEY")

if not key:
    raise RuntimeError("Missing FERNET_KEY in environment.")

fernet = Fernet(key.encode())
client_sockets = {}
clients = []
users = {}

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



def handle_traffic(clientsocket):
    attempts = 0
    while True:
        try:
            msg = recv_msg(clientsocket)
            print(Fore.LIGHTBLUE_EX + f"\nEncrypted message len: {len(msg)}\n" + Style.RESET_ALL)
            decrypt_msg = fernet.decrypt(msg).decode("utf-8")
            data = json.loads(decrypt_msg)
            authenticated = (clientsocket in clients)
            allowed = True
            if not authenticated:
                allowed = (data["msg"].startswith("/login") or
                data["msg"].startswith("/createaccount") or
                data["msg"] in {"/help", "/quit", "/users"})
            if not allowed:
                send_encrypted(clientsocket, {"user":"server","msg":"Please /login first (or /createaccount)."})
                continue
            
            if data["msg"] == "/help":
                response = {
                    "user" : "server",
                    "msg": """Available commands:
                            /quit      - Exit chat
                            /dm USER   - Private message
                            /users     - Show online users
                            /help      - Show this menu
                            /createaccount       - Create your new account
                            /login       - Login to existing account"""
                }

                send_encrypted(clientsocket, response)
            
            elif data["msg"].startswith("/dm"):
                #/dm Bob Hi bob
                parts = data["msg"].split(maxsplit=2)
                if len(parts) < 3 or not parts[2].strip():
                    message = {"user": "server", "msg": "Usage: /dm <user> <message>"}
                    send_encrypted(clientsocket, message)
                    continue

                _,to_person, content = parts
                
                if to_person in client_sockets:
                        dm = {
                            "user": data["user"],
                            "msg": content
                        }
                        recipient = client_sockets[to_person]
                        send_encrypted(recipient, dm)
                else:
                    dm_fail = {
                        "user": "server",
                        "msg" : f"{to_person} not found.Could not forward the message"
                    }
                    send_encrypted(clientsocket, dm_fail)


            elif data["msg"] == "/users":
                online_users = ', '.join(client_sockets.keys())
                info = {
                        "user":"server",
                        "msg": f"Online are: {online_users}"
                    }
                send_encrypted(clientsocket, info)
            
            elif data["msg"] == "/createaccount":
                username = data.get("user")
                password = data.get("password")
                if username in users:
                    error = {
                        "user": "server",
                        "msg": f"Username '{username}' is already taken. Please try again."
                    }
                    send_encrypted(clientsocket, error)
                    continue
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() #bcrypt need bytes args and return bytes
                users[username] = pw_hash

                print(Fore.GREEN + (f"{username} just created account.\n") +  Style.RESET_ALL)
                join_msg = {
                    "user": "server",
                    "msg": f"{username} just created account."
                }
                for client in clients:
                    if client != clientsocket:
                        send_encrypted(client, join_msg)

                welcome = {
                    "user": "server",
                    "msg": f"Welcome, {username}! Now please do /login."
                }
                send_encrypted(clientsocket, welcome)
                
            elif data["msg"] == "/login":
                print(f"Registered users: {list(users.keys())}")
                username = data.get("user")
                password = data.get("password")
                print(f"Trying to login as {username}")
                print(f"Registered users: {list(users.keys())}")
                if username in users and bcrypt.checkpw(password.encode(), users[username].encode()):
                    attempts = 0
                    print(Fore.GREEN + f"{username} successfully logged in." + Style.RESET_ALL)
                    login_msg = {
                        "user": "server",
                        "msg": f"{username} just logged in."
                    }
                    
                    if clientsocket not in clients:
                        clients.append(clientsocket)
                    client_sockets[username] = clientsocket


                    for client in clients:
                        if client != clientsocket:
                            try:
                                send_encrypted(client, login_msg)
                            except:
                                print("Could not send to client; removing.")
                                clients.remove(client)

                    welcome_msg = {
                        "user": "server",
                        "msg": f"Welcome back, {username}! Type /help to see commands."
                    }
                    
                    try:
                        send_encrypted(clientsocket, welcome_msg)
                    except Exception as e:
                        print(f"Failed to send welcome: {e}")
                        clients.remove(clientsocket)
                        clientsocket.close()
                    
                else:
                    attempts +=1
                    if attempts <= MAX_ATTEMPTS:
                        print(Fore.RED + f"This username or password do not exist." + Style.RESET_ALL)
                        failed_msg = {
                        "user": "server",
                        "msg": "Make sure you entered the right username and password."
                    }
                        send_encrypted(clientsocket, failed_msg)
                        continue
                    else:
                        failed_max_attempts = {
                            "user": "server",
                            "msg": "Too many failed attempts. Disconnecting..."
                        }
                        send_encrypted(clientsocket, failed_max_attempts)
                        clientsocket.close()
                        break

            elif data["msg"] == "/quit":
                username = data["user"]
                response = {
                    "user": "server",
                    "msg": f"{username} has left the chat."
                }
                for client in clients:
                    if client != clientsocket:
                        send_encrypted(client, response)
                
                if username in client_sockets:
                    del client_sockets[username]
                if clientsocket in clients:
                    clients.remove(clientsocket)
                
                clientsocket.close()
                print(Fore.RED + f"\n{username} disconnected." + Style.RESET_ALL)
                break
                

            else:
                for client in clients:
                    if client != clientsocket:
                        send_encrypted(client, {"user": data["user"], "msg": data["msg"]})
        
        except:
            user_to_remove = None
            
            for name, sock in client_sockets.items():
                
                if sock == clientsocket:
                    user_to_remove = name
                    break

            if user_to_remove:
                del client_sockets[user_to_remove]
            if clientsocket in clients:
                clients.remove(clientsocket)

            clientsocket.close()
            break

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #use IPv4 and TCP
s.bind(("0.0.0.0", 1234)) #I’ll accept connections on port 1234 for any IP address that belongs to this machine.
s.listen(5) #how many connections can wait to the line until accept

while True:
    clientsocket, address = s.accept() #new object and (address,port) tuple of client
    print(Fore.MAGENTA + f"Connection from {address} has been established."+ Style.RESET_ALL)

    threading.Thread(target = handle_traffic, args = (clientsocket, )).start() #multi-thread arg is a tuple, threads nice for I/O, same CPU, lightweight
    