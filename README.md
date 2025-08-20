#  _SocketChat_

**SocketChat** is a personal project showcasing an **end-to-end encrypted chat system** built with Python.  
It combines **sockets**, **threading**, and a **JSON-based communication protocol** to provide a secure and functional chat experience.

---

##  Features
### Account system  
  - Create accounts with **bcrypt-hashed passwords**  
  - Login with retry limits (`MAX_ATTEMPTS`)  
-  **End-to-end encryption**  
  - All messages encrypted with **Fernet symmetric encryption**  
### Chat commands 
  - `/createaccount` – Register a new user  
  - `/login` – Authenticate existing user  
  - `/dm <user> <message>` – Send private messages  
  - `/users` – List all online users  
  - `/help` – Show available commands  
  - `/quit` – Leave the chat  
### Threaded architecture
  - Separate threads for **sending** and **receiving** (non-blocking chat)  
### User experience improvements 
  - Colored CLI output with `colorama`  
  - Structured error handling  

---

##  Technologies Used
- **Python Sockets** – low-level networking  
- **Threading** – concurrency for I/O operations  
- **Fernet (cryptography)** – symmetric message encryption  
- **bcrypt** – secure password hashing  
- **dotenv** – environment variable management  
- **colorama** – CLI styling  

---

##  Getting Started

### Clone the repository and Run Scripts
```bash
git clone https://github.com/kosmits-ai/_SocketChat_.git
cd SocketChat
python server.py    #In one terminal window
python client.py    #In different terminal windows, one for each client.
```
