**1. LAN (Local Area Network)**

A LAN is a network that connects computers and devices in a small, localized area—like your home, office, or school—so they can communicate with each other and share resources like files, printers, or applications.

Key points:

Covers small geographic area (e.g., one building).

Uses Ethernet cables or Wi-Fi.

Devices in a LAN can talk directly using private IP addresses (like 192.168.x.x).

LANs are internal and usually not directly connected to the internet (though they can be).

Example:
Your office computers connected to the same Wi-Fi router form a LAN. If you host a web app on one PC, others on the same LAN can access it.

---

**2. DNS (Domain Name System)**

DNS is like the phonebook of the internet or a network. It converts human-friendly names into IP addresses that computers use to communicate.

Key points:

Makes it easier to access resources. Instead of typing 192.168.1.100, you can type myapp.local.

Works on internet (global DNS) and internal networks (internal DNS).

Internal DNS is optional; without it, you can still access your app using the IP address directly.

Example:

Internal network: You set myapp.local → 192.168.1.100 in DNS or hosts file.

Now, typing myapp.local in a browser takes you to your server, no IP memorization needed.

---

| Feature        | LAN (Local Area Network)                                                   | DNS (Domain Name System)                                                            |
| -------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **What it is** | A network that connects computers/devices in a small area (office/home).   | A system that converts human-friendly names (like `myapp.local`) into IP addresses. |
| **Purpose**    | Allows devices to communicate, share files, printers, and apps internally. | Makes it easy to access devices or websites without remembering numeric IPs.        |
| **Scope**      | Physical or wireless network in a building or small area.                  | Logical system that works on LAN or internet.                                       |
| **Example**    | Your office computers connected to the same Wi-Fi or router.               | Mapping `192.168.1.100 → myfastapi.local` so you can type a name instead of an IP.  |
| **Type**       | Hardware/network concept.                                                  | Software/service concept.                                                           |
| **Dependency** | Needed for devices to connect internally.                                  | Optional; only helps with easier addressing.                                        |


LAN = the roads connecting your computers.

DNS = the signboards that tell you where to go on those roads.

---

**simple FastAPI example that you can deploy internally on Windows over a LAN without internet**

**Step 1: Install Python
**
Download Python 3.x offline installer from python.org
 and install it.

Make sure “Add Python to PATH” is checked.

**Step 2: Create Your FastAPI App**

Open a folder, e.g., C:\FastAPIApp

Create a file main.py:

```text
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello LAN!"}

@app.get("/users/{name}")
def read_user(name: str):
    return {"message": f"Hello {name} from LAN"}
```

**Step 3: Install FastAPI and Waitress**

Since you don’t want internet, download offline wheels on another machine if needed.

Install locally:
```text
pip install fastapi
pip install waitress
```

**Step 4: Run the App on LAN**

Open Command Prompt in C:\FastAPIApp:

```text
python -m waitress --listen=*:8000 main:app
```

* → all IPs on the machine

8000 → port number

Now your app is running.

**Step 5: Find Your LAN IP**

Open Command Prompt:

```text
ipconfig
```

Look for IPv4 Address under your network adapter, e.g., 192.168.1.100.

**Step 6: Access from Another Computer in LAN**

On any PC in the same LAN, open a browser:

http://192.168.1.100:8000/

```text
{"message": "Hello LAN!"}
```

And for dynamic route:

```text

http://192.168.1.100:8000/users/Chitra

```

Returns:
```text

{"message": "Hello Chitra from LAN"}
```

---

**Optional: Friendly Name (DNS or Hosts File)**

If you don’t want to type IP every time:

1. On each PC, edit the hosts file:

```text

C:\Windows\System32\drivers\etc\hosts
```

2. Add line:

```text
192.168.1.100 myfastapi.local
```

3. Now open browser:
```text
http://myfastapi.local:8000/
```