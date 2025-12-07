# FNS – File Notes System  
**Attach encrypted notes to any file – forever.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)  
![Security](https://img.shields.io/badge/security-RSA%202048%20%2B%20OAEP-green)  
![CTF](https://img.shields.io/badge/CTF-Friendly-red)  
![Kali](https://img.shields.io/badge/Kali-Linux-lightgrey)

---

## What is FNS?

> **You found a shell, a credential, an exploit…**  
> But how do you **remember** what it does **when you come back later**?

`FNS` lets you **attach a secure note to any file** using its **unique fingerprint** (based on `mtime`).  
Even if you **move, copy, or rename** the file — the note **stays attached**.

**All notes are encrypted with RSA-4096 + OAEP**  
Keys stored in: `~/.fnt/.db_priv_key.pem` (private) | `.db_pub_key.pem` (public)

---

## Features

| Feature | Description |
|-------|-----------|
| **Encrypted Notes** | RSA-4096 + SHA256 OAEP |
| **File Fingerprinting** | Uses `st_mtime` → survives copy/move |
| **Templates** | `shell`, `exploit`, `creds` |
| **JSON Export** | Backup all notes securely |
| **Blacklist Protection** | Blocks shell metachars |

---

## Installation

```bash
# Clone the repo
git clone https://github.com/Laaach/Files-Notes-System.git
cd Files-Notes-System

# Install dependencies
pip3 install cryptography tqdm

```
---

### **Example 1: Reverse Shell Note**

```bash
┌──(kali㉿kali)-[~/loot]
└─$ python3 ~/fnt/fnt.py -f shell.php -t shell
What is lhost: 10.8.5.123
What is the listener port: 9001
[+] 200 Note for webshell_10.10.10.123.php saved.
```

### **Example 2: Credential storage**
```bash
┌──(kali㉿kali)-[~/htb]
└─$ python3 ~/fnt/fnt.py -f id_rsa_john -t creds
What is the username: john
What is the password: P@ssw0rd!2025
What is the service that data belongs to: SSH @ 10.10.11.150
[+] 200 Note for id_rsa_john saved.
```

