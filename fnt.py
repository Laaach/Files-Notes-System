import os
import sqlite3
import argparse
import hashlib
from cryptography.hazmat.primitives import serialization, hashes # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding # type: ignore
import base64
import tqdm
import time
import json

home = os.path.expanduser("~")

db_file = f"{home}/fnt/notes.db"
db_name = "fnt"
db_pub_key_file = f"{home}/fnt/.db_pub_key.pem"
db_priv_key_file = f"{home}/fnt/.db_priv_key.pem"
json_folder = f"{home}/fnt/jsons/"

try:
    try:
        db_connection = sqlite3.connect(db_file)
    except sqlite3.OperationalError:
        print("\033[1;31;4m[-] ERROR 501 - DB File doesn't exist\033[0m")
        os.system(f"touch {db_file}")
        for _ in tqdm.tqdm(range(30)):
                time.sleep(3/30)
        print(f"\033[1;32m[+] 202 New DB file was created at {db_file}\033[0m")


    parser = argparse.ArgumentParser(description="""\
\033[1;96mFNS - File Notes System.\033[0m
\033[1;97mThis script allows you to make notes for each file.\033[0m
\033[1;97mYou can copy them, move them, or whatever — the note will stay attached to your file.\033[0m
\033[1;92mALL notes are safely encrypted\033[0m \033[4;91m(Keys are saved in /home/user/.fnt/)\033[0m

\033[1;95mCODES\033[0m
\033[1;33m1xx - Something is missing\033[0m
\033[1;92m2xx - Operation succeeded\033[0m
\033[1;93m3xx - User interaction\033[0m
\033[1;91m5xx - Critical error\033[0m

\033[1;97mExample usage:\033[0m
- \033[1;94mpython3 fnt.py -f shell.php -n 'Shell for TryHackMe with address...'\033[0m \033[1;97m<-- Make note for this file\033[0m
- \033[1;94mpython3 fnt.py -f shell.php -r\033[0m \033[1;97m<-- Read saved note for this file\033[0m
- \033[1;94mpython3 fnt.py -f shell.php -d\033[0m \033[1;97m<-- Delete note for this file\033[0m
- \033[1;94mpython3 fnt.py -j fns\033[0m \033[1;97m<-- Import DB to JSON file\033[0m
- \033[1;94mpython3 fnt.py -t shell -f shell.php\033[0m \033[1;97m<-- Use 'shell' template\033[0m

\033[1;96mAvailable templates:\033[0m
\033[1;95m- Shell\033[0m
    \033[1;97m1.\033[1;93m What's lhost?\033[0m
    \033[1;97m2.\033[1;93m What's the listener port?\033[0m
\033[1;95m- Exploit\033[0m
    \033[1;97m1.\033[1;93m What's the CVE?\033[0m
    \033[1;97m2.\033[1;93m What's the vulnerable service?\033[0m
    \033[1;97m3.\033[1;93m What's the vulnerable version?\033[0m
\033[1;95m- Creds\033[0m
    \033[1;97m1.\033[1;93m What's the username?\033[0m
    \033[1;97m2.\033[1;93m What's the password?\033[0m
    \033[1;97m3.\033[1;93m What's the service that data belongs to?\033[0m
    \033[1;97m""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-f", "--file", help="Specify file")
    parser.add_argument("-n", "--note", help="Content of your note")
    parser.add_argument("-r", "--read", default=False, action="store_true", help="Read saved note")
    parser.add_argument("-d", "--delete", default=False, action="store_true", help="Delete note for specified file")
    parser.add_argument("-j", "--json", help="Select DB to import to JSON (default 'fns')")
    parser.add_argument("-t", "--template", required=False ,help="Create note according to Template")



    sign_blacklist = ['<', '>', '|', '&', ';', '$', '`', '\\', "'", '"', '*', '?', '{', '}', '~','#', '%', '!', '=', '+', ':', ',','^','\t']

    def check_for_keys():
        if os.path.isfile(db_pub_key_file) and os.path.isfile(db_priv_key_file):
            pass
        elif not os.path.isfile(db_pub_key_file) and os.path.isfile(db_priv_key_file):
            os.system(f"openssl rsa -in {db_priv_key_file} -pubout -out {db_pub_key_file} > /dev/null 2>&1")
            os.system(f"chmod 0600 {db_pub_key_file}")
        elif not os.path.isfile(db_pub_key_file) and os.path.isfile(db_priv_key_file):
            print("\033[1;31m[-] ERROR 102 - Missing private key file\033[0m")
            print("\033[1;33m[-] OPTION 1 - Purge database and generate new keys\033[0m")
            print("\033[1;33m[-] OPTION 2 - Restore all notes safely to txt file\033[0m")
            decision = str(input("\033[1;36m[!] Which option do you choose 1/2 : \033[0m"))
            
            if decision == "1":
                cursor.execute("DELETE FROM fns")
                os.system(f"rm -f {db_priv_key_file}")
                os.system(f"openssl genrsa -out {db_priv_key_file} 2048 > /dev/null 2>&1")
                os.system(f"openssl rsa -in {db_priv_key_file} -pubout -out {db_pub_key_file} > /dev/null 2>&1")
                os.system(f"chmod 0600 {db_pub_key_file}")
                os.system(f"chmod 0600 {db_priv_key_file}")
                db_connection.commit()
                print("\033[1;32m[+] 200 Done\033[0m")
                exit()
            else:
                cursor.execute(f"SELECT note FROM {db_name};")
                result = cursor.fetchall()
                notes = [w[0] if isinstance(w, tuple) else w for w in result]

                with open(db_priv_key_file , "rb") as key:
                    private_key = serialization.load_pem_private_key(key.read(), password=None)
                
                decrypted_notes = []

                for enc in notes:
                    if not enc:
                        continue
                    enc_bytes = base64.b64decode(enc)
                    decrypted = private_key.decrypt(enc_bytes,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
                    decrypted_notes.append(decrypted.decode("utf-8"))

                with open("/home/kali/.file_notes/secured_notes.txt" , "a" , encoding="utf-8") as notes:
                    notes.writelines(f"{x}\n" for x in decrypted_notes)
                
                print("\033[1;32m[+] 200 Done\033[0m")
                exit()

        else:
            print("\033[1;31m[-] ERROR 103 - Missing keys\033[0m")
            os.system(f"openssl genrsa -out {db_priv_key_file} 2048 > /dev/null 2>&1")
            os.system(f"openssl rsa -in {db_priv_key_file} -pubout -out {db_pub_key_file} > /dev/null 2>&1")
            for _ in tqdm.tqdm(range(30)):
                time.sleep(3/30)
                    
    def gen_file_fingerprint(file):
        
            if any(ch in file for ch in sign_blacklist):
                print("\033[1;31m[-] ERROR 500 Blacklisted chars found in file name\033[0m")
                exit()
            if not os.path.isfile(file):
                print("\033[1;31m[-] ERROR 100 - File not found\033[0m")
                exit()
                
            stat_info = os.stat(file)
            birthtime = str(stat_info.st_mtime)
            fingerprint = hashlib.sha256(birthtime.encode()).hexdigest()
            return fingerprint

    def check_for_file(file):
        if os.path.isfile(file):
            fingerprint_to_find = gen_file_fingerprint(file)
            cursor.execute(f"SELECT file_fingerprint FROM {db_name} WHERE file_fingerprint = '{fingerprint_to_find}'")
            result = cursor.fetchall()
            if not result:
                print("\033[1;31m[-] ERROR 104 - No match was found in DB\033[0m")
                exit()
        else:
            print("\033[1;31m[-] ERROR 100 - File not found\033[0m")
            exit()

    def insert_data_to_db(fingerprint , note , template):
        if template is not None:
            note = []
            questions = what_template_use(template)
            for question in questions:
                answer =input(question)
                note.append(f"{question} {answer}")
            note = "\n".join(note)
        else:
            pass
            template = "NONE"
    

        with open(db_pub_key_file, "rb") as key:
            public_key = serialization.load_pem_public_key(key.read())

        encrypted_note = public_key.encrypt(note.encode("utf-8"),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        encrypted_note = base64.b64encode(encrypted_note).decode("utf-8")
        cursor.execute(f"INSERT OR REPLACE INTO {db_name} (file_fingerprint , note , template_used) VALUES ('{fingerprint}' , '{encrypted_note}' , '{template}');")
        db_connection.commit()

    def read_note(file):
        with open(db_priv_key_file , "rb") as key:
            private_key = serialization.load_pem_private_key(key.read(), password=None)

        check_for_file(file)
        fingerprint_to_find = gen_file_fingerprint(file)
        cursor.execute(f"SELECT note FROM {db_name} WHERE file_fingerprint = '{fingerprint_to_find}';")
        result = cursor.fetchone()
        if not result:
            return None
        encrypted_note = base64.b64decode(result[0])
        decrypted = private_key.decrypt(encrypted_note, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return decrypted.decode("utf-8")

    def delete_note(file):
        fingerprint_to_find = gen_file_fingerprint(args.file)
        check_for_file(file)
        cursor.execute(f"DELETE FROM {db_name} WHERE file_fingerprint = '{fingerprint_to_find}'")
        db_connection.commit()

    def import_to_json(db):
        cursor.execute(f"SELECT * FROM {args.json};")
        result = cursor.fetchall()
        try:
            if not result:
                print("\033[1;31m[-] ERROR 502 - DB is empty\033[0m")
                exit()

            timestamp = int(time.time())
            json_file = str(f"JNotes{timestamp}.json")

            with open(db_priv_key_file , "rb") as priv_key:
                private_key = serialization.load_pem_private_key(priv_key.read(), password=None)


            json_structure = {
                "export_date": time.strftime("%Y-%m-%d %H:%M:%S") ,
                "database_name": args.json ,
                "timestamp": timestamp ,
                "total_amount_of_notes": len(result) ,
                "records":[]
            }

            for file_fingerprint, note in result:
                
                json_structure['records'].append({
                    "file_fingerprint": file_fingerprint ,
                    "note": note,
                })

            save_path = os.path.join(json_folder, json_file)

            with open(save_path ,"w" , encoding="utf-8") as json_file:
                json.dump(json_structure , json_file , indent=2)
        except Exception as e:
            print(f"\033[1;31m[-] ERROR 503 - Export failed: {e}\033[0m")
            exit()
        
        
        print(f"\033[1;32m[+] 202 Database exported successfully (Saved in {save_path})\033[0m")
        exit()

    def what_template_use(template):
        templates = {
        "shell": ["What is lhost: ", "What is the listener port: "],
        "exploit": ["What is cve: ", "What is the vulnerable service: ", "What is the vulnerable version: "],
        "creds": ["What is the username: ", "What is the password: ", "What is the service that data belongs to: "]
    }

        if template in templates:
            return templates[template]
        else:
            print("\033[1;31;4m[-] ERROR 502 - No such template\033[0m")
            exit()
            

    try:
        cursor = db_connection.cursor()
    except NameError:
        print("\033[1;31;4m[-] ERROR 501 - Checks path in code for DB\033[0m")

    args = parser.parse_args()


    template = args.template
    try:
        template = template.lower()
    except Exception:
        pass

    sqlite_new_table = f"CREATE TABLE IF NOT EXISTS {db_name} (file_fingerprint TEXT PRIMARY KEY, note TEXT NOT NULL , template_used TEXT);"
    cursor.execute(sqlite_new_table)

    check_for_keys()

except KeyboardInterrupt:
    print("\033[1;31m[-] ERROR 300 - Stopped by user (CTRL+C)\033[0m")

if args.read:
    if not args.file:
        print("\033[1;31m[-] ERROR 100 - No file specified. Use -f <file>\033[0m")
        exit(1)
    os.system("clear")
    print(f"\033[1;33mNOTE FOR {args.file}:\033[0m\n")
    note = read_note(args.file)
    if not note:
        print("\033[1;31m[-] No saved note for this file\033[0m")
        exit(0)
    print(note)
    exit(0)
elif args.note is not None or args.template is not None:
    if not args.file:
        print("\033[1;31m[-] ERROR 100 - No file specified. Use -f <file>\033[0m")
        exit(1)
    insert_data_to_db(gen_file_fingerprint(args.file), args.note, args.template if args.template else None)
    print(f"\033[1;32m[+] 200 Note for {args.file} saved.\033[0m")
    exit(0)
elif args.delete:
    if not args.file:
        print("\033[1;31m[-] ERROR 100 - No file specified. Use -f <file>\033[0m")
        exit(1)
    delete_note(args.file)
    print(f"\033[1;32m[+] 201 Note for {args.file} has been deleted.\033[0m")
    exit(0)
elif args.json is not None:
    import_to_json(args.json)
    exit(0)



