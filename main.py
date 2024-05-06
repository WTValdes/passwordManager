from cryptography.fernet import Fernet
import os
import tkinter as tk
from tkinter import messagebox

def generate_key():
    key = Fernet.generate_key()
    return key

def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    encoded_password = password.encode('utf-8')
    encrypted_password = cipher_suite.encrypt(encoded_password)
    return encrypted_password

def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password)
    return decrypted_password.decode('utf-8')

def store_passwords(passwords, key):
    with open('passwords.txt', 'ab') as f:
        for password in passwords:
            encrypted_password = encrypt_password(password, key)
            f.write(encrypted_password + b'\n')

def load_passwords(key):
    passwords = []
    with open('passwords.txt', 'rb') as f:
        for line in f:
            encrypted_password = line.strip()
            password = decrypt_password(encrypted_password, key)
            passwords.append(password)
    return passwords



def remove_password(password, key):
    passwords = load_passwords(key)
    passwords.remove(password)
    with open('passwords.txt', 'wb') as f:
        for pw in passwords:
            encrypted_password = encrypt_password(pw, key)
            f.write(encrypted_password + b'\n')

def main():
    if not os.path.exists('key.key'):
        key = generate_key()
        with open('key.key', 'wb') as f:
            f.write(key)
    else:
        with open('key.key', 'rb') as f:
            key = f.read()

    def store_password():
        website = entry_website.get()
        username = entry_username.get()
        password = entry_password.get()
        if website and username and password:
            passwords = load_passwords(key)
            new_password = f"{website}: {username}: {password}"
            for pw in passwords:
                pw_website, pw_username, _ = pw.split(': ')
                if pw_website == website and pw_username == username:
                    overwrite = messagebox.askyesno("Warning",
                                                    "An entry already exists with this website/username combination. Do you want to overwrite it?")
                    if not overwrite:
                        return
                    remove_password(pw, key)
            store_passwords([new_password], key)
            load_password()
            messagebox.showinfo("Success", "Password stored successfully.")
            entry_website.delete(0, tk.END)
            entry_username.delete(0, tk.END)
            entry_password.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Please enter all fields.")


    def load_password():
        passwords = load_passwords(key)
        passwords.sort(key=lambda x: x.split(': ')[0].lower())  # Sort by website, ignoring case
        password_list.delete(0, tk.END)
        for password in passwords:
            password_list.insert(tk.END, password)

    current_selection = None

    def populate_fields(event):
        nonlocal current_selection
        selected_index = password_list.curselection()
        if selected_index:
            current_selection = selected_index
            selected_password = password_list.get(selected_index)
            website, username, password = selected_password.split(': ')
            entry_website.delete(0, tk.END)
            entry_username.delete(0, tk.END)
            entry_password.delete(0, tk.END)
            entry_website.insert(0, website)
            entry_username.insert(0, username)
            entry_password.insert(0, password)


    def delete_password():
        nonlocal current_selection
        if current_selection is not None:
            confirm_delete = messagebox.askyesno(title="Warning", message="Are you sure you would like to delete this entry?")
            if not confirm_delete:
                return
            selected_password = password_list.get(current_selection)
            password_list.delete(current_selection)
            remove_password(selected_password, key)
            messagebox.showinfo("Success", "Password deleted successfully.")
            current_selection = None
        else:
            messagebox.showerror("Error", "Please select a password to delete.")

    root = tk.Tk()
    root.title("Password Manager")

    frame = tk.Frame(root)
    frame.pack(padx=20, pady=20)

    label_website = tk.Label(frame, text="Website: ")
    label_website.pack()
    entry_website = tk.Entry(frame, width=75)
    entry_website.pack(padx=5, pady=5)

    label_username = tk.Label(frame, text="Username: ")
    label_username.pack()
    entry_username = tk.Entry(frame, width=75)
    entry_username.pack(padx=5, pady=5)

    label_password = tk.Label(frame, text="Password: ")
    label_password.pack()
    entry_password = tk.Entry(frame, show="*", width=75)
    entry_password.pack(padx=5, pady=5)

    button_store = tk.Button(frame, text="Save Password", command=store_password)
    button_store.pack(padx=5, pady=5)

    button_delete = tk.Button(frame, text="Delete Password", command=delete_password)
    button_delete.pack(padx=5, pady=5)

    password_list = tk.Listbox(frame, width=75, borderwidth=3, highlightthickness=0)
    password_list.bind('<<ListboxSelect>>', populate_fields)

    scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
    scrollbar.config(command=password_list.yview)

    password_list.config(yscrollcommand=scrollbar.set)
    password_list.pack(side=tk.LEFT, fill=tk.BOTH)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    load_password()

    root.mainloop()

if __name__ == "__main__":
    main()

















