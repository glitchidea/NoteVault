#!/usr/bin/env python3

import shutil
import os
import sqlite3
import datetime
from cryptography.fernet import Fernet
import getpass
import hashlib

# Default database file path
db_path = 'notlar.db'
password_path = "password.txt"
key_path = "secret.key"

def file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()

def load_key():
    try:
        with open(key_path, "rb") as key_file:
            key = key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        # Save the hash of the new key file
        with open(key_path + ".hash", "w") as hash_file:
            hash_file.write(file_hash(key_path))
    return key

# Create database connection
def create_connection(path=db_path):
    return sqlite3.connect(path)

def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    return encrypted

def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    try:
        decrypted = f.decrypt(encrypted_message).decode()
    except Exception as e:
        print(f"Şifre çözme hatası: {e}")
        decrypted = ""
    return decrypted

def initialize_database():
    if not os.path.exists("secret.key"):
        print("This is being set up for the first time. You need to set a password.")
        set_password()
    else:
        if not verify_password():
            print("Password verification failed. The program is closing.")
            exit()
    conn = create_connection()
    create_table(conn)
    return conn

def set_password():
    global password_path
    password1 = getpass.getpass("Enter your new password: ")
    password2 = getpass.getpass("Re-enter your password: ")
    if password1 == password2:
        encrypted_password = encrypt_message(password1)
        with open(password_path, "wb") as f:
            f.write(encrypted_password)
        # Save the hash of the new password file
        with open(password_path + ".hash", "w") as hash_file:
            hash_file.write(file_hash(password_path))
        print("Password successfully set.")
    else:
        print("The passwords do not match. The program is closing.")
        exit()

def verify_password():
    global password_path
    try:
        with open(password_path, "rb") as f:
            stored_password = f.read()
        with open(password_path + ".hash", "r") as hash_file:
            stored_hash = hash_file.read()
        entered_password = getpass.getpass("Enter your password: ")
        decrypted_password = decrypt_message(stored_password)
        
        if file_hash(password_path) != stored_hash:
            print("The password file has been changed or corrupted.")
            return False
        
        return entered_password == decrypted_password
    except FileNotFoundError:
        print("Password file not found.")
        return False

# Create database table
def create_table(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS notlar
             (ID INTEGER PRIMARY KEY AUTOINCREMENT,
             BASLIK TEXT NOT NULL,
             ICERIK TEXT NOT NULL,
             ETIKET TEXT,
             OLUSTURMA_TARIHI TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
             GUNCELLEME_TARIHI TIMESTAMP DEFAULT CURRENT_TIMESTAMP);''')

# Main system menu
def ana_menu():
    conn = initialize_database()
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\nMain system")
        print("----------------------")
        print("1-New Note")
        print("2-All Notes")
        print("3-Search Notes")
        print("4-Delete Note")
        print("5-Update Note")
        print("6-Settings")
        print("0-Log out")

        secim = input("Please make a selection: ")

        if secim == "1":
            yeni_not_ekle(conn)
            input("  ")
        elif secim == "2":
            tum_notlari_goster(conn)
            input("  ")
        elif secim == "3":
            not_ara(conn)
            input("  ")
        elif secim == "4":
            not_sil(conn)
            input("  ")
        elif secim == "5":
            not_guncelle(conn)
            input("  ")
        elif secim == "6":
            ayarlar_menu(conn)
            input("  ")
        elif secim == "0":
            print("The program has been terminated.")
            conn.close()
            break
        else:
            print("Invalid login.")

# Function to add new note
def yeni_not_ekle(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    baslik = input("Enter note title: ")
    icerik = input("Enter note content: ")
    etiket = input("Enter tag: ")
    tarih = datetime.datetime.now()

    sifreli_baslik = encrypt_message(baslik)
    sifreli_icerik = encrypt_message(icerik)

    conn.execute("INSERT INTO notlar (BASLIK, ICERIK, ETIKET, OLUSTURMA_TARIHI, GUNCELLEME_TARIHI) \
                  VALUES (?, ?, ?, ?, ?)", (sifreli_baslik, sifreli_icerik, etiket, tarih, tarih))

    conn.commit()
    print("Not başarıyla eklendi.")

# Function to display all notes
def tum_notlari_goster(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    secim = input("For all notes (1)\nTo filter by tag (2)\nPlease make a selection: ")

    if secim == "1":
        cursor = conn.execute("SELECT * FROM notlar")
    elif secim == "2":
        etiket = input("Etiket giriniz: ")
        cursor = conn.execute("SELECT * FROM notlar WHERE ETIKET LIKE ?", ('%' + etiket + '%',))
    else:
        print("Invalid input.")
        return

    for row in cursor:
        print("\nID: ", row[0])
        print("Title: ", decrypt_message(row[1]))  # Şifre çözülüyor
        print("Content: ", decrypt_message(row[2]))  # Şifre çözülüyor
        print("Tag: ", row[3])
        print("Creation date: ", row[4])
        print("Update date: ", row[5])

#Function to search notes by keyword
def not_ara(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    anahtar_kelime = input("Enter the word to search: ").lower()  # Kullanıcının girdiği kelimeyi küçük harfe çeviriyoruz
    cursor = conn.execute("""
        SELECT * FROM notlar
        WHERE LOWER(BASLIK) LIKE ? OR LOWER(ICERIK) LIKE ? OR LOWER(ETIKET) LIKE ?""",
        ('%' + anahtar_kelime + '%', '%' + anahtar_kelime + '%', '%' + anahtar_kelime + '%')
    )
    found = False
    for row in cursor:
        print("\nID: ", row[0])
        print("Title: ", decrypt_message(row[1]))  # Şifre çözülüyor
        print("Content: ", decrypt_message(row[2]))  # Şifre çözülüyor
        print("Tag: ", row[3])
        print("Creation date: ", row[4])
        print("Update date: ", row[5])
        found = True
    if not found:
        print("No notes found with the searched word.")

#Function to delete a note by ID
def not_sil(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    id = input("Enter the ID of the note to be deleted: ")
    conn.execute("DELETE FROM notlar WHERE ID=?", (id,))
    conn.commit()
    print("Note successfully deleted.")

#Function to update a note by ID
def not_guncelle(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    id = input("Enter the ID of the note to be updated: ")

    cursor = conn.execute("SELECT BASLIK, ICERIK, ETIKET FROM notlar WHERE ID=?", (id,))
    row = cursor.fetchone()
    if row:
        baslik, icerik, etiketler = row

        print("Current Title:")
        print(decrypt_message(baslik))  # Şifre çözülüyor
        print("\nCurrent Content:")
        print(decrypt_message(icerik))  # Şifre çözülüyor
        print("\nCurrent Tags:")
        print(etiketler)

        print("     Change Operation\n")
        
        yeni_baslik = input(f"New title :  ") or decrypt_message(baslik)
        yeni_icerik = input(f"New content : ") or decrypt_message(icerik)
        yeni_etiketler = input(f"New tags : ") or etiketler
        tarih = datetime.datetime.now()

        sifreli_baslik = encrypt_message(yeni_baslik)
        sifreli_icerik = encrypt_message(yeni_icerik)

        conn.execute("UPDATE notlar SET BASLIK=?, ICERIK=?, ETIKET=?, GUNCELLEME_TARIHI=? WHERE ID=?",
                     (sifreli_baslik, sifreli_icerik, yeni_etiketler, tarih, id))
        conn.commit()
        print("Not başarıyla güncellendi.")
    else:
        print("Not bulunamadı.")

def ayarlar_menu(conn):
    global db_path, password_path, key_path
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\nSettings")
        print("----------------------")
        print(f"Database Location: {os.path.abspath(db_path)}")
        print(f"Password File Location: {os.path.abspath(password_path)}")
        print(f"Encryption Key Location: {os.path.abspath(key_path)}\n")
        print("1- Backup Database")
        print("2- Change Database Location")
        print("3- Change Password File Location")
        print("4- Backup Password File")
        print("5- Change Encryption Key File Location")
        print("6- Backup Encryption Key File")
        print("7- Change Password File Hash Location")
        print("8- Change Encryption Key Hash Location")
        print("9- Restore Database")
        print("0- Back")

        secim = input("Seçim yapınız: ")

        if secim == "1":
            veritabani_yedekle(conn)
        elif secim == "2":
            veritabani_konum_degistir()
        elif secim == "3":
            sifre_dosya_yolu_degistir()
        elif secim == "4":
            sifre_dosyasini_yedekle()
        elif secim == "5":
            anahtar_dosya_yolu_degistir()
        elif secim == "6":
            anahtar_dosyasini_yedekle()
        elif secim == "7":
            sifre_dosya_hash_yolu_degistir()
        elif secim == "8":
            anahtar_dosya_hash_yolu_degistir()
        elif secim == "9":
            veritabani_geri_yukle(conn)
        elif secim == "0":
            print("Exiting from the Settings menu...")
            break
        else:
            print("Invalid entry.")

# Function to backup the database
def veritabani_yedekle(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    backup_file = input("Please enter the name of the backup file: ")
    if backup_file:
        shutil.copy2(db_path, backup_file)
        shutil.copy2(password_path, backup_file + "_password")
        shutil.copy2(key_path, backup_file + "_key")
        if os.path.exists(password_path + ".hash"):
            shutil.copy2(password_path + ".hash", backup_file + "_password.hash")
        if os.path.exists(key_path + ".hash"):
            shutil.copy2(key_path + ".hash", backup_file + "_key.hash")
        print("Database, password file, and key backup successfully completed.")

def sifre_dosyasini_yedekle():
    os.system('cls' if os.name == 'nt' else 'clear')
    yedek_adi = input("Please enter the name of the password file backup: ")
    if yedek_adi:
        shutil.copy2(password_path, yedek_adi)
        if os.path.exists(password_path + ".hash"):
            shutil.copy2(password_path + ".hash", yedek_adi + ".hash")
        print("Password file backup successfully completed.")

def anahtar_dosyasini_yedekle():
    os.system('cls' if os.name == 'nt' else 'clear')
    yedek_adi = input("Please enter the name of the encryption key backup: ")
    if yedek_adi:
        shutil.copy2(key_path, yedek_adi)
        if os.path.exists(key_path + ".hash"):
            shutil.copy2(key_path + ".hash", yedek_adi + ".hash")
        print("Encryption key backup successfully completed.")


def veritabani_geri_yukle():
    global db_path, password_path, key_path
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Please enter the locations of the backup files required for database restoration.")
    
    backup_db_path = input(f"Path to the database backup file (if left blank, the current database will be used): ")
    backup_password_path = input(f"Path to the password file backup (if left blank, the current password file will be used): ")
    backup_key_path = input(f"Path to the encryption key backup file (if left blank, the current key file will be used): ")

    if backup_db_path:
        shutil.copy2(backup_db_path, db_path)
        print("Database successfully restored.")
    if backup_password_path:
        shutil.copy2(backup_password_path, password_path)
        if os.path.exists(backup_password_path + ".hash"):
            shutil.copy2(backup_password_path + ".hash", password_path + ".hash")
        print("Password file successfully restored.")
    if backup_key_path:
        shutil.copy2(backup_key_path, key_path)
        if os.path.exists(backup_key_path + ".hash"):
            shutil.copy2(backup_key_path + ".hash", key_path + ".hash")
        print("Encryption key successfully restored.")

def anahtar_dosya_hash_yolu_degistir():
    global key_path
    os.system('cls' if os.name == 'nt' else 'clear')
    global key_path
    new_path = input("Please enter the path to the new encryption key hash file: ")
    os.rename(key_path + ".hash", new_path)
    print("Encryption key hash file path successfully changed.")

def sifre_dosya_hash_yolu_degistir():
    global password_path
    os.system('cls' if os.name == 'nt' else 'clear')
    new_path = input("Please enter the path to the new password file hash file: ")
    os.rename(password_path + ".hash", new_path)
    print("Password file hash file path successfully changed.")


# Function to change database file path
def veritabani_konum_degistir():
    global db_path
    os.system('cls' if os.name == 'nt' else 'clear')
    db_path = input("Please enter the path to the new database file: ")
    if not db_path.endswith(".db"):
        db_path += ".db"
    print(f"Database file has been set to the new location: {db_path}")

def anahtar_dosya_yolu_degistir():
    global key_path
    os.system('cls' if os.name == 'nt' else 'clear')
    key_path = input("Please enter the path for the new encryption key file: ")
    if not key_path.endswith(".key"):
        key_path += ".key"
    print(f"The encryption key file has been set to the new location: {key_path}")

def sifre_dosya_yolu_degistir():
    global password_path
    os.system('cls' if os.name == 'nt' else 'clear')
    password_path = input("Please enter the path for the new password file: ")
    if not password_path.endswith(".txt"):
        password_path += ".txt"
    print(f"The password file has been set to the new location: {password_path}")

# Function to show current database file path
def veritabani_konum_goster():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"Current database file path: {os.path.abspath(db_path)}")

# Function to restore the database from backup
def veritabani_geri_yukle(conn):
    global db_path, password_path, key_path
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Please enter the locations of the backup files needed for database restoration.")
    
    backup_db_path = input(f"Path to the database backup file (leave blank to use the current database).: ")
    backup_password_path = input(f"Path to the password file backup (leave blank to use the current password file).: ")
    backup_key_path = input(f"Path to the encryption key backup file (leave blank to use the current key file): ")

    if backup_db_path and os.path.isfile(backup_db_path):
        shutil.copy2(backup_db_path, db_path)
        print("The database has been successfully restored.")
    else:
        print("A valid database backup file path was not provided or the file could not be found.")
    
    if backup_password_path and os.path.isfile(backup_password_path):
        shutil.copy2(backup_password_path, password_path)
        if os.path.exists(backup_password_path + ".hash"):
            shutil.copy2(backup_password_path + ".hash", password_path + ".hash")
        print("The password file has been successfully restored.")
    else:
        print("A valid password file backup path was not provided or the file could not be found.")
    
    if backup_key_path and os.path.isfile(backup_key_path):
        shutil.copy2(backup_key_path, key_path)
        if os.path.exists(backup_key_path + ".hash"):
            shutil.copy2(backup_key_path + ".hash", key_path + ".hash")
        print("The encryption key has been successfully restored.")
    else:
        print("An invalid key file backup path was provided or the file could not be found.")
ana_menu()
