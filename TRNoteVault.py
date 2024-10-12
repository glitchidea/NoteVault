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
        print("İlk kez başlatılıyor. Şifre belirlemeniz gerekiyor.")
        set_password()
    else:
        if not verify_password():
            print("Şifre doğrulama başarısız. Program kapanıyor.")
            exit()
    conn = create_connection()
    create_table(conn)
    return conn

def set_password():
    global password_path
    password1 = getpass.getpass("Yeni şifrenizi girin: ")
    password2 = getpass.getpass("Şifrenizi tekrar girin: ")
    if password1 == password2:
        encrypted_password = encrypt_message(password1)
        with open(password_path, "wb") as f:
            f.write(encrypted_password)
        # Save the hash of the new password file
        with open(password_path + ".hash", "w") as hash_file:
            hash_file.write(file_hash(password_path))
        print("Şifre başarıyla belirlendi.")
    else:
        print("Şifreler uyuşmuyor. Program kapanıyor.")
        exit()

def verify_password():
    global password_path
    try:
        with open(password_path, "rb") as f:
            stored_password = f.read()
        with open(password_path + ".hash", "r") as hash_file:
            stored_hash = hash_file.read()
        entered_password = getpass.getpass("Şifrenizi girin: ")
        decrypted_password = decrypt_message(stored_password)
        
        if file_hash(password_path) != stored_hash:
            print("Şifre dosyası değiştirilmiş veya bozulmuş.")
            return False
        
        return entered_password == decrypted_password
    except FileNotFoundError:
        print("Şifre dosyası bulunamadı.")
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
        print("\nAna sistem")
        print("----------------------")
        print("1-Yeni not")
        print("2-Tüm notlar")
        print("3-Not ara")
        print("4-Not sil")
        print("5-Not güncelle")
        print("6-Ayarlar")
        print("0-Çıkış")

        secim = input("Seçim yapınız: ")

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
            print("Program sonlandırıldı.")
            conn.close()
            break
        else:
            print("Hatalı giriş.")

# Function to add new note
def yeni_not_ekle(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    baslik = input("Not başlığı giriniz: ")
    icerik = input("Not içeriği giriniz: ")
    etiket = input("Etiket giriniz: ")
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
    secim = input("Tüm notlar için (1)\nEtikete göre filtrelemek için (2)\nSeçim yapınız: ")

    if secim == "1":
        cursor = conn.execute("SELECT * FROM notlar")
    elif secim == "2":
        etiket = input("Etiket giriniz: ")
        cursor = conn.execute("SELECT * FROM notlar WHERE ETIKET LIKE ?", ('%' + etiket + '%',))
    else:
        print("Hatalı giriş.")
        return

    for row in cursor:
        print("\nID: ", row[0])
        print("Başlık: ", decrypt_message(row[1]))  # Şifre çözülüyor
        print("İçerik: ", decrypt_message(row[2]))  # Şifre çözülüyor
        print("Etiket: ", row[3])
        print("Oluşturulma tarihi: ", row[4])
        print("Güncelleme tarihi: ", row[5])

#Function to search notes by keyword
def not_ara(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    anahtar_kelime = input("Aranacak kelimeyi giriniz: ").lower()  # Kullanıcının girdiği kelimeyi küçük harfe çeviriyoruz
    cursor = conn.execute("""
        SELECT * FROM notlar
        WHERE LOWER(BASLIK) LIKE ? OR LOWER(ICERIK) LIKE ? OR LOWER(ETIKET) LIKE ?""",
        ('%' + anahtar_kelime + '%', '%' + anahtar_kelime + '%', '%' + anahtar_kelime + '%')
    )
    found = False
    for row in cursor:
        print("\nID: ", row[0])
        print("Başlık: ", decrypt_message(row[1]))  # Şifre çözülüyor
        print("İçerik: ", decrypt_message(row[2]))  # Şifre çözülüyor
        print("Etiket: ", row[3])
        print("Oluşturulma tarihi: ", row[4])
        print("Güncelleme tarihi: ", row[5])
        found = True
    if not found:
        print("Aradığınız kelimeye sahip not bulunamadı.")

#Function to delete a note by ID
def not_sil(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    id = input("Silinecek notun ID'sini giriniz: ")
    conn.execute("DELETE FROM notlar WHERE ID=?", (id,))
    conn.commit()
    print("Not başarıyla silindi.")

#Function to update a note by ID
def not_guncelle(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    id = input("Güncellenecek notun ID'sini giriniz: ")

    cursor = conn.execute("SELECT BASLIK, ICERIK, ETIKET FROM notlar WHERE ID=?", (id,))
    row = cursor.fetchone()
    if row:
        baslik, icerik, etiketler = row

        print("Mevcut Başlık:")
        print(decrypt_message(baslik))  # Şifre çözülüyor
        print("\nMevcut İçerik:")
        print(decrypt_message(icerik))  # Şifre çözülüyor
        print("\nMevcut Etiketler:")
        print(etiketler)

        print("     Değiştirme İşlemi\n")
        
        yeni_baslik = input(f"Yeni başlık :  ") or decrypt_message(baslik)
        yeni_icerik = input(f"Yeni içerik : ") or decrypt_message(icerik)
        yeni_etiketler = input(f"Yeni etiketler : ") or etiketler
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
        print("\nAyarlar")
        print("----------------------")
        print(f"Veri Tabanı Konumu: {os.path.abspath(db_path)}")
        print(f"Şifre Dosyası Konumu: {os.path.abspath(password_path)}")
        print(f"Şifreleme Anahtarı Konumu: {os.path.abspath(key_path)}\n")
        print("1- Veri tabanı yedekle")
        print("2- Veri tabanı konumu değiştir")
        print("3- Şifre dosyası konumu değiştir")
        print("4- Şifre dosyasını yedekle")
        print("5- Şifreleme anahtarı dosyası konumu değiştir")
        print("6- Şifreleme anahtarı dosyasını yedekle")
        print("7- Şifre dosyası hash dosyasının konumunu değiştir")
        print("8- Şifreleme anahtarı hash dosyasının konumunu değiştir")
        print("9- Veritabanı geri yükle")
        print("0- Geri")

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
            print("Ayarlar menüsünden çıkılıyor...")
            break
        else:
            print("Hatalı giriş.")

# Function to backup the database
def veritabani_yedekle(conn):
    os.system('cls' if os.name == 'nt' else 'clear')
    backup_file = input("Lütfen yedek dosyasının adını giriniz: ")
    if backup_file:
        shutil.copy2(db_path, backup_file)
        shutil.copy2(password_path, backup_file + "_password")
        shutil.copy2(key_path, backup_file + "_key")
        if os.path.exists(password_path + ".hash"):
            shutil.copy2(password_path + ".hash", backup_file + "_password.hash")
        if os.path.exists(key_path + ".hash"):
            shutil.copy2(key_path + ".hash", backup_file + "_key.hash")
        print("Veritabanı, şifre dosyası ve anahtar yedeği başarıyla alındı.")

def sifre_dosyasini_yedekle():
    os.system('cls' if os.name == 'nt' else 'clear')
    yedek_adi = input("Lütfen şifre dosyası yedeğinin adını giriniz: ")
    if yedek_adi:
        shutil.copy2(password_path, yedek_adi)
        if os.path.exists(password_path + ".hash"):
            shutil.copy2(password_path + ".hash", yedek_adi + ".hash")
        print("Şifre dosyası yedeği başarıyla alındı.")

def anahtar_dosyasini_yedekle():
    os.system('cls' if os.name == 'nt' else 'clear')
    yedek_adi = input("Lütfen şifreleme anahtarı yedeğinin adını giriniz: ")
    if yedek_adi:
        shutil.copy2(key_path, yedek_adi)
        if os.path.exists(key_path + ".hash"):
            shutil.copy2(key_path + ".hash", yedek_adi + ".hash")
        print("Şifreleme anahtarı yedeği başarıyla alındı.")


def veritabani_geri_yukle():
    global db_path, password_path, key_path
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Veritabanı geri yükleme işlemi için gerekli yedek dosyalarının konumlarını giriniz.")
    
    backup_db_path = input(f"Veritabanı yedeği dosyasının yolu (boş bırakılırsa mevcut veritabanı kullanılacak): ")
    backup_password_path = input(f"Şifre dosyası yedeği dosyasının yolu (boş bırakılırsa mevcut şifre dosyası kullanılacak): ")
    backup_key_path = input(f"Şifreleme anahtarı yedeği dosyasının yolu (boş bırakılırsa mevcut anahtar dosyası kullanılacak): ")

    if backup_db_path:
        shutil.copy2(backup_db_path, db_path)
        print("Veritabanı başarıyla geri yüklendi.")
    if backup_password_path:
        shutil.copy2(backup_password_path, password_path)
        if os.path.exists(backup_password_path + ".hash"):
            shutil.copy2(backup_password_path + ".hash", password_path + ".hash")
        print("Şifre dosyası başarıyla geri yüklendi.")
    if backup_key_path:
        shutil.copy2(backup_key_path, key_path)
        if os.path.exists(backup_key_path + ".hash"):
            shutil.copy2(backup_key_path + ".hash", key_path + ".hash")
        print("Şifreleme anahtarı başarıyla geri yüklendi.")

def anahtar_dosya_hash_yolu_degistir():
    global key_path
    os.system('cls' if os.name == 'nt' else 'clear')
    global key_path
    new_path = input("Lütfen yeni şifreleme anahtarı hash dosyasının yolunu giriniz: ")
    os.rename(key_path + ".hash", new_path)
    print("Şifreleme anahtarı hash dosyası yolu başarıyla değiştirildi.")

def sifre_dosya_hash_yolu_degistir():
    global password_path
    os.system('cls' if os.name == 'nt' else 'clear')
    new_path = input("Lütfen yeni şifre dosyası hash dosyasının yolunu giriniz: ")
    os.rename(password_path + ".hash", new_path)
    print("Şifre dosyası hash dosyası yolu başarıyla değiştirildi.")


# Function to change database file path
def veritabani_konum_degistir():
    global db_path
    os.system('cls' if os.name == 'nt' else 'clear')
    db_path = input("Lütfen yeni veritabanı dosyasının yolunu giriniz: ")
    if not db_path.endswith(".db"):
        db_path += ".db"
    print(f"Veritabanı dosyası yeni konum olarak ayarlandı: {db_path}")

def anahtar_dosya_yolu_degistir():
    global key_path
    os.system('cls' if os.name == 'nt' else 'clear')
    key_path = input("Lütfen yeni şifreleme anahtarı dosyasının yolunu giriniz: ")
    if not key_path.endswith(".key"):
        key_path += ".key"
    print(f"Şifreleme anahtarı dosyası yeni konum olarak ayarlandı: {key_path}")

def sifre_dosya_yolu_degistir():
    global password_path
    os.system('cls' if os.name == 'nt' else 'clear')
    password_path = input("Lütfen yeni şifre dosyasının yolunu giriniz: ")
    if not password_path.endswith(".txt"):
        password_path += ".txt"
    print(f"Şifre dosyası yeni konum olarak ayarlandı: {password_path}")

# Function to show current database file path
def veritabani_konum_goster():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"Şu anki veritabanı dosya yolu: {os.path.abspath(db_path)}")

# Function to restore the database from backup
def veritabani_geri_yukle(conn):
    global db_path, password_path, key_path
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Veritabanı geri yükleme işlemi için gerekli yedek dosyalarının konumlarını giriniz.")
    
    backup_db_path = input(f"Veritabanı yedeği dosyasının yolu (boş bırakılırsa mevcut veritabanı kullanılacak): ")
    backup_password_path = input(f"Şifre dosyası yedeği dosyasının yolu (boş bırakılırsa mevcut şifre dosyası kullanılacak): ")
    backup_key_path = input(f"Şifreleme anahtarı yedeği dosyasının yolu (boş bırakılırsa mevcut anahtar dosyası kullanılacak): ")

    if backup_db_path and os.path.isfile(backup_db_path):
        shutil.copy2(backup_db_path, db_path)
        print("Veritabanı başarıyla geri yüklendi.")
    else:
        print("Geçerli bir veritabanı yedeği dosyası yolu sağlanmadı veya dosya bulunamadı.")
    
    if backup_password_path and os.path.isfile(backup_password_path):
        shutil.copy2(backup_password_path, password_path)
        if os.path.exists(backup_password_path + ".hash"):
            shutil.copy2(backup_password_path + ".hash", password_path + ".hash")
        print("Şifre dosyası başarıyla geri yüklendi.")
    else:
        print("Geçerli bir şifre dosyası yedeği dosyası yolu sağlanmadı veya dosya bulunamadı.")
    
    if backup_key_path and os.path.isfile(backup_key_path):
        shutil.copy2(backup_key_path, key_path)
        if os.path.exists(backup_key_path + ".hash"):
            shutil.copy2(backup_key_path + ".hash", key_path + ".hash")
        print("Şifreleme anahtarı başarıyla geri yüklendi.")
    else:
        print("Geçerli bir anahtar dosyası yedeği dosyası yolu sağlanmadı veya dosya bulunamadı.")
ana_menu()
