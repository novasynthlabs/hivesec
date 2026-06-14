import time
import json
import os
import random
import string
import base64
import hashlib
import hmac

def slow_print(text, delay=0.03):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

from ctypes import create_string_buffer, c_void_p, c_int, c_size_t, c_uint32, byref, CDLL
import ctypes

DATA_FILE = "hivesec_data.json"
CONFIG_FILE = "hivesec_config.json"

def encode(text, master_password):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 100000, 32)
    iv = os.urandom(16)
    
    plaintext = text.encode('utf-8')
    plaintext_len = len(plaintext)
    
    ciphertext_buffer = create_string_buffer(plaintext_len + 16)
    ciphertext_len = c_size_t(0)
    
    kCCEncrypt = 0
    kCCAlgorithmAES128 = 0
    kCCOptionPKCS7Padding = 1
    kCCSuccess = 0
    
    CCCrypt = CDLL('/System/Library/Frameworks/Security.framework/Security').CCCrypt
    CCCrypt.restype = c_int
    CCCrypt.argtypes = [c_uint32, c_uint32, c_uint32, c_void_p, c_size_t, c_void_p, c_void_p, c_size_t, c_void_p, c_size_t, ctypes.POINTER(c_size_t)]
    
    key_buffer = create_string_buffer(key)
    iv_buffer = create_string_buffer(iv)
    plaintext_buffer = create_string_buffer(plaintext)
    
    status = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, key_buffer, len(key), iv_buffer, plaintext_buffer, plaintext_len, ciphertext_buffer, plaintext_len + 16, byref(ciphertext_len))
    
    if status != kCCSuccess:
        raise Exception("Encryption failed")
    
    final_data = salt + iv + ciphertext_buffer.raw[:ciphertext_len.value]
    return base64.b64encode(final_data).decode('utf-8')

def decode(encoded_text, master_password):
    try:
        data = base64.b64decode(encoded_text)
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]
        
        key = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 100000, 32)
        
        plaintext_buffer = create_string_buffer(len(ciphertext))
        plaintext_len = c_size_t(0)
        
        kCCDecrypt = 1
        kCCAlgorithmAES128 = 0
        kCCOptionPKCS7Padding = 1
        kCCSuccess = 0
        
        CCCrypt = CDLL('/System/Library/Frameworks/Security.framework/Security').CCCrypt
        CCCrypt.restype = c_int
        CCCrypt.argtypes = [c_uint32, c_uint32, c_uint32, c_void_p, c_size_t, c_void_p, c_void_p, c_size_t, c_void_p, c_size_t, ctypes.POINTER(c_size_t)]
        
        key_buffer = create_string_buffer(key)
        iv_buffer = create_string_buffer(iv)
        ciphertext_buffer = create_string_buffer(ciphertext)
        
        status = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, key_buffer, len(key), iv_buffer, ciphertext_buffer, len(ciphertext), plaintext_buffer, len(ciphertext), byref(plaintext_len))
        
        if status != kCCSuccess:
            raise ValueError("Decryption failed")
        
        return plaintext_buffer.raw[:plaintext_len.value].decode('utf-8')
    except:
        raise ValueError("Decryption failed")

def create_validation_hash(master_password):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 100000, 32)
    return base64.b64encode(salt + key).decode('utf-8')

def verify_password(entered_password, stored_validation):
    try:
        data = base64.b64decode(stored_validation)
        salt = data[:16]
        stored_key = data[16:]
        
        entered_key = hashlib.pbkdf2_hmac('sha256', entered_password.encode('utf-8'), salt, 100000, 32)
        return hmac.compare_digest(entered_key, stored_key)
    except:
        return False

def biometric_auth(reason="Confirm action"):
    from objc_util import ObjCClass, ObjCBlock
    LAContext = ObjCClass('LAContext')
    context = LAContext.alloc().init()
    if not context.canEvaluatePolicy_error_(1, None):
        return False

    result = {'success': False}

    def completion(success, error):
        result['success'] = bool(success)

    handler = ObjCBlock(completion, restype=None, argtypes=[ctypes.c_bool, ctypes.c_void_p])
    context.evaluatePolicy_localizedReason_reply_(1, reason, handler)

    start = time.time()
    while time.time() - start < 25:
        if result['success']:
            return True
        time.sleep(0.1)
    return False

def load_data(master_password):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            encoded_data = json.load(f)
            for entry in encoded_data:
                entry['value'] = decode(entry['value'], master_password)
            return encoded_data
    return []

def save_data(data, master_password):
    encoded_data = []
    for entry in data:
        new_entry = entry.copy()
        new_entry['value'] = encode(entry['value'], master_password)
        encoded_data.append(new_entry)
    with open(DATA_FILE, "w") as f:
        json.dump(encoded_data, f, indent=4)

def get_face_id_status():
    if os.path.exists(CONFIG_FILE):
        try:
            config = json.load(open(CONFIG_FILE))
            return config.get("face_id_enabled", None)  # None = not decided yet
        except:
            return None
    return None

def set_face_id_status(enabled):
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            config = json.load(open(CONFIG_FILE))
        except:
            pass
    config["face_id_enabled"] = enabled
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def require_face_id(reason="Confirm this action"):
    status = get_face_id_status()
    if status is not True:
        return True  # Face ID not enabled

    slow_print("\nFace ID required...")
    if biometric_auth(reason):
        slow_print("Face ID confirmed✅.")
        return True
    else:
        print("Face ID failed or cancelled. Action aborted.")
        return False

def master_password_check():
    slow_print("\n=== 🔒💎HiveSec.v7 Login💎🔒 ===")
    
    if not os.path.exists(DATA_FILE):
        new_pass = input("\nCreate a master password: ").strip()
        if not new_pass:
            slow_print("Password cannot be empty.")
            return None

        with open(DATA_FILE, "w") as f:
            json.dump([], f)

        validation_hash = create_validation_hash(new_pass)
        with open(CONFIG_FILE, "w") as f:
            json.dump({"validation_hash": validation_hash, "face_id_enabled": None}, f)

        slow_print("\nMaster password created successfully✅.")
        return new_pass

    entered = input("Enter master password: ").strip()

    if not os.path.exists(CONFIG_FILE):
        slow_print("🚫Access denied. Configuration file missing🚫.")
        return None

    try:
        config = json.load(open(CONFIG_FILE))
        stored_validation = config.get("validation_hash", "")
    except:
        slow_print("🚫Access denied. Configuration error🚫.")
        return None

    if not verify_password(entered, stored_validation):
        slow_print("🚨Access denied🚨 Incorrect master password.")
        return None

    print("Access granted✅ (Master password).")
    return entered

def main_menu(master_password):
    while True:
        print("\n" + "=" * 42)
        slow_print("           🔒💎HiveSec💎🔒")
        slow_print("=" * 42)
        slow_print(" 1. Add New Entry 💾")
        slow_print(" 2. View All Entries📓📚")
        slow_print(" 3. Search Entries🔎")
        slow_print(" 4. Delete Entry🗑️")
        slow_print(" 5. Generate Password⚙️")
        slow_print(" 6. Change Master Password⚠️")
        slow_print(" 7. Exit✌🏻")

        face_status = get_face_id_status()
        if face_status is None:
            slow_print(" 8. Implement Face ID 👁️‍🗨️ ?")

        print("=" * 42)

        choice = input("\nChoose an option (1–8): ").strip()

        if choice == "1":
            add_entry(master_password)
        elif choice == "2":
            view_entries(master_password)
        elif choice == "3":
            search_entries(master_password)
        elif choice == "4":
            delete_entry(master_password) 
        elif choice == "5":
            generate_password()
        elif choice == "6":
            master_password = change_master_password(master_password)
        elif choice == "7":
            slow_print("\nExiting HiveSec. Goodbye👾👾👾")
            break
        elif choice == "8" and face_status is None:
            setup_face_id()
        else:
            print("🚫Invalid choice. Please try again🚫.")

def setup_face_id():
    slow_print("\n" + "-" * 50)
    slow_print("           👁️‍🗨️IMPLEMENT FACE ID👁️‍🗨️")
    print("-" * 50)
    slow_print("\nThis uses your device's native Face ID☑️.")
    slow_print("Nothing is sent to the cloud.")
    print()
    slow_print("⚠️If you choose YES:")
    slow_print("  • Face ID will be required for:")
    slow_print("      - Delete Entry")
    slow_print("      - Change Master Password")
    slow_print("  • This is a permanent decision.")
    slow_print("  • This option will disappear from the menu⚠️.")
    print()
    slow_print("⚠️If you choose NO:")
    slow_print("  • Face ID will NOT be used.")
    slow_print("  • This option will be permanently removed from the menu⚠️.")
    print()
    slow_print("☑️If you choose LATER, this option stays in the menu for now☑️.")
    print("-" * 50)

    choice = input("\nEnable Face ID now? (yes / no / later): ").strip().lower()

    if choice in ["yes", "y"]:
        set_face_id_status(True)
        print("\n✅ Face ID has been enabled✅.")
        slow_print("This option will no longer appear in the menu🔥.")
    elif choice in ["no", "n"]:
        set_face_id_status(False)
        print("\nFace ID has been disabled🚫.")
        slow_print("This option has been permanently removed from the menu🔥.")
    else:
        slow_print("\nYou chose to decide later. This option will remain in the menu for now🟢.")

def add_entry(master_password):
    print("\n" + "-" * 42)
    slow_print("              📥ADD NEW ENTRY📥")
    print("-" * 42)
    slow_print("  1 = Password🔒    2 = Email📧")
    slow_print("  3 = Address📍     4 = Phone Number📱")
    slow_print("  5 = Other🗃️")
    print("-" * 42)
    
    entry_type = input("\nChoose type (1-5): ").strip()
    label = input("Label / Name: ").strip()
    value = input("Value: ").strip()
    
    data = load_data(master_password)
    data.append({"type": entry_type, "label": label, "value": value})
    save_data(data, master_password)
    print("\n✅ Entry saved successfully.")

def view_entries(master_password):
    print("\n" + "-" * 42)
    print("              💎ALL ENTRIES💎")
    print("-" * 42)
    
    data = load_data(master_password)
    if not data:
        print("No entries found.")
        return
    
    for i, entry in enumerate(data, 1):
        slow_print(f"\n{i}. {entry['label']}")
        slow_print(f"   Type: {entry['type']}")
        slow_print(f"   Value: {entry['value']}")

def delete_entry(master_password):
    slow_print("\n=== ⚠️DELETE ENTRY⚠️ ===")
    
    entries = load_data(master_password)   # ← Fixed
    
    if not entries:
        print("No entries to delete.")
        return

    # Require Face ID for deletion if enabled
    if not require_face_id("Delete this entry"):
        print("Face ID failed or was cancelled. Deletion aborted.")
        return

    slow_print("\nYour entries:")
    for i, entry in enumerate(entries, 1):
        slow_print(f"{i}. {entry['label']} (Type: {entry['type']})")

    try:
        choice = int(input("\nDelete which number? ").strip())
        if 1 <= choice <= len(entries):
            deleted = entries.pop(choice - 1)
            save_data(entries, master_password)   # ← Fixed
            slow_print(f"\nEntry '{deleted['label']}' deleted successfully🔥.")
        else:
            print("🚫Invalid number🚫.")
    except ValueError:
        slow_print("Please enter a valid number.")

def search_entries(master_password):
    print("\n" + "-" * 42)
    print("              SEARCH ENTRIES")
    print("-" * 42)
    
    term = input("Search term: ").lower().strip()
    data = load_data(master_password)
    found = False
    
    for entry in data:
        if term in entry['label'].lower():
            slow_print(f"\n{entry['label']}")
            slow_print(f"  Type: {entry['type']}")
            slow_print(f"  Value: {entry['value']}")
            found = True
    
    if not found:
        print("No matching entries found.")

def generate_password():
    print("\n" + "-" * 42)
    print("              ⚙️PASSWORD GENERATOR⚙️")
    print("-" * 42)
    slow_print("  1. 8 characters")
    slow_print("  2. 13 characters (recommended)")
    
    choice = input("\nChoose length (1 or 2): ").strip()
    length = 8 if choice == "1" else 13
    
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    
    slow_print(f"\n🔑 Generated Password: {password}")

def change_master_password(current_master):
    print("\n" + "-" * 42)
    slow_print("              ⚠️CHANGE MASTER. PASSWORD⚠️")
    print("-" * 42)
    
    old_pass = input("Enter current master password: ").strip()
    if old_pass != current_master:
        print("🚫Incorrect password🚫.")
        return current_master

    if not require_face_id("Change master password?"):
        return current_master

    new_pass = input("Enter new master password: ").strip()
    confirm = input("Confirm new master password: ").strip()

    if new_pass == confirm and new_pass != "":
        data = load_data(old_pass)
        save_data(data, new_pass)

        new_validation = create_validation_hash(new_pass)
        config = {"validation_hash": new_validation}
        if os.path.exists(CONFIG_FILE):
            try:
                old_config = json.load(open(CONFIG_FILE))
                config["face_id_enabled"] = old_config.get("face_id_enabled")
            except:
                pass
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)

        slow_print("\n✅ Master password changed successfully.")
        slow_print("All entries have been re-encrypted.")
        return new_pass
    else:
        slow_print("Passwords do not match or were empty.")
        return current_master

# ====================== START PROGRAM ======================

master_password = master_password_check()
if master_password:
    main_menu(master_password)
