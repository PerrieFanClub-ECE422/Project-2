import binascii
import sqlite3
from hashlib import sha256
import commands
from utils import generate_key_pair
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import binascii
# global vars
db_path= os.getcwd() + '/sfs.db'
private_key = None
public_key = None
AES_KEY = b'0123456789abcdef0123456789abcdef'

def init_global_keys():
    global private_key, public_key
    private_key, public_key = generate_key_pair()


def init_db():
    
    # connect and create cursor
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    
    # create tables -------------------------------
    # users table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            group_name TEXT,   
            FOREIGN KEY(group_name) REFERENCES groups(name)
        )
        '''
    )

    # groups table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS groups (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT UNIQUE NOT NULL
        )
        '''
    )

    # directory table
    #cursor.execute("DROP TABLE IF EXISTS directories")
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS directories (
            dir_id INTEGER PRIMARY KEY AUTOINCREMENT,
            dir_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            dir_path TEXT NOT NULL,
            permissions TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (user_id)
        )
        '''
    )
    #populate directory table with root directory
    cursor.execute(
        '''
        INSERT INTO directories (
            dir_name, 
            owner_id,
            dir_path,
            permissions
            ) 
            VALUES (?, ?, ?, ?)
        ''', 
        ("root", 0, "root", db_encrypt_data("all"))
    )

    new_dir_path = os.path.join(os.getcwd(), "root")
    print(new_dir_path)
    if not os.path.exists(new_dir_path):
        os.mkdir(new_dir_path)
    os.chdir(new_dir_path)

    #cursor.execute("DROP TABLE IF EXISTS files")
    # files table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            permissions TEXT NOT NULL,
            content TEXT,
            FOREIGN KEY (owner_id) REFERENCES users (user_id)
        )
        '''
    )

    # ---------------------------------------------
    # NOTE:
    #   sqlite creates a special table called sqlite_sequence when
    #   using AUTOINCREMENT


    # commit changes and close db
    conn.commit()
    conn.close()

def db_check_user_exists(username):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT * 
            FROM users 
            WHERE username=?
            ''', 
            (db_encrypt_data(username),)
        )

        user = cursor.fetchone()
        if user:
            return True
        else:
            return False

    except sqlite3.Error as e:
        print(f"Database error: {e} check user exists")
        user = None

    finally:
        conn.close()

def db_encrypt_data(plaintext):

    #TODO: REFERENCE OR REYNEL GETS EXPELLED
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(b'0000000000000000'), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Encode the ciphertext in hexadecimal
    encrypted_hex = binascii.hexlify(ciphertext).decode('utf-8')
    return encrypted_hex

def db_decrypt_data(encrypted_data): 
    #TODO: REFERENCE OR REYNEL GETS EXPELLED
    encrypted_data = binascii.unhexlify(encrypted_data.encode('utf-8'))

    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(b'0000000000000000'), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data.decode('utf-8')


def db_get_directory_perms(dir_name, dir_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT permissions 
            FROM directories 
            WHERE dir_name = ? 
            AND dir_path = ?
            ''', 
            (dir_name, dir_path)
        )

        dir_perms = cursor.fetchone()
        if dir_perms:
            return db_decrypt_data(dir_perms[0])
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e} get directory perms")


def db_get_file_perms(file_name, file_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT permissions 
            FROM files 
            WHERE file_name = ?
            AND file_path = ?
            ''', 
            (file_name, file_path)
        )

        file_perms = cursor.fetchone()
        if file_perms:
            return db_decrypt_data(file_perms[0])
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e} get file perms")



def db_get_directory_id(dir_name, dir_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT dir_id 
            FROM directories 
            WHERE dir_name = ? 
            AND dir_path = ?
            ''', 
            (db_encrypt_data(dir_name), dir_path)
        )
        dir_id = cursor.fetchone()

        if dir_id:
            print("Directory ID found! ", dir_id)
            return dir_id
        else:
            print("No ID found, ", dir_id)
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e} get dir id")


def db_get_directory_owner(dir_name, dir_path):

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT owner_id 
            FROM directories 
            WHERE dir_name = ? 
            AND dir_path = ? 
            ''', 
            (dir_name, dir_path)
        )

        dir_owner_id = cursor.fetchone()

        if dir_owner_id:
            return dir_owner_id[0]
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e} get dir owner")

    finally:
        conn.close()

def db_get_file_owner(file_name, file_path):
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT owner_id 
            FROM files 
            WHERE file_name = ? 
            AND file_path = ? 
            ''', 
            (file_name, file_path)
        )

        file_owner_id = cursor.fetchone()

        if file_owner_id:
            return file_owner_id[0]
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e} get file owner")

    finally:
        conn.close()

def db_get_user_id(username):

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT user_id 
            FROM users 
            WHERE username=?
            ''', 
            (db_encrypt_data(username),)
        )
        user_id = cursor.fetchone()[0]

        if user_id is not None:
            return user_id
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e} get user id")
        user_id = None

    finally:
        conn.close()

def db_get_all_users():
    userlist = []

    try:

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT * 
            FROM users
            '''
        )

        users = cursor.fetchall()

        for user in users:

            userlist.append({
                'user_id': user[0],
                'username': user[1],
                # 'password_hash': user[2]
            })

    except sqlite3.Error as e:
        print(f"Database error: {e} get all users")
    
    finally:
        # Ensure the database connection is closed
        conn.close()

    return userlist

def db_add_group(group_name):

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Encrypt the group name using the admin's public key
        encrypted_group_name = db_encrypt_data(group_name)

        # Insert the encrypted group name into the groups table
        cursor.execute('INSERT INTO groups (group_name) VALUES (?)', (encrypted_group_name,))
        conn.commit()
        print("Group added successfully.")
        return True
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

    
def db_get_existing_groups():
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT group_name FROM groups')
        groups = cursor.fetchall()

        conn.close()

        # Print the group names in a nice format
        print("Existing groups:")
        for group in groups:
            group_name = db_decrypt_data(group[0])
            print(f"- {group_name}")

        # Return a list of decrypted group names
        return [db_decrypt_data(group[0]) for group in groups]
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return []

def db_assign_user_to_groups(username, selected_groups):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    for group in selected_groups:
        cursor.execute('INSERT INTO users (username, group_name) VALUES (?, ?)', (username, group))

    conn.commit()
    conn.close()

def db_add_user(username, password, group_name=None):

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # hash the pw with sha256
        password_hash = sha256(password.encode()).hexdigest()
        print("Registering user: ", username)
        cursor.execute("INSERT INTO users (username, password_hash, group_name) VALUES (?, ?, ?)", (db_encrypt_data(username), password_hash, db_encrypt_data(group_name) if group_name else None))

        # Commit changes
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print("error - username already exists")
        return False

    except sqlite3.Error as e:
        print(f"error occurred: {e}")

    finally:
        # Ensure the database connection is closed
        conn.close()


def db_auth_user(username, password):

    # hash the pw with sha256
    password_hash = sha256(password.encode()).hexdigest()

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT user_id 
            FROM users 
            WHERE username = ? AND password_hash = ?
            ''', 
            (db_encrypt_data(username), password_hash)
        )

        fetcheduser = cursor.fetchone()

        # return user_id
        if fetcheduser:
            return fetcheduser[0]

    except sqlite3.Error as e:
        print(f"error occurred: {e}")
        fetcheduser = None

    finally:
        conn.close()

    return None



def db_create_directory(dir_name, owner_name):
    e_dir_name = db_encrypt_data(dir_name)
    owner_id = db_get_user_id(owner_name)
    new_dir_path = os.path.join(commands.pwd(), e_dir_name)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM directories WHERE dir_name = ? AND dir_path = ?", (e_dir_name, new_dir_path))
        result = cursor.fetchone()
        if result is not None:
            print("Directory already exists")
            return  # Entry exists
        else:
            #TODO: possibly make sure that owner_id is referencing the tables correctly
            cursor.execute(
                '''INSERT INTO directories (
                    dir_name, 
                    owner_id,
                    dir_path,
                    permissions
                    )
                    VALUES (?, ?, ?, ?)
                    ''', 
                    (e_dir_name, owner_id, new_dir_path, db_encrypt_data("owner"))
                )

            conn.commit()
            print(f"Directory {dir_name} created by {owner_name}")
            # populate files database with name, hashed name, owner id, permission type, content = empty for now

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None


    finally:
        conn.close()

def db_get_directory_id(dir_name, parent_dir_id):
    #TODO: encrypt/decrypt values

    # use directory name and parent directory ID
    # if parent_dir_id == 0, we are in root directory
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Execute the query to fetch the dir_id
        cursor.execute("SELECT dir_id FROM directories WHERE dir_name = ? AND parent_dir_id = ?", (dir_name, parent_dir_id))
        result = cursor.fetchone()

        if result:
            return result[0]  # Return the dir_id value
        else:
            return None

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None

def change_permissions(name, group_names, fileflag):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        id = None
        # Fetch directory ID based on directory name
        if not fileflag:
            cursor.execute("SELECT dir_id FROM directories WHERE dir_name = ?", (db_encrypt_data(name),))
        else: 
            cursor.execute("SELECT file_id FROM files WHERE encrypted_name = ?", (db_encrypt_data(name),))
        
        id = cursor.fetchone()
        if id:            
            # Convert group names to a string to store as permissions
            permissions = ','.join(group_names)
            print("PERMISSIONS: " , permissions)
            print("Encrypted PERMISSIONS: ", db_encrypt_data(permissions))

            # Update permissions for the directory
            if not fileflag:
                cursor.execute("UPDATE directories SET permissions = ? WHERE dir_id = ?", (db_encrypt_data(permissions), id[0]))
            else:
                cursor.execute("UPDATE files SET permissions = ? WHERE file_id = ?", (db_encrypt_data(permissions), id[0]))

            conn.commit()
            print("Permissions updated successfully.")
        else:
            print("Directory or File not found.")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

    finally:
        conn.close()

def db_create_file(file_name, owner_name):
    e_file_name = db_encrypt_data(file_name)
    owner_id = db_get_user_id(owner_name)
    new_file_path = os.path.join(commands.pwd(), e_file_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM files WHERE file_name = ? AND file_path = ?", (e_file_name, new_file_path))
        result = cursor.fetchone()
        if result is not None:
            print("File already exists")
            return  # Entry exists
        else:
            cursor.execute(
                '''INSERT INTO files (
                    file_name, 
                    owner_id, 
                    file_path,
                    permissions, 
                    content) 
                    VALUES (?, ?, ?, ?, ?)
                    ''', 
                    (e_file_name, owner_id, new_file_path, db_encrypt_data("owner"), db_encrypt_data(""))
                )

        
        print(f"File {file_name} created by {owner_name}")

        conn.commit()


    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None


    finally:
        conn.close()


def db_delete_file(file_name, owner_name):
    e_file_name = db_encrypt_data(file_name)
    owner_id = db_get_user_id(owner_name)
    new_file_path = os.path.join(commands.pwd(), e_file_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM files WHERE file_name = ? AND file_path = ?", (e_file_name, new_file_path))
        result = cursor.fetchone()
        if result is None:
            print("File does not exist")
            return 
        else:
            cursor.execute(
                '''DELETE FROM files 
                WHERE file_name = ?
                AND file_path = ?
                ''', 
                (e_file_name, new_file_path)
                )

        
        print(f"File {file_name} deleted by {owner_name}")

        conn.commit()


    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None


    finally:
        conn.close()



def db_modify_file_contents(file_name, new_content):
    # cncrypt the file name to match the encrypted version stored in the database
    e_file_name = db_encrypt_data(file_name)
    e_new_content = db_encrypt_data(new_content)  # Encrypt the new content
    file_path = os.path.join(commands.pwd(), e_file_name)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if the file exists
        cursor.execute("SELECT * FROM files WHERE file_name = ? AND file_path = ?", (e_file_name, file_path))
        result = cursor.fetchone()
        
        if not result:
            print(f"File {file_name} does not exist or you do not have permission to modify it.")
            return
        
        # Update the file's content
        cursor.execute(
            '''UPDATE files
               SET content = ?
               WHERE file_path = ?''',
            (e_new_content, file_path,)
        )
        
        if cursor.rowcount == 0:
            print(f"Failed to update {file_name}.")
        else:
            print(f"File {file_name} updated successfully.")
        
        conn.commit()
    
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    
    finally:
        conn.close()

    

def db_modify_file_name(file_name, new_file_name):
    # cncrypt the file name to match the encrypted version stored in the database
    e_old_file_name = db_encrypt_data(file_name)
    e_new_file_name = db_encrypt_data(new_file_name) 
    old_file_path = os.path.join(commands.pwd(), e_old_file_name)
    new_file_path = os.path.join(commands.pwd(), e_new_file_name)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if the file exists
        cursor.execute("SELECT * FROM files WHERE file_name = ? AND file_path = ?", (e_old_file_name, old_file_path))
        result = cursor.fetchone()
        
        if not result:
            print(f"File {file_name} does not exist or you do not have permission to modify it.")
            return
        
        # Update the file's name
        cursor.execute(
            '''UPDATE files
               SET file_name = ?
               WHERE file_path = ?''',
            (e_new_file_name, old_file_path,)
        )
        
        cursor.execute(
            '''UPDATE files
               SET file_path = ?
               WHERE file_path = ?''',
            (new_file_path, old_file_path,)
        )

        if cursor.rowcount == 0:
            print(f"Failed to update {file_name}.")
        else:
            print(f"File {file_name} updated successfully.")
        
        conn.commit()
    
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    
    finally:
        conn.close()



def db_check_file_name_integrity(external_filename, file_path, username):

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    print(f" arg: {external_filename}, {file_path}, {username}")
    try:
        cursor.execute(
            '''
            SELECT encrypted_name
            FROM files
            WHERE file_path = ?
            ''', 
            (file_path,)
            )

        db_encrypted_name = cursor.fetchone()

        if db_encrypted_name:
            if db_encrypted_name != db_encrypt_data(external_filename):
                print(f"{external_filename}'s name has been modified by an external user!")
                return
        else:
            print("no such file exists")

    except sqlite3.Error as e:
        print("SQLite error:", e)



def db_check_file_content_integrity(filename, external_filecontent, e_file_path, username):

    e_external_filecontent = db_encrypt_data(external_filecontent)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute(
            '''
            SELECT content
            FROM files
            WHERE file_path = ?
            ''', 
            (e_file_path,)
            )
        
        db_encrypted_content = cursor.fetchone()[0]

        if db_encrypted_content != e_external_filecontent:
            print(f"{filename}'s content has been modified by an external user!")
            return

    except sqlite3.Error as e:
        print("SQLite error:", e)

def prompt_and_change_permissions(dir_name, username, fileflag):
    # Prompt the user to select permission type
    print("Select permission type:")
    print("1. All")
    print("2. Owner")
    print("3. Certain groups")

    choice = input("Enter your choice (1, 2, or 3): ")

    if choice == '1':
        change_permissions(dir_name, ["all"], fileflag)
    elif choice == '2':
        change_permissions(dir_name, ["owner"], fileflag)
    elif choice == '3':
        db_get_and_change_permissions(dir_name, username, fileflag)
    else:
        print("Invalid choice. Please enter 1, 2, or 3.")

def db_get_and_change_permissions(dir_name, username, fileflag):
    # Show available groups
    db_get_existing_groups()
    group_names = input("Enter group names separated by comma: ").split(',')

    # Check if user is owner of the group and change permissions for valid groups
    owner_id = db_get_user_id(username)
    valid_group_names = [group_name for group_name in group_names if db_check_user_in_group(username, group_name)]
    if valid_group_names:
        print("Provided existing groups that you are a part of: ", valid_group_names)
        change_permissions(dir_name, valid_group_names, fileflag)
    else:
        print("No valid group names provided.")

def db_check_user_in_group(username, group_name):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT group_name FROM users WHERE username = ?', (db_encrypt_data(username),))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        user_groups = db_decrypt_data(result[0]).split(',') if result[0] else []
        return group_name in user_groups
    else:
        return False