import binascii
import sqlite3
from hashlib import sha256
import commands
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# global vars
db_path= os.getcwd() + '/sfs.db'

# see report for why this is hardcoded in
AES_KEY = b'0123456789abcdef0123456789abcdef'
HMAC_KEY = b'0987654321abcdef0123456789abcdef'


def init_db():
    
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

    # directories table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS directories (
            dir_id INTEGER PRIMARY KEY AUTOINCREMENT,
            dir_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            dir_path TEXT NOT NULL UNIQUE,
            permissions TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (user_id)
        )
        '''
    )

    #populate directory table with root directory
    new_dir_path = os.path.join(os.getcwd(), "root")

    if not os.path.exists(new_dir_path):
        os.mkdir(new_dir_path)
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
        ("root", 0, new_dir_path, db_encrypt_data("all"))
        )
    
    #move into the root directory
    os.chdir(new_dir_path)

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

    # commit changes and close db
    conn.commit()
    conn.close()

def db_check_user_exists(username):
    # runs query to see if the inputted username exists in users table
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

def generate_hmac(data):
    
    # https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def db_encrypt_data(plaintext):

    # https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/
    # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    # https://cryptography.io/en/latest/hazmat/primitives/padding/

    # pad data so that it is multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # symmetric encryption
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(b'0000000000000000'), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    hmac_values = generate_hmac(ciphertext)

    # combine hmac sig with ciphertext
    encrypted_data = ciphertext + hmac_values

    #convert to hex so that it can be stored in db without issue
    encrypted_hex = binascii.hexlify(encrypted_data).decode('utf-8')
    return encrypted_hex

def db_decrypt_data(encrypted_data): 

    # https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/
    # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    # https://cryptography.io/en/latest/hazmat/primitives/padding/

    # undo hexlify
    encrypted_data = binascii.unhexlify(encrypted_data.encode('utf-8'))

    # get ciphertext and hmac sig from the data
    ciphertext = encrypted_data[:-32]
    hmac_values = encrypted_data[-32:]

    # compare hmac
    computed_hmac = generate_hmac(ciphertext)
    if hmac_values != computed_hmac:
        raise ValueError("HMAC verification failed!")

    # decrypt
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(b'0000000000000000'), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    #remove padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    #reutnr decrypted data
    return decrypted_data.decode('utf-8')

def db_get_directory_perms(dir_name, dir_path):
    #for a given directory, uniquely defined by its dir_path. 
    #this function will get and return directory permissions on a successful query execution.
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
    #for a given file, uniquely defined by its file_path. 
    #this function will get and return file permissions on a successful query execution.
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

def db_get_directory_owner(dir_name, dir_path):
    #for a given directory, uniquely defined by its dir_path. 
    #this function will return the directory owner_id on a successful query execution.
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
    #for a given file, uniquely defined by its file_path. 
    #this function will return the file owner_id on a successful query execution.
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
    #for a given unique username. 
    #this function will return the user_id associated with the username on a successful query execution.
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
        user_id = cursor.fetchone()

        if user_id:
            return user_id[0]
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e} get user id")
        user_id = None

    finally:
        conn.close()

def db_add_group(group_name):
    #this function will populate the DB with the user defined group 
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
    #this function will get all existing groups and print them 
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
    #this function will add a user with the selected groups they want to be a part of. 
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    for group in selected_groups:
        cursor.execute('INSERT INTO users (username, group_name) VALUES (?, ?)', (username, group))

    conn.commit()
    conn.close()

def db_add_user(username, password, group_name=None):
    #Upon registering a new user, this function will be called to populate the users table with a new row reflecting the user defined inputs.
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # hash the pw with sha256
        password_hash = sha256(password.encode()).hexdigest()
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
    #Upon login, this function is called to validate the user credentials
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

        # return user_id, successful login
        if fetcheduser:
            return fetcheduser[0]

    except sqlite3.Error as e:
        print(f"error occurred: {e}")
        fetcheduser = None

    finally:
        conn.close()
    #unsuccessful login
    return None

def db_create_directory(dir_name, owner_name):
    #Upon running the mkdir this function is called populate the directories tables.
    #encrypting the directory
    e_dir_name = db_encrypt_data(dir_name)
    owner_id = db_get_user_id(owner_name)
    new_dir_path = os.path.join(commands.pwd(), e_dir_name)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Check if directory exists 
        cursor.execute("SELECT * FROM directories WHERE dir_name = ? AND dir_path = ?", (e_dir_name, new_dir_path))
        result = cursor.fetchone()
        if result is not None:
            print("Directory already exists")
            return  # Entry exists
        else:
            #populating table with new directory, with an intial permissions value of "owner".
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

    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None
    
    finally:
        conn.close()

def change_permissions(path, group_names, fileflag):
    #Upon the 'chmod' is ran, this function will update the file or directory permissions.
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        id = None

        # Fetch directory/file ID based on file/directory path
        if not fileflag:
            cursor.execute("SELECT dir_id FROM directories WHERE dir_path = ?", (path,))
        else: 
            cursor.execute("SELECT file_id FROM files WHERE file_path = ?", (path,))
        id = cursor.fetchone()
        if id:            
            # Convert group names from comma seperated string to a list
            permissions = ','.join(group_names)
            print("Permisions: " , permissions)

            # Update permissions for the directory/file
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
    # This function will be invoke after touch had been called
    e_file_name = db_encrypt_data(file_name)
    owner_id = db_get_user_id(owner_name)
    new_file_path = os.path.join(commands.pwd(), e_file_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        #check if file_path exists already
        cursor.execute("SELECT * FROM files WHERE file_name = ? AND file_path = ?", (e_file_name, new_file_path))
        result = cursor.fetchone()
        if result is not None:
            print("File already exists")
            return  # Entry exists
        else:
            #create and populate the file with a new file where their permissions is default as 'owner' and content defaulted as the encrypted value of an empty string.
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
    #this function will be invoke when 'rm' is called
    e_file_name = db_encrypt_data(file_name)
    owner_id = db_get_user_id(owner_name)
    new_file_path = os.path.join(commands.pwd(), e_file_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM files WHERE file_name = ? AND file_path = ?", (e_file_name, new_file_path))
        result = cursor.fetchone()
        #checks if file exists
        if result is None:
            print("File does not exist")
            return 
        else:
            #if so delete it from the files table
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
    #this function will be invoked when 'echo' is executed
    # encrypt the file name to match the encrypted version stored in the database
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
    #this function will be invoke when 'mv' is executed
    # encrypt the file name to match the encrypted version stored in the database
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
        
        # Update the file's path
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

def db_check_file_content_integrity(e_filename, e_external_filecontent, e_file_path, username):
    #this function is invoked when a user logs in. 
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        #retrieve the content of a file based on a given file_path
        cursor.execute(
            '''
            SELECT content
            FROM files
            WHERE file_path = ?
            ''', 
            (e_file_path,)
            )
        
        db_encrypted_content = cursor.fetchone()

        if not db_encrypted_content:
            try:
                #if the parent directory has been renamed, its path wouldnt exists.
                print(f"File: '{db_decrypt_data(e_filename)}' parent directory has been renamed by an external user")
            except:
                #if the decrypt function returns an error, that means that the file had been renamed.
                print(f"File: '{e_filename}' has been renamed by an external user")
            return
        elif db_encrypted_content[0] != e_external_filecontent:
            #the current file content does not match the file content stored in DB, means that the file content was changed by an external user.
            try:
                print(f"{db_decrypt_data(e_filename)}'s content has been modified by an external user!")
            except:
                #just in case e_filename causes an error in our decrypt function, shouldnt happen.
                print(f"{e_filename}'s content has been modified by an external user!")

    except sqlite3.Error as e:
        print("SQLite error:", e)

def prompt_and_change_permissions(path, username, fileflag):
    # this function is invoked when chmod is execute
    # Prompt the user to select permission type
    print("Select permission type:")
    print("1. All")
    print("2. Owner")
    print("3. Certain groups")

    choice = input("Enter your choice (1, 2, or 3): ")
    #based on the users input we then update permission
    if choice == '1':
        change_permissions(path, ["all"], fileflag)
    elif choice == '2':
        change_permissions(path, ["owner"], fileflag)
    elif choice == '3':
        db_get_and_change_permissions(path, username, fileflag)
    else:
        print("Invalid choice. Please enter 1, 2, or 3.")

def db_get_and_change_permissions(path, username, fileflag):
    # this function will be invoked when chmod is executed
    # Show available groups
    db_get_existing_groups()
    group_names = input("Enter group names separated by comma: ").split(',')

    # Check and store the groups that user is a part of the groups out of the ones they selected
    valid_group_names = [group_name for group_name in group_names if db_check_user_in_group(username, group_name)]
    if valid_group_names:
        print("Provided existing groups that you are a part of: ", valid_group_names)
        change_permissions(path, valid_group_names, fileflag)
    else:
        print("No valid group names provided.")

def db_check_user_in_group(username, group_names):
    #this function will check if a given user is a part of the groups provided
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT group_name FROM users WHERE username = ?', (db_encrypt_data(username),))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        user_groups = db_decrypt_data(result[0]).split(',')
        for group in user_groups:
            if group in group_names:
                return True
    else:
        return False