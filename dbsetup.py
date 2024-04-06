import sqlite3
from hashlib import sha256
import secrets
import commands
from utils import decrypt_with_private_key, deserialize_private_key, deserialize_public_key, encrypt_with_public_key, generate_key_pair, serialize_private_key, serialize_public_key
import os
# global vars
db_path= os.getcwd() + '/sfs.db'
ROOT_PARENT_ID = 0

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
            private_key BLOB,
            public_key BLOB,           
            FOREIGN KEY(group_name) REFERENCES groups(name)
        )
        '''
    )

    # sessions table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
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
            encrypted_dir_name TEXT NOT NULL,
            parent_dir_id INTEGER,
            owner_id INTEGER NOT NULL,
            dir_path TEXT NOT NULL,
            permissions TEXT NOT NULL,
            FOREIGN KEY (parent_dir_id) REFERENCES directories (dir_id),
            FOREIGN KEY (owner_id) REFERENCES users (user_id)
        )
        '''
    )
    #populate directory table with root directory
    cursor.execute(
        '''
        INSERT INTO directories (
            dir_name, 
            encrypted_dir_name,
            parent_dir_id, 
            owner_id,
            dir_path,
            permissions
            ) 
            VALUES (?, ?, ?, ?, ?,?)
        ''', 
        ("root", "encryped_dir_name", 0, 0, "root", "all")
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
            real_name TEXT NOT NULL,
            encrypted_name TEXT,
            owner_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            permissions TEXT NOT NULL,
            content TEXT,
            FOREIGN KEY (owner_id) REFERENCES users (user_id)
        )
        '''
    )

    
    ######### UNTESTED ###########################################

    # directory permissions table
    # cursor.execute(
    #     '''
    #     CREATE TABLE IF NOT EXISTS user_directory_permissions (
    #         user_id INTEGER,
    #         dir_id INTEGER,
    #         FOREIGN KEY (user_id) REFERENCES users (user_id),
    #         FOREIGN KEY (dir_id) REFERENCES directories (dir_id),
    #         PRIMARY KEY (user_id, dir_id, permission_id)
    #     );
    #     '''
    # )

    ##############################################################

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
            (username,)
        )

        user = cursor.fetchone()
        if user:
            return True
        else:
            return False

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        user = None

    finally:
        conn.close()

def db_encrypt_data(data,username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM users WHERE username = ?', (username.lower(),))
    public_key_data = cursor.fetchone()[0]
    public_key = deserialize_public_key(public_key_data)
    encrypted_data = encrypt_with_public_key(public_key, data.encode())
    return encrypted_data

def db_decrypt_data(data, username): 
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT private_key FROM users WHERE username = ?', (username.lower(),))
    private_key_data = cursor.fetchone()[0]
    private_key = deserialize_private_key(private_key_data)
    decrypted_data = decrypt_with_private_key(private_key, data)
    return decrypted_data.decode()

def db_get_directory_perms(owner_id, dir_name, dir_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT permissions 
            FROM directories 
            WHERE owner_id = ? 
            AND dir_name = ? 
            AND dir_path = ?
            ''', 
            (owner_id, dir_name, dir_path)
        )
        dir_perms = cursor.fetchone()

        if dir_perms:
            print("Directory perms found! ", dir_perms)
            return dir_perms
        else:
            print("No dir perms found, ", dir_perms)
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e}")


def db_get_file_perms(owner_id, file_name, file_path):
    print(owner_id, file_name, file_path)
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT permissions 
            FROM files 
            WHERE owner_id = ? 
            AND real_name = ? 
            AND file_path = ?
            ''', 
            (owner_id, file_name, file_path)
        )

        file_perms = cursor.fetchone()

        if file_perms:
            print("File perms found! ", file_perms)
            return file_perms
        else:
            print("No file perms found, ", file_perms)
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e}")



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
            (dir_name, dir_path)
        )
        dir_id = cursor.fetchone()

        if dir_id:
            print("Directory ID found! ", dir_id)
            return dir_id
        else:
            print("No ID found, ", dir_id)
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e}")


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

        dir_owner_id = cursor.fetchone()[0]

        if dir_owner_id is not None:
            return dir_owner_id
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e}")

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
            WHERE real_name = ? 
            AND file_path = ? 
            ''', 
            (file_name, file_path)
        )

        file_owner_id = cursor.fetchone()[0]

        if file_owner_id is not None:
            return file_owner_id
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e}")

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
            (username,)
        )

        user_id = cursor.fetchone()[0]

        if user_id is not None:
            return user_id
        else:
            return None

    except sqlite3.Error as e:
        print(f"Database error: {e}")
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
        print(f"Database error: {e}")
    
    finally:
        # Ensure the database connection is closed
        conn.close()

    return userlist

def get_admin_keys():
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        admin_username = 'admin'  # Assuming the admin's username is 'admin'
        cursor.execute('SELECT private_key, public_key FROM users WHERE username = ?', (admin_username,))
        admin_keys = cursor.fetchone()

        if admin_keys:
            private_key = deserialize_private_key(admin_keys[0])
            public_key = deserialize_public_key(admin_keys[1])
            return private_key, public_key
        else:
            print("Admin user not found.")
            return None, None

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return None, None

    finally:
        conn.close()

def db_add_group(group_name):
    private_key, public_key = get_admin_keys()
    if private_key and public_key:
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.cursor()

            # Encrypt the group name using the admin's public key
            encrypted_group_name = encrypt_with_public_key(public_key, group_name.encode('utf-8'))

            # Insert the encrypted group name into the groups table
            cursor.execute('INSERT INTO groups (group_name) VALUES (?)', (encrypted_group_name,))
            conn.commit()
            print("Group added successfully.")
            return True
        except sqlite3.Error as e:
            print(f"An error occurred: {e}")
        finally:
            conn.close()
    else:
        print("Admin keys not found, you need an Admin account in order to make groups")
        return False
    
def db_get_existing_groups():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('SELECT group_name FROM groups')
    groups = cursor.fetchall()

    conn.close()

    return [db_decrypt_data(group[0], "admin") for group in groups]

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
        # Generate RSA key pair for the admin user
        private_key, public_key = generate_key_pair()

        # Serialize the public and private keys
        serialized_public_key = serialize_public_key(public_key)
        serialized_private_key = serialize_private_key(private_key)
        # attempt to add user
        if username.lower() == "admin":
            cursor.execute("INSERT INTO users (username, password_hash, group_name, private_key, public_key) VALUES (?, ?, ?, ?, ?)", (username, password_hash, group_name, serialized_private_key, serialized_public_key))
        else:
            cursor.execute("INSERT INTO users (username, password_hash, group_name, private_key, public_key) VALUES (?, ?, ?, ?, ?)", (username, password_hash, group_name, None, None))

        # Commit changes
        conn.commit()

    except sqlite3.IntegrityError:
        print("error - username already exists")

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
            (username, password_hash)
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

def db_create_session(user_id):

    # init token
    token = secrets.token_hex(16)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            INSERT INTO sessions (user_id, token) 
            VALUES (?, ?)
            ''', 
            (user_id, token)
        )

        conn.commit()

    except sqlite3.Error as e:
        print(f"error occurred: {e}")
        token = None

    finally:
        conn.close()

    return token



def db_get_session_user_id(token):

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT user_id 
            FROM sessions 
            WHERE token = ?
            ''', 
            (token,)
        )

        session = cursor.fetchone()

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        session = None

    finally:
        conn.close()

    if session:
        return session[0]
    else:
        return None



def db_create_directory(dir_name, owner_name):

    owner_id = db_get_user_id(owner_name)
    new_dir_path = os.path.join(commands.pwd(), dir_name)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM directories WHERE dir_name = ? AND dir_path = ?", (dir_name, new_dir_path))
        result = cursor.fetchone()
        if result is not None:
            print("Directory already exists")
            return  # Entry exists
        else:
            #TODO: possibly make sure that owner_id is referencing the tables correctly
            cursor.execute(
                '''INSERT INTO directories (
                    dir_name, 
                    encrypted_dir_name,
                    parent_dir_id,
                    owner_id,
                    dir_path,
                    permissions
                    )
                    VALUES (?, ?, ?, ?,?,?)
                    ''', 
                    (dir_name, "encrypted_dir_name",0, owner_id, new_dir_path, None)
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

def change_directory_permissions(dir_name, group_ids):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Fetch directory ID based on directory name
        cursor.execute("SELECT dir_id FROM directories WHERE dir_name = ?", (dir_name,))
        dir_id = cursor.fetchone()
        
        if dir_id:            
            # Convert group IDs to a string to store as permissions
            permissions = ','.join(str(group_id) for group_id in group_ids)
            
            # Update permissions for the directory
            cursor.execute("UPDATE directories SET permissions = ? WHERE dir_id = ?", (permissions, dir_id))
            
            conn.commit()
            print("Directory permissions updated successfully.")
        else:
            print("Directory not found.")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

    finally:
        conn.close()

def db_create_file(file_name, owner_name):
    #TODO: encrypt info in function caller, decrypt info here

    owner_id = db_get_user_id(owner_name)
    new_file_path = os.path.join(commands.pwd(), file_name)
    print(db_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        #TODO: possibly make sure that owner_id is referencing the tables correctly
        cursor.execute(
            '''INSERT INTO files (
                real_name, 
                encrypted_name, 
                owner_id, 
                file_path,
                permissions, 
                content) 
                VALUES (?, ?, ?, ?, ?, ?)
                ''', 
                (file_name, "hashed_file_name", owner_id, new_file_path,None, "filler content")
            )

        
        print(f"File {file_name} created by {owner_name}")

        conn.commit()
    except sqlite3.Error as e:
        print("SQLite error:", e)
        return None


    finally:
        conn.close()
    # populate files database with name, hashed name, owner id, permission type, content = empty for now

def get_private_key(username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        serialized_private_key = row[0]
        private_key = deserialize_private_key(serialized_private_key)
        return private_key
    else:
        return None


def get_public_key(username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        serialized_public_key = row[0]
        public_key = deserialize_public_key(serialized_public_key)
        return public_key
    else:
        return None


# testing
if __name__ == '__main__':
    init_db() # to init the db
    yorn = input("add user? [y/n] >")
    if yorn.lower() == 'y':
        uu = input("u: ")
        pp = input("p: ")
        db_add_user(uu, pp)


    for usern in db_get_all_users():
        print(usern)

    while True:
        print("auth------------------------")
        uname = input("username: ")
        pw = input("password: ")
        userAuth = db_auth_user(uname, pw)
        if userAuth:
            print("auth succeeded")
            user_token = db_create_session(userAuth)
            print("session created for user_id =",  db_get_session_user_id(user_token), " with token =", user_token )

