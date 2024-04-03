import sqlite3
from hashlib import sha256
import secrets

from utils import deserialize_key, generate_key_pair, serialize_key

# global vars
db_path='sfs.db'

def init_db():

    # connect and create cursor
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # create tables -------------------------------
    # users table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            groups TEXT,
            public_key BLOB,
            private_key BLOB
        )
        '''
    )

    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            groups TEXT,
            public_key BLOB,
            private_key BLOB
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
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS directories (
            dir_id INTEGER PRIMARY KEY AUTOINCREMENT,
            dir_name TEXT NOT NULL,
            parent_dir_id INTEGER,
            owner_id INTEGER NOT NULL,
            FOREIGN KEY (parent_dir_id) REFERENCES directories (dir_id),
            FOREIGN KEY (owner_id) REFERENCES users (user_id)
        )
        '''
    )

    # files table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            real_name TEXT NOT NULL,
            encrypted_name TEXT,
            owner_id INTEGER NOT NULL,
            dir_id INTEGER NOT NULL,
            permissions TEXT NOT NULL,
            is_selected INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (user_id),
            FOREIGN KEY (dir_id) REFERENCES directories (dir_id)
        )
        '''
    )

    
    ######### UNTESTED ###########################################

    # abstract permission type table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS permissions (
            permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
        '''
    )
    # predefine permissions
    permissions = ['create', 'delete', 'read', 'write', 'rename']
    for permission in permissions:
        cursor.execute(
            '''
            INSERT OR IGNORE INTO permissions (name) 
            VALUES (?)
            ''', 
            (permission,)
        )


    # file permissions table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS user_file_permissions (
            user_id INTEGER,
            file_id INTEGER,
            permission_mode TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id),
            FOREIGN KEY (file_id) REFERENCES files (file_id),
            FOREIGN KEY (permission_id) REFERENCES permissions (permission_id),
            PRIMARY KEY (user_id, file_id, permission_id)
        );
        '''
    )


    # directory permissions table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS user_directory_permissions (
            user_id INTEGER,
            dir_id INTEGER,
            permission_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (user_id),
            FOREIGN KEY (dir_id) REFERENCES directories (dir_id),
            FOREIGN KEY (permission_id) REFERENCES permissions (permission_id),
            PRIMARY KEY (user_id, dir_id, permission_id)
        );
        '''
    )

    ##############################################################

    # ---------------------------------------------
    # NOTE:
    #   sqlite creates a special table called sqlite_sequence when
    #   using AUTOINCREMENT


    # commit changes and close db
    conn.commit()
    conn.close()

def create_user_db(username, password_hash):
    """
    Create an user in the database.

    Args:
        username (str): The username of the admin user.
        password_hash (str): The hash of the admin user's password.
    """
    # Generate RSA key pair for the admin user
    private_key, public_key = generate_key_pair()

    # Serialize the public and private keys
    serialized_public_key = serialize_key(public_key)
    serialized_private_key = serialize_key(private_key)

    # Insert the admin user into the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password_hash, public_key, private_key, is_admin) VALUES (?, ?, ?, ?, 1)", (username, password_hash, serialized_public_key, serialized_private_key))
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



def db_get_user_id(username):

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT * 
            FROM users 
            WHERE user_id=?
            ''', 
            (username,)
        )

        user = cursor.fetchone()

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        user = None

    finally:
        conn.close()

    return user


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


def db_add_user(username, password):

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # hash the pw with sha256
        password_hash = sha256(password.encode()).hexdigest()
        # Generate RSA key pair for the admin user
        private_key, public_key = generate_key_pair()

        # Serialize the public and private keys
        serialized_public_key = serialize_key(public_key)
        serialized_private_key = serialize_key(private_key)
        # attempt to add user
        cursor.execute("INSERT INTO users (username, password_hash, public_key, private_key) VALUES (?, ?, ?, ?)", (username, password_hash, serialized_public_key, serialized_private_key))

        # Commit changes
        conn.commit()
        print("user added successfully.")

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



def create_directory(dir_name):
    print("create dir here")


def db_create_file(file_name):
    print("create file here")

def get_private_key(username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        serialized_private_key = row[0]
        private_key = deserialize_key(serialized_private_key)
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
        public_key = deserialize_key(serialized_public_key)
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
        group = input("group: ")
        db_add_user(uu, pp, group)


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


