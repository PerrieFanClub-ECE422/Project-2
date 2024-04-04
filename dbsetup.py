import sqlite3
from hashlib import sha256
import secrets
import commands
from utils import deserialize_key, generate_key_pair, serialize_key

# global vars
db_path='sfs.db'
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
    #cursor.execute("DROP TABLE IF EXISTS directories")
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS directories (
            dir_id INTEGER PRIMARY KEY AUTOINCREMENT,
            dir_name TEXT NOT NULL,
            parent_dir_id INTEGER,
            owner_id INTEGER NOT NULL,
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
            parent_dir_id, 
            owner_id,
            permissions
            ) 
            VALUES (?, ?, ?,?)
        ''', 
        ("root", 0, 0, "all")
    )

    #cursor.execute("DROP TABLE IF EXISTS files")
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
            content TEXT,
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
            SELECT user_id 
            FROM users 
            WHERE username=?
            ''', 
            (username,)
        )

        user = cursor.fetchone()

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        user = None

    finally:
        conn.close()

    return user[0]


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



def db_create_directory(dir_name, owner_name, parent_dir_id):

    owner_id = db_get_user_id(owner_name)
    print(owner_id)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM directories WHERE dir_name = ? AND parent_dir_id = ?", (dir_name, parent_dir_id))
        result = cursor.fetchone()
        if result is not None:
            print("Directory already exists")
            return  # Entry exists
        else:
            #TODO: possibly make sure that owner_id is referencing the tables correctly
            cursor.execute(
                '''INSERT INTO directories (
                    dir_name, 
                    parent_dir_id,
                    owner_id,
                    permissions
                    )
                    VALUES (?, ?, ?, ?)
                    ''', 
                    (dir_name, parent_dir_id, owner_id, "user")
                )

            conn.commit()
            print(f"Directory {dir_name} added to db for {owner_name}")
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

def db_create_file(file_name, owner_name):
    print("create file here")
    #TODO: encrypt info in function caller, decrypt info here

    owner_id = db_get_user_id(owner_name)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    #TODO: possibly make sure that owner_id is referencing the tables correctly
    cursor.execute(
        '''INSERT INTO files (
            real_name, 
            encrypted_name, 
            owner_id, 
            dir_id
            permissions, 
            content) 
            VALUES (?, ?, ?, ?, ?)
            ''', 
            (file_name, "hashed_file_name", owner_id, 0 ,"user", "filler content")
        )

    print(f"File {file_name} added to db for {owner_name}")
    # populate files database with name, hashed name, owner id, permission type, content = empty for now

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


