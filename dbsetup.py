import sqlite3

def init_db(db_path='sfs.db'):

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
            password_hash TEXT NOT NULL
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

    # files table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            group_id INTEGER,
            permissions TEXT NOT NULL,
            content BLOB,
            FOREIGN KEY (owner_id) REFERENCES users (user_id),
            FOREIGN KEY (group_id) REFERENCES groups (group_id)
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


def db_add_user(username, password_hash, db_path='sfs.db'):

    # connect and create cursor
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # add user
    cursor.execute(
        '''
        INSERT INTO users (username, password_hash) VALUES (?, ?)
        ''', 
        (username, password_hash)
    )

    # commit changes and close db
    conn.commit()
    conn.close()

def db_get_user(username, db_path='sfs.db'):

    # connect and create cursor
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT * FROM users WHERE username=?', 
        (username,)
    )

    user = cursor.fetchone()

    # close db
    conn.close()

    return user
