
import os
import shutil
import pycrypto

import sys

# get access to db-functions from the dbsetup file
from dbsetup import init_db, db_add_user, db_get_user
# init_db() # to init the db


def db_functions(username, password):

    db_add_user(username, password_hash)
    if user and user[2] == password:  # Placeholder for proper password check
        print("Login successful.")
    else:
        print("Login failed.")
    
    gottenuser = db_get_user(username)




class User:
    # user is saved to database
    def __init__(self, name):
        self.name = name
        self.home_dir = create_dir(name)         # user should also have their own directory created



class File:
    # user is saved to database
    def __init__(self, name, owner):
        self.name = name
        self.owner = owner


class Directory:
    # user is saved to database
    def __init__(self, name, owner):
        self.name = name
        self.owner = owner


def create_user(name):
    user = User(name)
    # do some database stuff
    return user

def create_dir(name, owner):
    dir = Directory(name, owner)
    # do some database stuff
    return dir



def command_ls():
    files = os.listdir('.')
    for file in files: 
        print(file, end="  ")



def main():
    while True:
        cmd = input("\nSFS$ : ")


    """

    Your SFS should support common commands in the Linux file system (while you
        can name your own commands). At least the following commands should be
        supported:
        ○ pwd: see what directory you are currently in,
        ○ ls: list the files in current directory,
        ○ cd: change directory,
        ○ mkdir: make a new subdirectory,
        ○ touch: create a new file,
        ○ cat: read a file,
        ○ echo: write to a file,
        ○ mv: rename a file (however you are not required to support moving files
        between different directories)
        Keep in mind that you need to check permissions whenever a user executes
        these commands.

    """

        # switch statements using input cmd
        # check permissions whenever a user executes these commands
        if cmd == "ls":
            command_ls()

def login():
    currentuser_name = input("Username: ")

    # Check if user exists in db

    currenuser_pass = input("Pass: ")

    # Check if password is correct -> do some encryption/decryption on db side


if __name__ == '__main__':
    print("Welcome to the SFS")
    print("<Authentication stuff>")

    # we do some authentication before we go to main
    main()