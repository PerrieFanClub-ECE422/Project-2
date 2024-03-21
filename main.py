import os
import shutil

import sys
# get access to db-functions from the dbsetup file
from dbsetup import init_db, db_add_user, db_get_user


class User:
    # user is saved to database
    def __init__(self, name):
        self.name = name
        self.home_dir = create_dir(name)         # user should also have their own directory created



class File:
    # user is saved to database
    def __init__(self, name):
        self.name = name


class Directory:
    # user is saved to database
    def __init__(self, name):
        self.name = name


def create_user(name):
    user = User(name)
    # do some database stuff
    return user

def create_dir(name):
    dir = Directory(name)
    # do some database stuff
    return dir



def command_ls():
    files = os.listdir('.')
    for file in files: 
        print(file, end="  ")



def main():
    while True:
        cmd = input("\nSFS$ : ")


        # switch statements using input cmd
        if cmd == "ls":
            command_ls()


if __name__ == '__main__':
    print("Welcome to the SFS")
    print("<Authentication stuff>")
    # we do some authentication before we go to main
    main()