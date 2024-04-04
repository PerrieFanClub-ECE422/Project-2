import sys
import commands
from dbsetup import db_add_group, db_add_user, db_auth_user, db_check_user_exists, get_private_key, get_public_key, db_create_directory, db_get_user_id, db_get_directory_id, db_get_directory_perms, db_get_directory_owner, db_create_directory, init_db
import sqlite3
import os
from InquirerPy import inquirer

PERMISSION_USER = "user"
PERMISSION_GROUP = "group"
PERMISSION_ALL = "all"
db_path = os.getcwd() + "/sfs.db"


def main():
    init_db()  # Initialize the database and tables if they don't exist
    print("\nWelcome to the Secure File System (SFS)")
    print("Choose an option:")
    print("1. Login")
    print("2. Register")
    print("3. Create Group")
    print("4. Exit")
    
    choice = input("Enter your choice (1-4): ")
    if choice == "1":
        login()
    elif choice == "2":
        register()
    elif choice == "3":
        create_group_prompt()
    elif choice == "4":
        sys.exit()
    else:
        print("Invalid choice. Please enter a number from 1 to 4.")

def login():
    username = input("Enter username: ")
    password = inquirer.secret(message="Enter password: ", transformer=lambda _: "[hidden]").execute()
    
    if login_user(username, password):  # Login user using the database
        file_system(username)
    else:
        if not db_check_user_exists(username): 
            print("User does not exist, please register before logging in.")
        else: 
            print("Invalid Password")
        main()

def login_user(username, password):
    try:
        if not db_auth_user(username, password):
            print("Invalid Credentials, try again")
            return False
        print("Successful login, Welcome " + username)
        return True
    except sqlite3.IntegrityError:
        print("Failed login")

def register():
    username = input("Enter username: ")
    password = inquirer.secret(message="Enter password: ", transformer=lambda _: "[hidden]").execute()
    
    # Optional: Implement group selection logic if needed
    # For simplicity, assume group_name is either entered by the user or null
    group_name = None  # You can modify this to allow users to select a group during registration
    db_add_user(username.lower(), password, group_name)
    main() 

def create_group_prompt():
    group_name = inquirer.text(message="Enter group name: ").execute()
    try:
        db_add_group(group_name)
        main()
    except sqlite3.IntegrityError:
        print("Group already exists.") 
    
 
def file_system(current_user_name):
    while True:
        cmd = input("\nSFS$ : ").strip().split()
        # switch statements using input cmd
        # check permissions whenever a user executes these commands
        if cmd[0] == "ls":
            commands.ls()  
        elif cmd[0] == "pwd":
            commands.pwd()
        elif cmd[0] == "mkdir":
            dir_path = commands.pwd() # get current path
            dir_name = os.path.basename(dir_path) # name of current directory
            print(f"{dir_path}, {dir_name}")
            if check_directory_perms(current_user_name, dir_name, dir_path):
                commands.mkdir(cmd[1], current_user_name)
        elif cmd[0] == "touch":
            commands.touch(cmd[1], current_user_name)
        elif cmd[0] == "cd":
            dir_path = commands.pwd() + "/" + cmd[1]
            print(f"{cmd[1]}, {dir_path}")
            if check_directory_perms(current_user_name, cmd[1], dir_path):
                commands.cd(os.getcwd() + "/" + cmd[1])
        else:
            print("Command not recognized. Type 'cmds' to list all commands.")
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


def select_file(filename, dir_id):
    """
    Set is_selected for 'filename' to 1


    Since unix doesnt allow for same file names within the same directory, we should follow that

    When any command that deals with files (ls, touch, cat, echo, mv, chmod) is used,
    we run get_directory_id() which returns the directory ID
    Then we query the file DB for 'filename' with 'dir_id', and set "is_selected" for this row to 1



    """


def check_file_perms(filename):
    """
    - Check if user is logged in via CURRENT_USER value
        - if CURRENT USER == "", NO PERMISSION
    
    - Get ID of CURRENT_USER from DB by querying for username
    - Get ID of 'filename' from DB by querying for the current directory id

    - Check permission column of file.
        - If "all", grant permission. Else, go next
    - Get file owner_id from file ID row
    - Compare CURRENT_USER ID to file owner_id
        - If match, grant permission. Else, go next
    - Check user_file_permissions DB. Query for file_id. It will return a different row
    for each permitted group
    - Compare CURRENT_USER's groups with permitted groups. 
        - If match, grant permisseion. Else, NO PERMISSION.

    """

def check_directory_perms(curruser, dir_name, dir_path):
    """
    Args:
    dir_name: name of the folder(directory) that you wish to check perms for
    dir_path: unique path of the folder(directory) that you wish to check perms for
    """
    #TODO: figure out how we plan on adding info to user_file_permissions and user_directory_permissions
    #TODO: figre out how to get ID of current directory and selected file

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if curruser == "":
        print(f"{curruser}:No permission to access directory")
        return False
    else:
        owner_id = db_get_user_id(curruser)
        dir_perms = db_get_directory_perms(owner_id, dir_name, dir_path)
        dir_owner_id = db_get_directory_owner(dir_name, dir_path)
        print(f"{owner_id}, {dir_path}, {dir_name}")
        
        if dir_perms[0] == "all":
            return True
        elif dir_perms[0] == "user":
            if owner_id == dir_owner_id:
                return True
            else:
                return False



    return True

    # Check if password is correct -> do some encryption/decryption on db side
    # set CURRENT_USER variable to the unique ID of the user that just logged in.
    # CURRENT_USER = <query to get unique ID>

if __name__ == '__main__':
    print("Welcome to the SFS")
    print("<Authentication stuff>")
    print("Type 'login' to login to the SFS. Type 'cmds' to list all commands.")
    # we do some authentication before we go to main
    main()