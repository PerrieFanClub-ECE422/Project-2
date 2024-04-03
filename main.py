import commands
from dbsetup import db_add_user, db_auth_user, db_check_user_exists, get_private_key, get_public_key

PERMISSION_USER = "user"
PERMISSION_GROUP = "group"
PERMISSION_ALL = "all"
CURRENT_USER = ""



class User:
    # user is saved to database
    def __init__(self, name):
        self.name = name
        self.home_dir = create_dir(name)         # user should also have their own directory created

class File:
    # user is saved to database
    def __init__(self, name, owner):
        # query database to find # of files in db, then set unique ID to the next file number
        #self.id = <query>
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

def main():
    while True:
        cmd = input("\nSFS$ : ").split()

        # switch statements using input cmd
        # check permissions whenever a user executes these commands
        if cmd[0] == "ls":
            commands.ls()  
        elif cmd[0] == "pwd":
            commands.pwd()
        elif cmd[0] == "login":
            login()
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

def get_directory_id():
    return

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
    - Get ID of 'filename' from DB by querying for "is_selected"

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

def check_directory_perms(dir_id):
    return

def login():
    currentuser_name = input("Username: ")
    new_user = False
    if db_check_user_exists(currentuser_name):
        print("user exists")
    else: 
        print(f"User does not exist! Register new user {currentuser_name}? Y/N :")
        createuser_response = input()
        if createuser_response == "Y":
            new_user = True      
    currentuser_pass = input("Pass: ")

    if new_user: 
        try:
            db_add_user(currentuser_name,currentuser_pass)
            CURRENT_USER = currentuser_name
        except:
            print("error with uploading user to DB")
        
    else: 
        if db_auth_user(currentuser_name, currentuser_pass):
            print("Sucessful Login!")
            CURRENT_USER = currentuser_name
            print("Welcome: "+CURRENT_USER)
        else: 
            print("Invalid Password")

    # Check if password is correct -> do some encryption/decryption on db side
    # set CURRENT_USER variable to the unique ID of the user that just logged in.
    # CURRENT_USER = <query to get unique ID>

if __name__ == '__main__':
    print("Welcome to the SFS")
    print("<Authentication stuff>")
    print("Type 'login' to login to the SFS. Type 'cmds' to list all commands.")
    # we do some authentication before we go to main
    main()