import commands
import dbsetup 
import sqlite3
import os
import getpass

db_path = os.getcwd() + "/sfs.db"


def main():
    print("\nWelcome to the PERRIEFANCLUB SFS :)")
    dbsetup.init_db()  # Initialize the database and tables if they don't exist
    cmds = "\n[1]Login \t[2]Register \t[3]Create Group \t[4]Exit"
    while True:
        print(cmds)
        cmd = input("\n--- > ").split()
        if len(cmd) < 1:
            print("invalid cmd")
        elif cmd[0] == "1":
            login()
        elif cmd[0] == "2":
            register() 
        elif cmd[0] == "3":
            create_group_prompt()
        elif cmd[0] == "4" :
            break # quit the program
        else:
            print("invalid cmd")

def login():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    if login_user(username, password):  # Login user using the database
        file_system(username)
    else:
        if not dbsetup.db_check_user_exists(username): 
            print("User credentials do not exist")
        else: 
            print("Invalid Password")

def login_user(username, password):
    try:
        if not dbsetup.db_auth_user(username, password):
            return False
        print("Successful login, Welcome " + username)
        return True
    except sqlite3.IntegrityError:
        print("Failed login")

def register():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    group_name = None
    listgroups = dbsetup.db_get_existing_groups()

    if not listgroups:
        print("No groups made, please make a group to become apart of one.")
    else: 
        inputgroup = input("Enter group name: ")

        if inputgroup in listgroups:
            print("group", inputgroup, "assigned")
            group_name = inputgroup
        else:
            print("invalid group name - no group assigned")

    result = dbsetup.db_add_user(username.lower(), password, group_name)

    if result:
        print("registration succeeded")
        commands.mkdir(username.lower(), username.lower())
        



def create_group_prompt():
    group_name = input("Enter group name: ")
    try:
        dbsetup.db_add_group(group_name)
    except sqlite3.IntegrityError:
        print("Group already exists.") 
    

def file_system(current_user_name):
    cmds = """
    cd        => change directory       >> cd     [filename]
    pwd       => display current path   >> pwd
    ls        => list all items         >> ls 
    touch     => create new file        >> touch  [filename]
    mkdir     => create new directory   >> mkdir  [direcname]
    cat       => read file contents     >> cat    [filename]
    echo      => write file contents    >> echo   [filename]  [contents]
    mv        => rename file            >> mv     [filename]  [name]
    chmod     => change permissions of file/dir >> chmod [-f, -d] [targetname]
    cmds      => show all cmds          >> cmds
    exit      => exit the file system   >> exit
    """
    print(cmds)
    list_files(os.path.join(os.getcwd(),current_user_name), current_user_name)
    while True:

        cmd = input("\n------ SFS ------ " + commands.pwd_short() + "$ ").strip().split()
        # switch statements using input cmd
        # check permissions whenever a user executes these commands
        if len(cmd) < 1: # ----------------------------------------------- invalid
            print("invalid cmd")
        
        elif cmd[0] == "cd": # ----------------------------------------------- cd
            if len(cmd) < 2:
                print("insufficient args")
            else:
                if cmd[1] == "..":
                    curdir = os.getcwd()
                    parentdir = os.path.dirname(curdir)
                    os.chdir(parentdir)

                else:   
                    commands.cd(os.path.join(os.getcwd(), cmd[1]), current_user_name, cmd[1])

        elif cmd[0] == "pwd": # ----------------------------------------------- pwd
            print("Current Directory: ",commands.pwd())
        
        elif cmd[0] == "ls": # ----------------------------------------------- ls
            if len(cmd) > 1:
                commands.ls(cmd[1])
            else:
                commands.ls()
        
        elif cmd[0] == "touch": # ----------------------------------------------- touch
            if len(cmd) < 2:
                print("please specify a file name")
            else:
                commands.touch(cmd[1], current_user_name)
        
        elif cmd[0] == "mkdir": # ----------------------------------------------- mkdir
            if len(cmd) < 2:
                print("please specify a directory name")
            else:
                dir_path = commands.pwd()
                dir_name = os.path.basename(dir_path)
                if check_directory_perms(current_user_name, dir_name, dir_path):
                    commands.mkdir(cmd[1], current_user_name)
        
        elif cmd[0] == "cat": # ----------------------------------------------- cat
            if len(cmd) < 2:
                print("please specify a file name")
            else:
                commands.cat(cmd[1])

        elif cmd[0] == "echo": # ----------------------------------------------- echo
            if len(cmd) < 3:
                print("please specify both a file name and contents to write")
            else:
                commands.echo(cmd[1], cmd[2])
        
        elif cmd[0] == "mv": # ----------------------------------------------- mv
            if len(cmd) < 3:
                print("please specify both a file name and your desired new file name")
            else:
                commands.mv(cmd[1], cmd[2])

        elif cmd[0] == "chmod": # ----------------------------------------------- chmod
            if len(cmd) < 3:
                print("please specify flag and target name")
            else:
                flag = cmd[1]
                target_name = cmd[2]
                if flag == "-d":
                    dbsetup.prompt_and_change_directory_permissions(target_name, current_user_name)
                    return
                elif flag == '-f':

                    return
                else:
                    print("Invalid flag!")
        
        elif cmd[0] == "cmds": # ----------------------------------------------- cmds
            print(cmds)
        
        elif cmd[0] == "exit": # ----------------------------------------------- exit
            break
        
        else:
            print("command not recognized; type 'cmds' to list all commands")
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


def check_file_perms(curruser, file_name, file_path):

    if curruser == "":
        print(f"{curruser}:No permission to access directory")
        return False
    else:
        owner_id = dbsetup.db_get_user_id(curruser)
        file_perms = dbsetup.db_get_file_perms(owner_id, file_name, file_path)
        file_owner_id = dbsetup.db_get_file_owner(file_name, file_path)

        if file_perms == None:
            print(f"No access to file {file_name}")
            return False
        else:
            if owner_id == file_owner_id:
                return True
            elif file_perms[0] == "all":
                return True
            else:
                return False


def check_directory_perms(curruser, dir_name, dir_path):
    """
    Args:
    dir_name: name of the folder(directory) that you wish to check perms for
    dir_path: unique path of the folder(directory) that you wish to check perms for
    """
    #TODO: figure out how we plan on adding info to user_file_permissions and user_directory_permissions
    #TODO: figre out how to get ID of current directory and selected file

    if curruser == "":
        print(f"{curruser}:No permission to access directory")
        return False
    else:
        owner_id = dbsetup.db_get_user_id(curruser)
        dir_perms = dbsetup.db_get_directory_perms(owner_id, dir_name, dir_path)
        dir_owner_id = dbsetup.db_get_directory_owner(dir_name, dir_path)
        
        if dir_perms == None:
            print(f"No access to directory {dir_name}")
            return False
        else:
            if owner_id == dir_owner_id:
                return True
            elif dir_perms[0] == "all":
                return True
            else:
                return False



    return True

    # Check if password is correct -> do some encryption/decryption on db side
    # set CURRENT_USER variable to the unique ID of the user that just logged in.
    # CURRENT_USER = <query to get unique ID>


def list_files(directory, username):
    for root, dirs, files in os.walk(directory):
        for f in files:
            f_path = os.path.join(root, f)

            #dbsetup.db_check_file_name_integrity(f, f_path, username)

            with open(f_path, 'r') as fi:
                content = fi.read()
                dbsetup.db_check_file_content_integrity(f, content, f_path, username)


if __name__ == '__main__':

    main()