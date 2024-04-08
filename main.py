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
    listgroups = dbsetup.db_get_existing_groups()
    valid_group_names = []

    if not listgroups:
        print("No groups made, please make a group to become apart of one.")
    else: 
        group_names = input("Enter group names separated by comma (Leave empty for no groups): ").strip()

        if group_names:
            selected_groups = [g.strip() for g in group_names.split(",")]
            valid_group_names = [g for g in selected_groups if g in listgroups]
            invalid_groups = [g for g in selected_groups if g not in listgroups]
            if invalid_groups:
                print("Non-existing group names: ", ", ".join(invalid_groups))
            
    group_name = ",".join(valid_group_names) if valid_group_names else None
    result = dbsetup.db_add_user(username.lower(), password, group_name)

    if result:
        print("Registration succeeded")
        commands.mkdir(username, username)

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
    check_integrity(os.path.join(os.getcwd(),dbsetup.db_encrypt_data(current_user_name)), dbsetup.db_encrypt_data(current_user_name))
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
                    commands.cd(os.getcwd(), current_user_name, cmd[1])

        elif cmd[0] == "pwd": # ----------------------------------------------- pwd
            print("Current Directory: ",commands.pwd())
        
        elif cmd[0] == "ls": # ----------------------------------------------- ls
            if len(cmd) > 1:
                commands.ls(current_user_name, os.path.join(os.getcwd(), cmd[1]))
            else:
                commands.ls(current_user_name,os.getcwd())
        
        elif cmd[0] == "touch": # ----------------------------------------------- touch
            if len(cmd) < 2:
                print("please specify a file name")
            else:
                dir_path = commands.pwd()
                dir_name = os.path.basename(dir_path)
                
                if check_directory_perms(current_user_name, dir_name, dir_path): 
                     commands.touch(cmd[1], current_user_name)
                else: 
                    print(f"{current_user_name}:No permission to access directory")
        
        elif cmd[0] == "mkdir": # ----------------------------------------------- mkdir
            if len(cmd) < 2:
                print("please specify a directory name")
            else:
                dir_path = commands.pwd()
                dir_name = os.path.basename(dir_path)

                if check_directory_perms(current_user_name, dir_name, dir_path):
                    commands.mkdir(cmd[1], current_user_name)
                else: 
                    print(f"{current_user_name}:No permission to access directory")

        
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
                print("Please specify flag and target name.")
            else:
                flag = cmd[1]
                target_name = cmd[2]
                if flag in ["-d", "-f"]:
                    dbsetup.prompt_and_change_permissions(target_name, current_user_name, fileflag=(flag == "-f"))
                else:
                    print("Invalid flag!")
        
        elif cmd[0] == "cmds": # ----------------------------------------------- cmds
            print(cmds)
        
        elif cmd[0] == "exit": # ----------------------------------------------- exit
            # Change directory to ~/root on exit
            root_dir = os.path.join(os.path.expanduser('~'), 'Project-2/root')
            os.chdir(root_dir)
            print("Exiting...")
            break
        
        else:
            print("command not recognized; type 'cmds' to list all commands")


def check_file_perms(curruser, file_name, file_path):
    if curruser == "":
        print(f"{curruser}:No permission to access file")
        return False
    else:
        curruser_id = dbsetup.db_get_user_id(curruser)
        file_perms = dbsetup.db_get_file_perms(file_name, file_path)
        file_owner_id = dbsetup.db_get_file_owner(file_name, file_path)
        if file_perms:
            if file_perms == "owner" and (curruser_id == file_owner_id):
                return True
            elif file_perms == "owner" and (curruser_id != file_owner_id):
                return False
            elif file_perms[0] == "all":
                return True
            elif dbsetup.db_check_user_in_group(curruser, file_perms):
                return True
            else:
                return False
        else:
            return False

def check_directory_perms(curruser, dir_name, dir_path):
    """
    Args:
    dir_name: name of the folder(directory) that you wish to check perms for
    dir_path: unique path of the folder(directory) that you wish to check perms for
    """
    if curruser == "":
        return False
    else:
        curruser_id = dbsetup.db_get_user_id(curruser)
        dir_perms = dbsetup.db_get_directory_perms(dir_name, dir_path)
        dir_owner_id = dbsetup.db_get_directory_owner(dir_name, dir_path)
    
    if dir_perms:
        if dir_perms == "owner" and (curruser_id == dir_owner_id):
            return True
        elif dir_perms == "owner" and (curruser_id != dir_owner_id):
            return False
        elif dir_perms[0] == "all":
            return True
        elif dbsetup.db_check_user_in_group(curruser, dir_perms):
            return True
        else:
            return False
    else: 
        return False


    return True

    # Check if password is correct -> do some encryption/decryption on db side
    # set CURRENT_USER variable to the unique ID of the user that just logged in.
    # CURRENT_USER = <query to get unique ID>


def check_integrity(directory, username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
    '''
    SELECT file_path, file_name
    FROM files
    '''
    )
    corrupted_files = cursor.fetchall()

    cursor.execute(
    '''
    SELECT dir_path, dir_name
    FROM directories
    WHERE dir_name != (SELECT username FROM users) AND dir_name != ?
    ''',
    ("root",)
    )
    corrupted_dirs = cursor.fetchall()


    for root, dirs, files in os.walk(directory):
        for e_file_name in files:
            f_path = os.path.join(root, e_file_name)
            for corrupted_path, corrupted_name in corrupted_files:
                if corrupted_name == e_file_name and corrupted_path in f_path:
                    corrupted_files.remove((corrupted_path, corrupted_name))
                    break  

            with open(f_path, 'r') as fi:
                e_content = fi.read()
                dbsetup.db_check_file_content_integrity(e_file_name, e_content, f_path, username)
        for e_dir_name in dirs:
            d_path = os.path.join(root, e_dir_name)
            for corrupted_path, corrupted_name in corrupted_dirs:
                if corrupted_name == e_dir_name and corrupted_path in d_path:
                    corrupted_dirs.remove((corrupted_path, corrupted_name))
                    break
    if corrupted_dirs:
        print("Original directories names that have been changed:")
        for dir_path, dir_name in corrupted_dirs:
            print(f"Directory name: {dbsetup.db_decrypt_data(dir_name)}, Directory path: {decrypt_directory_names(dir_path)}")
    if corrupted_files:
        print("Original file names that have been changed:")
        for file_path, file_name in corrupted_files:
            print(f"Filename: {dbsetup.db_decrypt_data(file_name)}, Filepath: {decrypt_directory_names(file_path)}")

def decrypt_directory_names(file_path):
    path_components = file_path.split('/')

    decrypted_path = ""

    root_found = False

    for directory_name in path_components:
        if directory_name == 'root':
            root_found = True
            decrypted_path += "root/"
        elif root_found:
            decrypted_directory_name = dbsetup.db_decrypt_data(directory_name)
            decrypted_path += decrypted_directory_name + '/'
        else: 
            decrypted_path += directory_name + '/'

    # Remove the trailing '/' if present
    if decrypted_path.endswith('/'):
        decrypted_path = decrypted_path[:-1]

    return decrypted_path

if __name__ == '__main__':
    dbsetup.init_global_keys()
    main()