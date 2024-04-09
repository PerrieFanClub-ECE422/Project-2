import os
import dbsetup
import main
ROOT_DIR_SHORT = os.path.dirname(os.path.abspath(__file__))

def pwd(): # see current directory
    curdir = os.getcwd()
    return curdir

def decrypt_sfs_path(path):
    #this function will decrypt paths after root to show in terminal
    segments = path.split(os.sep)
    root_index = segments.index("root")
    decrypted_segments = [dbsetup.db_decrypt_data(segment) for segment in segments[root_index + 1:]]
    encrypted_path = os.sep.join(segments[:root_index + 1] + decrypted_segments)
    return encrypted_path

def pwd_short():
    #prints shortened version of pwd
    curdirshort = os.getcwd()

    if curdirshort.startswith(ROOT_DIR_SHORT):
        display_dir_short = curdirshort.replace(ROOT_DIR_SHORT, "").lstrip(os.sep)
        display_dir_short = os.sep + decrypt_sfs_path(display_dir_short) if display_dir_short else "root"
    else:
        display_dir_short = curdirshort  
    return display_dir_short

def ls(username, dir_path): # ------------------------------------ ls command
    try:
        files = os.listdir(dir_path)
        for file in files:
            #check if they have permissions to view the decrypted view of either the file or folder
            if main.check_directory_perms(username, file, os.path.join(dir_path,file)) or main.check_file_perms(username, file, os.path.join(dir_path,file)):
                print(dbsetup.db_decrypt_data(file), end="  ")
            else:
                print(file, end="  ")
        print()
    except FileNotFoundError:
        print(f"Error: Directory '{dir_path}' not found.")
    except PermissionError:
        print(f"Error: Permission denied to access '{dir_path}'.")
    except Exception as e:
        print(f"Error: {e}")

def cd(current_directory, current_user_name, target_directory): # ------------------------------------ cd command
    e_dir_name=dbsetup.db_encrypt_data(target_directory)
    dir_path = os.path.join(current_directory, e_dir_name)
    #check if they have permissions
    if main.check_directory_perms(current_user_name, e_dir_name, dir_path):
        os.chdir(dir_path)
    elif not os.path.exists(target_directory):
        print(f"No directory {target_directory} exists")
    else:
        print(f"No access to directory {target_directory}")

    return 

def mkdir(new_dir, owner_name):# ------------------------------------ mkdir command

    e_new_dir = dbsetup.db_encrypt_data(new_dir)
    
    new_dir_path = os.path.join(os.getcwd(), e_new_dir)
    os.mkdir(new_dir_path)
    #create a new directory for the user in database

    dbsetup.db_create_directory(dbsetup.db_decrypt_data(e_new_dir), owner_name)

def touch(file_name, owner_name):# ------------------------------------ touch command

    e_file_name = dbsetup.db_encrypt_data(file_name)

    try:
        if not os.path.exists(e_file_name):
            with open(e_file_name , 'w') as file:
                file.write(dbsetup.db_encrypt_data(""))
                pass
            dbsetup.db_create_file(file_name, owner_name)
            print(f"File '{file_name}' created successfully.")
        else:
            print(f"File '{file_name}' already exists!")

    except Exception as e:
        print("Error:", e)

    return 

def rm(file_name, owner_name): # ------------------------------------ rm command
    e_file_name = dbsetup.db_encrypt_data(file_name)

    try:
        if os.path.exists(e_file_name):
            os.remove(e_file_name)
            dbsetup.db_delete_file(file_name, owner_name)
            print(f"File '{file_name}' deleted successfully.")
        else:
            print(f"File '{file_name}' does not exist!")

    except Exception as e:
        print("Error:", e)

def cat(file_name): # ---------------------------------------------------------- cat command
    e_file_name = dbsetup.db_encrypt_data(file_name)

    try:
        # open the file to read
        with open(e_file_name, 'r') as file:
            content = file.read()
            if content:
                print(dbsetup.db_decrypt_data(content))
    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found!")
    except Exception as e:
        print(f"Error: {e}")

def echo(file_name, content): # ---------------------------------------------------------- echo command
    e_file_name = dbsetup.db_encrypt_data(file_name)

    try:
        if not os.path.exists(e_file_name):
            print(f"No file {file_name} exists.")
        else: 
            # open the file to write/overwrite
            with open(e_file_name, 'w') as file:
                file.write(dbsetup.db_encrypt_data(content))
                dbsetup.db_modify_file_contents(file_name, content)
                print(f"Content written to '{file_name}'")
        
    except Exception as e:
        print(f"Error: {e}")

def mv(file_name, new_name): # ---------------------------------------------------------- mv command
    e_file_name = dbsetup.db_encrypt_data(file_name)
    e_new_name = dbsetup.db_encrypt_data(new_name)

    try:
        if not os.path.exists(e_new_name):

            os.rename(e_file_name, e_new_name)
            dbsetup.db_modify_file_name(file_name, new_name)
            print(f"File '{file_name}' renamed to '{new_name}'")
    except FileNotFoundError:
        print(f"Error: '{file_name}' does not exist.")
    except Exception as e:
        print(f"Error: {e}")