import os
import dbsetup
import main
ROOT_DIR = "/home/ubuntu/Project-2/root"

def pwd(): # see current directory
    curdir = os.getcwd()
    return curdir



ROOT_DIR_SHORT = os.path.dirname(os.path.abspath(__file__))

def decrypt_sfs_path(path):
    # Split the path into segments
    segments = path.split(os.sep)
    
    # Find the index of "root" in the segments
    root_index = segments.index("root")
    
    # Encrypt the segments after "root"
    decrypted_segments = [dbsetup.db_decrypt_data(segment) for segment in segments[root_index + 1:]]
    
    # Join the encrypted segments back together
    encrypted_path = os.sep.join(segments[:root_index + 1] + decrypted_segments)
    
    return encrypted_path

def pwd_short():
    curdirshort = os.getcwd()
    # Make the path relative to ROOT_DIR_SHORT if within it
    if curdirshort.startswith(ROOT_DIR_SHORT):
        display_dir_short = curdirshort.replace(ROOT_DIR_SHORT, "").lstrip(os.sep)
        display_dir_short = os.sep + decrypt_sfs_path(display_dir_short) if display_dir_short else "root"
    else:
        # Fallback in case the current dir is outside ROOT_DIR_SHORT
        display_dir_short = curdirshort  
    return display_dir_short



def ls(username, dir_path):
    try:
        files = os.listdir(dir_path)
        for file in files:
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


def cd(current_directory, current_user_name, target_directory): # change dir
    e_dir_name=dbsetup.db_encrypt_data(target_directory)
    dir_path = os.path.join(current_directory, e_dir_name)

    if main.check_directory_perms(current_user_name, e_dir_name, dir_path):
        os.chdir(dir_path)
    elif not os.path.exists(dir_path):
        print(f"No directory {target_directory} exists")
    else:
        print(f"No access to directory {target_directory}")

    return 


def mkdir(new_dir, owner_name):
    e_new_dir = dbsetup.db_encrypt_data(new_dir)
    print(e_new_dir)
    # Create a new directory inside the current directory
    new_dir_path = os.path.join(os.getcwd(), e_new_dir)
    print("new_dir_path", new_dir_path)
    os.mkdir(new_dir_path)
    #create a new directory for the user in database

    dbsetup.db_create_directory(dbsetup.db_decrypt_data(e_new_dir), owner_name)


def touch(file_name, owner_name): # create a new file (txt)

    e_file_name = dbsetup.db_encrypt_data(file_name)

    try:
        # Check if the file already exists
        if not os.path.exists(e_file_name):
            # If it doesn't exist, create file
            with open(e_file_name, 'w'):
                pass
            dbsetup.db_create_file(file_name, owner_name)
            print(f"File '{file_name}' created successfully.")
        else:
            print(f"File '{file_name}' already exists!")

    except Exception as e:
        print("Error:", e)

    return 

def cat(file_name): #read a file
    try:
        # open the file to read
        with open(file_name, 'r') as file:
            content = file.read()
            print(content)
    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found!")
    except Exception as e:
        print(f"Error: {e}")



def echo(file_name, content): #write to a file
    try:
        # open the file to write/overwrite
        with open(file_name, 'w') as file:
            file.write(content)
            print(f"Content written to '{file_name}'")
        
        #TODO: CHANGE IN DB
    except Exception as e:
        print(f"Error: {e}")


def mv(file_name, new_name): #rename a file
    try:

        # Check if the new file name exists to avoid accidental overwriting
        if not os.path.exists(new_name):
            # If it doesn't exist, rename file
            os.rename(file_name, new_name)
            # TODO: need to rename in db?
            print(f"File '{file_name}' renamed to '{new_name}'")
    except FileNotFoundError:
        print(f"Error: '{file_name}' does not exist.")
    except Exception as e:
        print(f"Error: {e}")

def chmod(flag, mode, file_name):

    return
