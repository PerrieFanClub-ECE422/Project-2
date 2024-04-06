import os
import dbsetup
ROOT_DIR = "/home/ubuntu/Project-2/root"

def pwd(): # see current directory
    curdir = os.getcwd()
    display_dir = curdir.replace(ROOT_DIR, "root")
    print("Current dir: ", display_dir)
    return display_dir



ROOT_DIR_SHORT = os.path.dirname(os.path.abspath(__file__))
def pwd_short():
    curdirshort = os.getcwd()
    # Make the path relative to ROOT_DIR_SHORT if within it
    if curdirshort.startswith(ROOT_DIR_SHORT):
        display_dir_short = curdirshort.replace(ROOT_DIR_SHORT, "").lstrip(os.sep)
        display_dir_short = os.sep + display_dir_short if display_dir_short else "root"
    else:
        # Fallback in case the current dir is outside ROOT_DIR_SHORT
        display_dir_short = curdirshort  
    return display_dir_short



# old version
# def ls(): # list directory
#     files = os.listdir('.')
#     for file in files: 
#         print(file, end="  ")

def ls(dir_path='.'):
    try:
        files = os.listdir(dir_path)
        for file in files:
            print(file, end="  ")
        print()
    except FileNotFoundError:
        print(f"Error: Directory '{dir_path}' not found.")
    except PermissionError:
        print(f"Error: Permission denied to access '{dir_path}'.")
    except Exception as e:
        print(f"Error: {e}")


def cd(directory): # change dir
    os.chdir(directory)
    print("Now in ", os.getcwd())

    return 

def mkdir(new_dir, owner_name): # make new subdir in current directory on disk
    current_dir = os.getcwd()

    # Create a new directory inside the current directory
    new_dir_path = os.path.join(current_dir, new_dir)
    os.mkdir(new_dir_path)
    #create a new directory for the user in database
    dbsetup.db_create_directory(new_dir, owner_name)

    return 

def touch(file_name, owner_name): # create a new file (txt)
    #TODO: CHECK IF USER HAS DIRECTORY PERMS
    try:
        # Check if the file already exists
        if not os.path.exists(file_name):
            # If it doesn't exist, create file
            with open(file_name, 'w'):
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
    except Exception as e:
        print(f"Error: {e}")


def mv(file_name, new_name): #rename a file
    try:

        # Check if the new file name exists to avoid accidental overwriting
        if not os.path.exists(new_name):
            # If it doesn't exist, rename file
            os.rename(file_name, new_name)
            print(f"File '{file_name}' renamed to '{new_name}'")
    except FileNotFoundError:
        print(f"Error: '{file_name}' does not exist.")
    except Exception as e:
        print(f"Error: {e}")

def chmod(flag, mode, file_name):
    return
