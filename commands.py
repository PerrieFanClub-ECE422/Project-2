import os
import dbsetup
ROOT_DIR = "/home/ubuntu/Project-2/root"

def pwd(): # see current directory
    curdir = os.getcwd()
    display_dir = curdir.replace(ROOT_DIR, "root")
    print("Current dir: ", display_dir)
    return display_dir

def ls():
    files = os.listdir('.')
    for file in files: 
        print(file, end="  ")


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
    print(f"Directory '{new_dir}' created successfully on disk.")

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

def mv(): #rename a file
    return 

