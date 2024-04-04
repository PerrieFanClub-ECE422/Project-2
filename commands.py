import os

ROOT_DIR = "/home/ubuntu/Project-2"

def pwd(): # see current directory
    curdir = os.getcwd()
    display_dir = curdir.replace(ROOT_DIR, "root/")
    print("Current dir: ", display_dir)
    return 

def ls():
    files = os.listdir('.')
    for file in files: 
        print(file, end="  ")


def cd(directory): # change dir
    os.system("cd" + directory)
    return 

def mkdir(new_dir, owner_name): # make new subdir in current directory
    current_dir = os.getcwd()

    # Create a new directory inside the current directory
    new_dir_path = os.path.join(current_dir, new_dir)
    os.mkdir(new_dir_path)

    print(f"Directory '{new_dir}' created successfully.")

    return 

def touch(file_name, owner_name): # create a new file (txt)
    try:
        # Check if the file already exists
        if not os.path.exists(file_name):
            # If it doesn't exist, create an empty file
            with open(file_name, 'w'):
                pass
            
            print(f"File '{file_name}' created successfully.")
        else:
            # If it exists, update its access and modification timestamps
            print(f"File '{file_name}' already exists!")
    except Exception as e:
        print("Error:", e)

    return 

def cat(): #read a file
    return

def echo(): #write to a file
    return

def mv(): #rename a file
    return 

