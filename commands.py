import os


def pwd(): # see current directory
    curdir = os.getcwd()
    print("Current dir: ", curdir)
    return 

def ls():
    files = os.listdir('.')
    for file in files: 
        print(file, end="  ")


def cd(): # change dir
    return 

def mkdir(): # make new subdir in current directory
    return 

def touch(): # create a new file (txt)
    return 

def cat(): #read a file
    return

def echo(): #write to a file
    return

def mv(): #rename a file
    return 

