import os

def ls():
    files = os.listdir('.')
    for file in files: 
        print(file, end="  ")


