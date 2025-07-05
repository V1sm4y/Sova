import subprocess

def gobuster():
    wordlist = input("Enter wordlist path: ")
    rsultgo = subprocess.run(['gobuster' , 'dir' , '-u' , '-w' ])
    