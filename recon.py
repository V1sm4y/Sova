import nmap
import subprocess
target = input("Enter target IP or URL: ")

# Call nmap.py and pass the target as an argument
subprocess.run(['python', 'nmap.py', target])