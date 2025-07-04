import subprocess

target = input("Enter target ip or url:")
result = subprocess.run(['nmap', '-sV' , target], capture_output=True, text=True)

print (result.stdout)