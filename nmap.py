import subprocess

target = input("Enter target ip or url:")
result = subprocess.run(['nmap', '-sS' , '-sV', '-sC' , target], capture_output=True, text=True)

print (result.stdout)

output = input("what would you like to name the file that stores nmap data? : ")

with open(output , 'w') as f:
    f.write(result.stdout)