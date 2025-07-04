import subprocess
import sys

# Get target ONLY from command-line argument
target = sys.argv[1]

# Run nmap with the target
result = subprocess.run(['nmap', '-sS', '-sV', '-sC', target], capture_output=True, text=True)

print(result.stdout)

output = input("What would you like to name the file that stores Nmap data? : ")

if not output.endswith('.txt'):
    output += '.txt'

with open(output, 'w') as f:
    f.write(result.stdout)

print(f"Output saved in {output}")
