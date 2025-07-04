import subprocess
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap.py <target>")
        sys.exit(1)

target = sys.argv[1]

result = subprocess.run(['nmap', '-sS', '-sV', '-sC', target], capture_output=True, text=True)

print(result.stdout)

output = input("What would you like to name the file that stores Nmap data? : ")

if not output.endswith('.txt'):
    output += '.txt'

with open(output, 'w') as f:
    f.write(result.stdout)

print(f"Output saved in {output}")
