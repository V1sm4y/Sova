import re

def extract_http_ports(nmap_output):
    
    http_ports = []
    pattern = re.compile(r'^(\d+)/tcp\s+open\s+(http\S*)', re.MULTILINE)

    matches = pattern.findall(nmap_output)
    for match in matches:
        port = int(match[0])
        http_ports.append(port)

    return http_ports

if __name__ == "__main__":
    filename = input("Enter the filename of the Nmap output: ")
    with open(filename, 'r') as f:
        output = f.read()

    ports = extract_http_ports(output)
    print("HTTP ports found:", ports)
