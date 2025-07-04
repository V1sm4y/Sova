import re

def extract_http_ports(nmap_aoutput):
    http_port = []
    pattern = re.compile(r'^(\d+)/tcp\s+open\s+(http\S*)', re.MULTILINE)
    pattern = re.compile(r'^(\d+)/tcp\s+open\s+(http\S*)', re.MULTILINE)
    
    matches = pattern.findall(nmap_output)
    for match in matches:
        port = int(match[0])
        http_ports.append(port)

    return http_ports


# Example usage:
with open('yes.txt', 'r') as f:
    output = f.read()

ports = extract_http_ports(output)
print("HTTP ports found:", ports)