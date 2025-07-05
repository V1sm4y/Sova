import nmap
import http_parser

def main():
    # 1️⃣ Get target from user
    target = input("Enter target IP or URL: ")

    # 2️⃣ Call run_nmap() from nmap.py — returns output filename
    output_filename = nmap.run_nmap(target)

    # 3️⃣ Read saved file
    with open(output_filename, 'r') as f:
        nmap_output = f.read()

    # 4️⃣ Call extract_http_ports() from http_parser.py
    http_ports = http_parser.extract_http_ports(nmap_output)

    if http_ports:
        print(f"\n🔍 HTTP ports found: {http_ports}")
    else:
        print("\n❌ No HTTP ports found.")

if __name__ == "__main__":
    main()
