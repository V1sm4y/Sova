from http.server import SimpleHTTPRequestHandler, HTTPServer

# Listen on all interfaces (0.0.0.0) so you can access it from other machines
host = "0.0.0.0"
port = 8080

server = HTTPServer((host, port), SimpleHTTPRequestHandler)
print(f"Serving HTTP on {host} port {port} (http://{host}:{port}/) ...")
server.serve_forever()
