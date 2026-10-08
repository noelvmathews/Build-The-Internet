import http.server
import socketserver
import urllib.request
import urllib.parse
import json

PORT = 4000

class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/proxy":
            params = urllib.parse.parse_qs(parsed.query)
            target = params.get("target", [None])[0]
            if not target:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing target parameter")
                return
            
            try:
                req = urllib.request.Request(target, headers={'User-Agent': 'MeshPulse/1.0'})
                with urllib.request.urlopen(req, timeout=5) as response:
                    self.send_response(response.status)
                    for k, v in response.getheaders():
                        if k.lower() not in ['transfer-encoding', 'content-encoding']:
                            self.send_header(k, v)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(response.read())
            except urllib.error.HTTPError as e:
                self.send_response(e.code)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(e.read())
            except Exception as e:
                self.send_response(502)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return
        
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/proxy":
            params = urllib.parse.parse_qs(parsed.query)
            target = params.get("target", [None])[0]
            if not target:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing target parameter")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            try:
                req = urllib.request.Request(
                    target, 
                    data=body, 
                    headers={'Content-Type': 'application/json', 'User-Agent': 'MeshPulse/1.0'}
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    self.send_response(response.status)
                    for k, v in response.getheaders():
                        if k.lower() not in ['transfer-encoding', 'content-encoding']:
                            self.send_header(k, v)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(response.read())
            except urllib.error.HTTPError as e:
                self.send_response(e.code)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(e.read())
            except Exception as e:
                self.send_response(502)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), ProxyHandler) as httpd:
        print(f"[*] MeshPulse Gateway running at http://localhost:{PORT}")
        httpd.serve_forever()
