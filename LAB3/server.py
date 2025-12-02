#!/usr/bin/python3

from sys import argv
from http.server import BaseHTTPRequestHandler, HTTPServer

hostnames = None

class CS341RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global hostnames
        host = self.headers.get('Host')
        if host in hostnames:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            client = self.client_address[0]
            self.wfile.write(f'Hello {client}, I am {host}\n'.encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            client = self.client_address[0]
            self.wfile.write(f'Hello {client}, I am not {host}\n'.encode('utf-8'))

    def do_POST(self):
        self.do_GET()

if __name__ == '__main__':
    if len(argv) < 3:
        print('Usage: python3 server.py <hostname1> <hostname2> ...')
        exit
    print(argv)
    hostnames = argv[1:] # argv: ['server.py', <hostname1>, <hostname2>, ...]
    print(hostnames)
    server = HTTPServer(('0.0.0.0', 80), CS341RequestHandler)
    server.serve_forever()