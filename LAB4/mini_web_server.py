import logging
import threading
import socket
import select
from os.path import join

MAX_INCOMING_CONNECTION = 5

def generate_response(client_ip, client_port, body=None):
    response_body = (f'Hello, you are talking to mini web server\r\n' 
                f'your address: {client_ip}:{client_port}\r\n')
    if body != None:
        response_body += f'your words:   {body}\r\n'
    response_header = (
        f'HTTP/1.1 200 OK\r\n'
        f'Content-Type: text/plain\r\n'
        f'Content-Length: {len(response_body)}\r\n\r\n')
    return response_header + response_body

class Mini_server(threading.Thread):
    def __init__(
            self, 
            ip,
            port,
            nickname,
    ):
        super().__init__()
        self.ip = ip
        self.port = port
        self.running = True
        self.nickname = nickname
        self.setup_logger()
        self.logger.info(f'\n\n\n\nstarting new run! initialize...')
        self.logger.info(f'ip: {self.ip}, port: {self.port}')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # to ignore TIME_WAIT for the sake of ease.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(MAX_INCOMING_CONNECTION)
        self.sock_list = [self.sock]

    def setup_logger(self):
        home_dir = join('data', self.nickname)
        filename = join(home_dir, self.nickname+'.log')
        self.logger = logging.getLogger(self.nickname)
        handler = logging.FileHandler(filename)
        fmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(fmtr)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    def run(self):
        client_list = []
        while self.running:
            readable, _, _ = select.select(self.sock_list, [], [], 0.5)
            self.logger.info(f'readable: {len(readable)}, clients: {len(client_list)}')
            for sock in readable:
                if sock == self.sock:
                    try:
                        client, addr = sock.accept()
                        client_list.append(client)
                        self.sock_list.append(client)
                        self.logger.info(f'client {addr} tries to connect')
                    except Exception as e:
                        self.logger.warning(
                            f'Encountered exception {e} when accepting client! '
                            f'Continue...')
                        continue
                elif sock in client_list:
                    try:
                        request = sock.recv(4096).decode('utf-8')
                        if len(request) == 0:
                            sock.close()
                            client_list.remove(sock)
                            self.sock_list.remove(sock)
                            continue
                        self.logger.info(f'got request: {request}\n')
                        header, body = request.split('\r\n\r\n', 1)
                        header_lines = header.split('\r\n')
                        client_ip, client_port = sock.getpeername()

                        if header_lines[0].startswith('GET / HTTP/'):
                            response = generate_response(client_ip, client_port)
                            self.logger.info(f'response: {response}')
                            sock.send(response.encode('utf-8'))
                        elif header_lines[0].startswith('POST /echo HTTP/'):
                            response = generate_response(client_ip, client_port, body)
                            self.logger.info(f'response: {response}')
                            sock.send(response.encode('utf-8'))
                        else: 
                            raise Exception('Invalid request line')
                    except Exception as e:
                        self.logger.warning(
                            f'Encountered exception {e} when handling request! '
                            f'Continue...')
                        response = (f'HTTP/1.1 400 Bad Request\r\n'
                                    f'Content-Type: text/plain\r\n'
                                    f'Content-Length: {7+len(str(e))}\r\n\r\n'
                                    f'Error: {str(e)}')
                        if sock:
                            sock.send(response.encode('utf-8'))
        self.clean_up()

    def stop(self):
        self.logger.info(f'stop() is called!')
        self.running = False
    
    def clean_up(self):
        self.logger.info(f'cleanup(): cleaning up relay on port {self.port}')
        for sock in self.sock_list:
            sock.close()
