import logging
import threading
import socket
import select
from os.path import join
import mini_crypt

MAX_INCOMING_CONNECTION = 5
RSA2048_SIGN_LEN = 256


def recv_descriptor_request(descriptor_list, private_key, logger):
    response_body = ''
    for descriptor in descriptor_list:
        response_body += descriptor + '\r\n'

    sign = mini_crypt.RSA_sign_msg(private_key, response_body.encode('utf-8'))

    response_body += 'AUTH_SIGN_LEN:' + str(len(sign)) + '\r\n' \
            + 'AUTH_SIGNATURE:'+ sign.hex() + '\r\n'

    response_header = (
        f'HTTP/1.1 200 OK\r\n'
        f'Content-Type: text/plain\r\n'
        f'Content-Length: {len(response_body)}\r\n\r\n')
    return response_header + response_body


def check_descriptor(descriptor):
    fields = descriptor.split('\r\n')
    for line in fields:
        if line.startswith('PUBLIC_K:'):
            pub_k_in_bytes = line.split(':', 1)[1]
            break
    else: return False

    pub_k = mini_crypt.deserialize_public_key_from_bytes(pub_k_in_bytes.encode('utf-8'))
    message = (descriptor.split('SIGN_LEN:', 1)[0]).encode('utf-8')
    sign = bytes.fromhex(descriptor.split('SIGNATURE:',1)[1][:RSA2048_SIGN_LEN*2])
    if mini_crypt.RSA_verify_sign(pub_k, message, sign):
        return True
    else: return False


def recv_descriptor_registration(header_lines, body, descriptor_list):
    for line in header_lines:
        if line.startswith('Content-Length:'):
            content_length = int(line.split(':')[1].strip())
            break
    else: raise Exception('Content-Length not found')

    body = body[:content_length]
    if check_descriptor(body):
        descriptor_list.append(body)
        response_body = 'Descriptor registered successfully'
    else: response_body = 'Bad descriptor'

    response_header = (
        f'HTTP/1.1 200 OK\r\n'
        f'Content-Type: text/plain\r\n'
        f'Content-Length: {len(response_body)}\r\n\r\n')
    return response_header + response_body


def read_PEM_file(file_path):
    data = b''
    with open(file_path, 'rb') as file_path:
        for line in file_path: data += line
    return data


class Authority(threading.Thread):
    def __init__(
            self, 
            ip,
            port,
            nickname,
            public_key_path = 'data/Auth/keys/Authority.pub',
            private_key_path = 'data/Auth/keys/Authority',
    ):
        super().__init__()
        self.ip = ip
        self.port = port
        self.running = True
        self.descriptor_list = []
        self.nickname = nickname
        self.setup_logger()
        self.logger.info(f'\n\n\n\nstarting new run! initialize...')

        self.public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(public_key_path))
        self.private_key = mini_crypt.deserialize_private_key_from_bytes(read_PEM_file(private_key_path))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # to ignore TIME_WAIT for the sake of ease.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(MAX_INCOMING_CONNECTION)


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
        try:
            while self.running:
                try:
                    readable, _, _ = select.select([self.sock], [], [], 0.5)
                    if self.sock in readable:
                        client, addr = self.sock.accept()
                        request = client.recv(4096).decode('utf-8')
                        self.logger.info(f'got request: {request}\n')
                        header, body = request.split('\r\n\r\n', 1)
                        header_lines = header.split('\r\n')

                        try:
                            if header_lines[0].startswith('POST /tor/ HTTP/'):
                                response = recv_descriptor_registration(header_lines, body, self.descriptor_list)
                                client.send(response.encode('utf-8'))
                            elif header_lines[0].startswith('GET /tor/server/all HTTP/'):
                                response = recv_descriptor_request(self.descriptor_list, self.private_key, self.logger)
                                self.logger.info(f'response: {response}')
                                client.send(response.encode('utf-8'))
                            else: 
                                raise Exception('Invalid request line')
                        except Exception as e:
                            response = (f'HTTP/1.1 400 Bad Request\r\n'
                                        f'Content-Type: text/plain\r\n'
                                        f'Content-Length: {7+len(str(e))}\r\n\r\n'
                                        f'Error: {str(e)}')
                            client.send(response.encode('utf-8'))
                except Exception as e:
                    self.logger.warning(f'Encountered exception {e}! Continue...')
                    continue
        finally:
            self.clean_up()
        return

    def stop(self):
        self.logger.info(f'stop() is called!')
        self.running = False
    
    def clean_up(self):
        self.logger.info(f'cleanup(): cleaning up relay on port {self.port}')
        self.sock.close()
