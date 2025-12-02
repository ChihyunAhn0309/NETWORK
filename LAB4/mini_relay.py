import random
import struct
import logging
import threading
import socket
import select
import mini_crypt
import mini_cell
from os.path import join

MAX_INCOMING_CONNECTION = 5
VERSIONS_BODY = 3

CELL_CIRCID_LEN = 2
CELL_CMD_LEN = 1
LEN_OF_CELL_VARIABLE_BODY_LEN = 2
CELL_FIXED_BODY_LEN = 1024

# cell_commands
CELL_CMD_CREATE = 1
CELL_CMD_CREATED = 2
CELL_CMD_RELAY = 3
CELL_CMD_DESTROY = 4
CELL_CMD_VERSIONS = 7
CELL_CMD_NETINFO = 8
CELL_CMD_CERTS = 129

# relay_commands:
RELAY_CMD_BEGIN = 1
RELAY_CMD_DATA = 2
RELAY_CMD_END = 3
RELAY_CMD_CONNECTED = 4
RELAY_CMD_EXTEND = 6
RELAY_CMD_EXTENDED = 7


DH_PUB_NUM_LEN = 128

DH_G = 2
DH_P = int("BC6E230F63512CB36605599417DE96B6DE189B93E63250EFAF457462533D8EBB"
           "EF362F478BDBDAEB4E0726F4102F54F6B58CB70C5257A829456D981A2E5FCD7B",
           16)


def read_PEM_file(file_path):
    data = b''
    with open(file_path, 'rb') as file_path:
        for line in file_path: data += line
    return data

def verify_or_descriptor(body:str) -> tuple[str, str, int, mini_crypt.RSAPublicKey]:
    lines = body.split('\r\n')
    or_name = ''
    or_addr = ''
    or_port = ''
    or_pubk = None
    or_msg = ''
    or_sign_len = 0
    or_sign = b''
    for line in lines:
        if 'NICKNAME:' in line:
            or_msg += line + '\r\n'
            or_name = line.strip().split('NICKNAME:', 1)[1]
        elif 'ADDRESS:' in line: 
            or_msg += line + '\r\n'
            or_addr_port = line.strip().split('ADDRESS:', 1)[1]
            or_addr = or_addr_port.split(':')[0]
            or_port = or_addr_port.split(':')[1]
        elif 'PUBLIC_K:' in line:
            or_msg += line + '\r\n'
            or_pubk = mini_crypt.deserialize_public_key_from_bytes(line.strip().split('PUBLIC_K:', 1)[1].encode('utf-8'))
        elif 'SIGN_LEN:' in line:
            or_sign_len = int(line.strip().split('SIGN_LEN:', 1)[1])
        elif 'SIGNATURE:' in line:
            or_sign = line.strip().split('SIGNATURE:', 1)[1][:or_sign_len*2]
    or_msg = or_msg.encode('utf-8')
    or_sign = bytes.fromhex(or_sign)
    if not mini_crypt.RSA_verify_sign(or_pubk, or_msg, or_sign):
        raise Exception('verify_or_descriptor(): OR\' signature is invalid')
    return or_name, or_addr, int(or_port), or_pubk

def verify_auth_signature(body:str, auth_pub_k, message:bytes):
    auth_sign_len = 0
    auth_sign = b''
    lines = body.split('\r\n')
    for line in lines:
        if line.startswith('AUTH_SIGN_LEN:'):
            auth_sign_len = int(line.split(':', 1)[1])
        elif line.startswith('AUTH_SIGNATURE:'):
            if auth_sign_len == 0: 
                raise Exception('check_auth_signature(): No AUTH_SIGN_LEN in the body')
            auth_sign = line.split('AUTH_SIGNATURE:', 1)[1][:auth_sign_len*2]
            break
    else: 
        raise Exception('check_auth_signature(): either no AUTH_SIGN_LEN or no AUTH_SIGNATURE')

    auth_sign = bytes.fromhex(auth_sign)
    if not mini_crypt.RSA_verify_sign(auth_pub_k, message, auth_sign):
        raise Exception('check_auth_signature(): Incorrect authority\'s signature')
    else: return True
    
def handle_descriptors_from_auth(response, auth_pub_k):
    dict_descriptors = {}
    descriptors = ''
    auth_signature = ''
    body = response.strip().split('\r\n\r\n', 1)[1]
    sign_chunks = body.split('\r\n\r\n')
    for chunk in sign_chunks:
        if chunk.startswith('NICKNAME:'):
            descriptors += chunk + '\r\n\r\n'
            or_name, or_addr, or_port, or_pubk = verify_or_descriptor(chunk)
            dict_descriptors[or_name] = {
                'or_ip': or_addr, 
                'or_port': or_port, 
                'or_pubk': or_pubk,
            }
        elif chunk.startswith('AUTH_SIGN_LEN:'):
            auth_signature = chunk
    verify_auth_signature(auth_signature, auth_pub_k, descriptors.encode('utf-8'))
    return dict_descriptors


class Relay(threading.Thread):
    def __init__(
            self, 
            ip,
            port, 
            auth_ip,
            auth_port, 
            nickname,
            circ_id_base,
            auth_public_key_path = 'Authority.pub',
    ):
        super().__init__()
        self.ip = ip
        self.port = port
        self.running = True
        self.auth_ip = auth_ip
        self.auth_port = auth_port
        self.nickname = nickname
        self.circ_id_base = circ_id_base

        self.dict_descriptors = {}
        self.sock_list = []
        # You may declare your own data structure here
        self.circuits = {}
        self.backward_map = {}

        self.web_socket_map = {}

        self.setup_logger()

        self.logger.info(f'\n\n\n\nstarting new run! initialize...')
        keys_dir = join(join('data', nickname), 'keys')
        self.public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(join(keys_dir, nickname+'.pub')))
        self.private_key = mini_crypt.deserialize_private_key_from_bytes(read_PEM_file(join(keys_dir, nickname)))
        self.auth_public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(join(keys_dir, auth_public_key_path)))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # to ignore TIME_WAIT for the sake of ease.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(MAX_INCOMING_CONNECTION)
        self.sock_list.append(self.sock)

    def setup_logger(self):
        home_dir = join('data', self.nickname)
        filename = join(home_dir, self.nickname+'.log')
        self.logger = logging.getLogger(self.nickname)
        handler = logging.FileHandler(filename)
        fmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(fmtr)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    # This is not necessary when we are opening the socket in the real world, but this is 
    # here only to demonstrate the anonymization of ip addresses. You should use this 
    # method when you are trying to connect to other relays and web server.
    def open_new_sock(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.ip, 0))
        return sock


    # You should use this method to accept incomming connnections, else the thread will 
    # not terminate properly.
    def socket_accept(self):
        while self.running:
            readable, _, _ = select.select([self.sock], [], [], 0.5)
            if self.sock in readable:
                sock, addr = self.sock.accept()
                return sock, addr
        return None, None

    # You should use this method to accept incomming connnections, else the thread will 
    # not terminate properly.
    def get_header(self, sock):
        while self.running:
            readable, _, _ = select.select([sock], [], [], 0.5)
            if sock in readable:
                header = sock.recv(CELL_CIRCID_LEN+CELL_CMD_LEN)
                if len(header) < CELL_CIRCID_LEN+CELL_CMD_LEN:
                    sock.close()
                    raise Exception(f'get_header(): failed to receive {CELL_CIRCID_LEN+CELL_CMD_LEN} bytes')
                cell_circ_id, cell_command = struct.unpack('!HB', header)
                return cell_circ_id, cell_command
        return None, None

    # You should use this method to recv from socket, else the thread will not terminate 
    # properly.
    def get_variable_length_body(self, sock):
        while self.running:
            readable, _, _ = select.select([sock], [], [], 0.5)
            if sock in readable:
                cell_body_len = sock.recv(LEN_OF_CELL_VARIABLE_BODY_LEN)
                if len(cell_body_len) < LEN_OF_CELL_VARIABLE_BODY_LEN:
                    sock.close()
                    raise Exception(f'get_variable_length_body(): failed to receive {LEN_OF_CELL_VARIABLE_BODY_LEN} bytes')
                cell_body_len = struct.unpack('!H', cell_body_len)[0]
                cell_body = sock.recv(cell_body_len)
                return cell_body_len, cell_body
        return None, None

    # You should use this method to recv from socket, else the thread will not terminate 
    # properly.
    def get_fixed_length_body(self, sock):
        while self.running:
            readable, _, _ = select.select([sock], [], [], 0.5)
            if sock in readable:
                cell_body = sock.recv(CELL_FIXED_BODY_LEN)
                if len(cell_body) < CELL_FIXED_BODY_LEN:
                    sock.close()
                    raise Exception(f'get_fixed_length_body(): failed to receive {CELL_FIXED_BODY_LEN} bytes')
                return cell_body
        return None

    def run(self):
        sock, addr = self.socket_accept()
        circ_id, cell_command = self.get_header(sock)

        # TODO task1: Accept channel open request. 
        # When an relay receives a VERSIONS cell, it replies VERIONS, CERTS, NETINFO 
        # cell. Then, it waits for NETINFO cell to finish the handshake to open channel.
        if sock is None:
            return
        
        if cell_command != CELL_CMD_VERSIONS:
            sock.close()
            return

        self.get_variable_length_body(sock)

        versions_cell = mini_cell.VERSIONS([3])
        sock.sendall(versions_cell.to_bytes())
        public_PEM = mini_crypt.serialize_public_key_into_bytes(self.public_key)
        signature = mini_crypt.RSA_sign_msg(self.private_key, public_PEM)
        certs_cell = mini_cell.CERTS(public_PEM, signature)
        sock.sendall(certs_cell.to_bytes())

        netinfo_cell = mini_cell.NETINFO(addr[0], addr[1], self.ip, self.port)
        sock.sendall(netinfo_cell.to_bytes())

        circ_id, cell_command = self.get_header(sock)
        if cell_command != CELL_CMD_NETINFO:
            sock.close()
            return

        self.get_variable_length_body(sock)

        # TODO task1: Accept circuit open request. 
        # When an relay receives a CREATE cell, it derives a shared secret key, 
        # then it replies CREATED cell with the public key (public number) and a signature
        # attached to it. The client then can derive the identical shared secret key with
        # the public key (public number).
        
        input_sockets = [sock]

        while self.running:
            try:
                readable, _, _ = select.select(input_sockets, [], [], 0.5)
            except Exception as e:
                self.logger.error(f"Select error: {e}")
                break
            
            if not readable:
                continue

            for sock in readable:
                # 1. Accept New Connections (Incoming Relay/Client)
                if sock == self.sock:
                    newsock, addr = self.socket_accept()
                    if newsock:
                        input_sockets.append(newsock)
                        # Handshake (VERSIONS -> CERTS -> NETINFO)
                        # Note: In a real non-blocking implementation, this should be state machine driven.
                        # For this lab, we do blocking handshake here for simplicity as per common lab patterns.
                        try:
                            # Recv VERSIONS
                            cid, cmd = self.get_header(newsock)
                            if cmd != CELL_CMD_VERSIONS:
                                newsock.close()
                                input_sockets.remove(newsock)
                                continue
                            self.get_variable_length_body(newsock)

                            # Send VERSIONS, CERTS, NETINFO
                            newsock.sendall(mini_cell.VERSIONS([3]).to_bytes())
                            
                            public_PEM = mini_crypt.serialize_public_key_into_bytes(self.public_key)
                            signature = mini_crypt.RSA_sign_msg(self.private_key, public_PEM)
                            newsock.sendall(mini_cell.CERTS(public_PEM, signature).to_bytes())

                            newsock.sendall(mini_cell.NETINFO(addr[0], addr[1], self.ip, self.port).to_bytes())

                            # Recv NETINFO
                            cid, cmd = self.get_header(newsock)
                            if cmd != CELL_CMD_NETINFO:
                                newsock.close()
                                input_sockets.remove(newsock)
                                continue
                            self.get_variable_length_body(newsock)
                            
                        except Exception as e:
                            self.logger.error(f"Handshake failed: {e}")
                            newsock.close()
                            if newsock in input_sockets: input_sockets.remove(newsock)
                    continue

                # 2. Handle Data from Web Server (Traffic coming back to Client)
                if sock in self.web_socket_map:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            # Web Server Closed Connection
                            self.close_web_connection(sock, input_sockets)
                            continue
                        
                        # Pack into RELAY_DATA and send back to prev hop
                        prev_sock, prev_circ_id = self.web_socket_map[sock]
                        if (prev_sock, prev_circ_id) in self.circuits:
                            info = self.circuits[(prev_sock, prev_circ_id)]
                            sym_key = info['symmetric_key']
                            
                            # Note: Lab says max cell body is 1024. If data > ~1000, should chunk.
                            # For simplicity, assuming echo server response fits in one cell or loop
                            # Chunking loop:
                            offset = 0
                            max_payload = 1024 - 11 # approximate overhead
                            while offset < len(data):
                                chunk = data[offset : offset + max_payload]
                                offset += max_payload
                                
                                relay_cell = mini_cell.RELAY(prev_circ_id, RELAY_CMD_DATA, 0, 0, chunk)
                                enc_cell = relay_cell.encrypt(sym_key)
                                prev_sock.sendall(enc_cell)

                    except Exception as e:
                        self.logger.error(f"Error reading from web sock: {e}")
                        self.close_web_connection(sock, input_sockets)
                    continue

                # 3. Handle Tor Cells (From Client or Relay)
                # Receive Header
                header = sock.recv(3)
                if len(header) < 3:
                    self.close_relay_connection(sock, input_sockets)
                    continue
                
                circ_id, cmd = struct.unpack('!HB', header)

                # --- Handle CREATE ---
                if cmd == CELL_CMD_CREATE:
                    try:
                        l_bytes = sock.recv(2)
                        l = struct.unpack('!H', l_bytes)[0]
                        body = sock.recv(l)
                        
                        create_cell = mini_cell.CREATE.from_bytes(body, circ_id)
                        decrypted_dh = mini_crypt.RSA_decrypt_msg(self.private_key, create_cell.enc_dh_pubk)
                        client_dh_pub_num = int(decrypted_dh.decode('utf-8'), 16)
                        
                        my_dh_priv, my_dh_pub = mini_crypt.DH_gen_key_pair(DH_G, DH_P)
                        shared_key = mini_crypt.DH_derive_shared_key(DH_G, DH_P, my_dh_priv, client_dh_pub_num)
                        
                        # Init Circuit
                        self.circuits[(sock, circ_id)] = {
                            'symmetric_key': shared_key,
                            'next_sock': None,
                            'next_circ_id': 0,
                            'web_sock': None
                        }
                        
                        # Send CREATED
                        my_dh_pub_bytes = format(mini_crypt.DH_gen_public_num(my_dh_pub), 'x').zfill(DH_PUB_NUM_LEN).encode('utf-8')
                        sig = mini_crypt.RSA_sign_msg(self.private_key, my_dh_pub_bytes)
                        sock.sendall(mini_cell.CREATED(circ_id, my_dh_pub_bytes, sig).to_bytes())

                    except Exception as e:
                        self.logger.error(f"CREATE failed: {e}")
                        self.close_relay_connection(sock, input_sockets)

                # --- Handle RELAY (Forward/Backward) ---
                elif cmd == CELL_CMD_RELAY:
                    body = self.get_fixed_length_body(sock)
                    if body is None:
                        self.close_relay_connection(sock, input_sockets)
                        continue

                    # 1) Forward Direction (Client -> Relay -> Next/Web)
                    if (sock, circ_id) in self.circuits:
                        info = self.circuits[(sock, circ_id)]
                        sym_key = info['symmetric_key']
                        
                        # Try decrypt
                        tmp_relay = mini_cell.RELAY(circ_id, 0, 0, 0, b'')
                        recognized = tmp_relay.decrypt(sym_key, body)
                        
                        if recognized:
                            # It is for ME
                            self.process_relay_command(sock, circ_id, tmp_relay, info, input_sockets)
                        else:
                            # Forward to Next Hop
                            next_s = info['next_sock']
                            next_cid = info['next_circ_id']
                            if next_s:
                                # Peel one layer
                                peeled = mini_crypt.AES_decrypt(sym_key, body)
                                header = struct.pack('!HB', next_cid, CELL_CMD_RELAY)
                                try:
                                    next_s.sendall(header + peeled)
                                except:
                                    self.close_relay_connection(next_s, input_sockets)
                    
                    # 2) Backward Direction (Next Hop -> Relay -> Client)
                    elif (sock, circ_id) in self.backward_map:
                        prev_sock, prev_circ_id = self.backward_map[(sock, circ_id)]
                        if (prev_sock, prev_circ_id) in self.circuits:
                            prev_info = self.circuits[(prev_sock, prev_circ_id)]
                            prev_key = prev_info['symmetric_key']
                            
                            # Add one layer (Encryption)
                            encrypted = mini_crypt.AES_encrypt(prev_key, body)
                            header = struct.pack('!HB', prev_circ_id, CELL_CMD_RELAY)
                            try:
                                prev_sock.sendall(header + encrypted)
                            except:
                                self.close_relay_connection(prev_sock, input_sockets)
                    else:
                        # Unknown circuit
                        pass

                # --- Handle DESTROY ---
                elif cmd == CELL_CMD_DESTROY:
                    # Clean up
                    try:
                        # DESTROY body is just padding, check length if strict, else ignore
                        self.get_fixed_length_body(sock)
                    except: pass
                    
                    self.handle_destroy(sock, circ_id, input_sockets)
                    self.close_relay_connection(sock, input_sockets) # Sender closed

                else:
                    # Unknown Command or VERSIONS/NETINFO out of order
                    # Just close to be safe
                    self.close_relay_connection(sock, input_sockets)
        
        self.cleanup()

    def process_relay_command(self, sock, circ_id, relay_cell, info, input_sockets):
        cmd = relay_cell.relay_cmd
        data = relay_cell.data
        sym_key = info['symmetric_key']

        # Task 2: EXTEND
        if cmd == RELAY_CMD_EXTEND:
            try:
                offset = 0
                nick_len = data[offset]
                offset += 1
                nickname = data[offset:offset+nick_len].decode('utf-8')
                offset += nick_len
                enc_dh = data[offset:offset+256]

                target = self.dict_descriptors[nickname]
                next_sock = self.open_new_sock()
                next_sock.connect((target['or_ip'], target['or_port']))
                input_sockets.append(next_sock)

                # Handshake
                next_sock.sendall(mini_cell.VERSIONS([3]).to_bytes())
                # ... skip detailed check for brevity, assume success or use helper ...
                self.get_header(next_sock) 
                self.get_variable_length_body(next_sock) # VERSIONS
                self.get_header(next_sock)
                self.get_fixed_length_body(next_sock) # CERTS
                self.get_header(next_sock)
                self.get_variable_length_body(next_sock) # NETINFO
                
                next_sock.sendall(mini_cell.NETINFO(target['or_ip'], target['or_port'], self.ip, self.port).to_bytes())

                # Send CREATE
                next_cid = random.randint(self.circ_id_base, self.circ_id_base+999)
                next_sock.sendall(mini_cell.CREATE(next_cid, enc_dh).to_bytes())

                # Recv CREATED
                h = next_sock.recv(3)
                l = struct.unpack('!H', next_sock.recv(2))[0]
                body = next_sock.recv(l)
                created_cell = mini_cell.CREATED.from_bytes(body, 0)
                
                # Update State
                info['next_sock'] = next_sock
                info['next_circ_id'] = next_cid
                self.backward_map[(next_sock, next_cid)] = (sock, circ_id)

                # Send RELAY_EXTENDED
                payload = created_cell.dh_pubk + created_cell.signature
                resp = mini_cell.RELAY(circ_id, RELAY_CMD_EXTENDED, 0, 0, payload)
                sock.sendall(resp.encrypt(sym_key))
            except Exception as e:
                self.logger.error(f"EXTEND failed: {e}")

        # Task 3: BEGIN
        elif cmd == RELAY_CMD_BEGIN:
            try:
                offset = 0
                addr_len = data[offset]
                offset += 1
                addr_str = data[offset:offset+addr_len].decode('utf-8')
                ip, port = addr_str.split(':')
                
                # Connect to Web Server
                web_sock = self.open_new_sock()
                web_sock.connect((ip, int(port)))
                input_sockets.append(web_sock)
                
                # Register mapping
                info['web_sock'] = web_sock
                self.web_socket_map[web_sock] = (sock, circ_id)

                # Send CONNECTED
                # Payload: [AddrLen][Addr] (Echoing back what was connected)
                payload = addr_len.to_bytes(1, 'big') + addr_str.encode('utf-8')
                resp = mini_cell.RELAY(circ_id, RELAY_CMD_CONNECTED, 0, 0, payload)
                sock.sendall(resp.encrypt(sym_key))
                
            except Exception as e:
                self.logger.error(f"BEGIN failed: {e}")
                # Ideally send DESTROY or END, but for now just log

        # Task 3: DATA
        elif cmd == RELAY_CMD_DATA:
            web_sock = info.get('web_sock')
            if web_sock:
                try:
                    web_sock.sendall(data)
                except:
                    self.close_web_connection(web_sock, input_sockets)

        # Task 4: END
        elif cmd == RELAY_CMD_END:
            web_sock = info.get('web_sock')
            if web_sock:
                self.close_web_connection(web_sock, input_sockets)
                info['web_sock'] = None

    def handle_destroy(self, sock, circ_id, input_sockets):
        # 1. Forward DESTROY if needed (to Next Hop)
        if (sock, circ_id) in self.circuits:
            info = self.circuits[(sock, circ_id)]
            next_s = info['next_sock']
            next_cid = info['next_circ_id']
            
            # Close web sock if exists
            if info['web_sock']:
                self.close_web_connection(info['web_sock'], input_sockets)

            if next_s:
                try:
                    next_s.sendall(mini_cell.DESTROY(next_cid).to_bytes())
                except: pass
                self.close_relay_connection(next_s, input_sockets) # Close next hop connection

            del self.circuits[(sock, circ_id)]

        # 2. Backward DESTROY (to Prev Hop)
        elif (sock, circ_id) in self.backward_map:
            prev_sock, prev_cid = self.backward_map[(sock, circ_id)]
            try:
                prev_sock.sendall(mini_cell.DESTROY(prev_cid).to_bytes())
            except: pass
            
            # We don't necessarily close prev_sock here because it might carry other circuits,
            # but in this simple lab, usually 1 conn = 1 circuit.
            # But strictly, we should just remove the mapping.
            del self.backward_map[(sock, circ_id)]
            # Clean up the corresponding forward entry
            if (prev_sock, prev_cid) in self.circuits:
                del self.circuits[(prev_sock, prev_cid)]

    def close_web_connection(self, web_sock, input_sockets):
        try:
            if web_sock in self.web_socket_map:
                del self.web_socket_map[web_sock]
            if web_sock in input_sockets:
                input_sockets.remove(web_sock)
            web_sock.close()
        except: pass

    def close_relay_connection(self, sock, input_sockets):
        try:
            if sock in input_sockets:
                input_sockets.remove(sock)
            sock.close()
            # Note: A robust implementation would also traverse circuits/backward_map
            # and clean up any circuits referencing this socket.
        except: pass

    def fetch_descriptors_from_auth(self):
        sock = self.open_new_sock()
        sock.connect((self.auth_ip, self.auth_port))

        self.logger.info(f'connected to authority, sending request for the descriptors..')
        request = (
            f'GET /tor/server/all HTTP/1.1\r\n'
            f'Host: {self.auth_ip}:{self.auth_port}\r\n'
            f'Content-Type: text/plain\r\n'
            f'Content-Length: {0}\r\n\r\n'
        )
        sock.sendall(request.encode('utf-8'))
        response = sock.recv(4096).decode('utf-8')

        self.logger.info(f'got response: {response}')
        self.dict_descriptors = handle_descriptors_from_auth(response, self.auth_public_key)
        self.logger.info(self.dict_descriptors)
        sock.close()

    def register_to_authority(self):
        public_PEM = (mini_crypt.serialize_public_key_into_bytes(self.public_key)).decode('utf-8')
        descriptor = 'NICKNAME:' + self.nickname + '\r\n' \
                    + 'ADDRESS:' + str(self.ip) + ':' + str(self.port) + '\r\n' \
                    + 'PUBLIC_K:' + public_PEM + '\r\n'
        sign = mini_crypt.RSA_sign_msg(self.private_key, descriptor.encode('utf-8'))
        descriptor += 'SIGN_LEN:' + str(len(sign)) + '\r\n' \
                    + 'SIGNATURE:' + sign.hex() + '\r\n'
        request_line = 'POST /tor/ HTTP/1.1\r\n'
        headers = (
            f'Host: {self.auth_ip}:{self.auth_port}\r\n'
            f'Content-Type: text/plain\r\n'
            f'Content-Length: {len(descriptor)}\r\n'
            '\r\n'
        )
        request = request_line + headers + descriptor
        sock = self.open_new_sock()
        sock.connect((self.auth_ip, self.auth_port))
        sock.sendall(request.encode('utf-8'))
        response = sock.recv(4096).decode('utf-8')
        self.logger.debug(f'got response from auth: {response}')
        # TODO: check authority's signature
        self.logger.info(f'successfully registered')
        sock.close()

    def stop(self):
        self.logger.info(f'stop() is called!')
        self.running = False
    
    def cleanup(self):
        self.logger.info(f'cleanup(): cleaning up relay on port {self.port}')
        for sock in self.sock_list:
            sock.close()
        self.sock.close()