import struct
import threading
import socket
import logging
import select
import mini_crypt
import mini_cell
from os.path import join

MAX_INCOMING_CONNECTION = 5
VERSIONS_BODY = 3

CIRCID_LEN = 2
COMMAND_LEN = 1
CELL_LENGTH = 2
CELL_BODY_LEN = 1024


CREATE_CELL = 1
CREATED_CELL = 2
RELAY_CELL = 3
DESTROY_CELL = 4
VERSIONS_CELL = 7
NETINFO_CELL = 8
CERTS_CELL = 129

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
        raise Exception('verify_or_descriptor(): OR\'s signature is invalid')
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

class Onion_client(threading.Thread):
    def __init__(
            self, 
            ip,
            auth_ip,
            auth_port,
            nickname,
            web_server_ip,
            web_server_port,
            circ_id,
            circuit_or_names = None,
            auth_public_key_path = 'Authority.pub',
    ):
        super().__init__()
        self.ip = ip
        self.running = True
        self.auth_ip = auth_ip
        self.auth_port = auth_port
        self.nickname = nickname
        self.circ_id = circ_id

        self.dict_descriptors = {}
        self.circuit = []
        self.sock = None
        self.web_server_ip = web_server_ip
        self.web_server_port = web_server_port
        self.circuit_or_names = circuit_or_names
        self.setup_logger()

        self.logger.info(f'\n\n\n\nstarting new run! initialize...')
        keys_dir = join(join('data', nickname), 'keys')
        self.public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(join(keys_dir, nickname+'.pub')))
        self.private_key = mini_crypt.deserialize_private_key_from_bytes(read_PEM_file(join(keys_dir, nickname)))
        self.auth_public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(join(keys_dir, auth_public_key_path)))

    def setup_logger(self):
        home_dir = join('data', self.nickname)
        filename = join(home_dir, self.nickname+'.log')
        self.logger = logging.getLogger(self.nickname)
        handler = logging.FileHandler(filename)
        fmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(fmtr)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    def open_new_sock(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # This is not necessary when we are opening the socket in the real world, 
        # but this is here only to demonstrate the anonymization of ip addresses.
        sock.bind((self.ip, 0))
        return sock

    def run(self):
        self.logger.info(f'entered run(), now start running')
        self.fetch_descriptors_from_auth()

        if self.circuit_or_names != None:
            self.constitute_circuit_path(self.circuit_or_names)
        else: return
        # the method for task1
        print("TASK start!!!!!!!")
        self.connect_to_first_router()
        print("Task1 fin")
        # the method for task2:
        self.extend_circuit()
        print("Task2 fin")
        # the method for task3:
        self.connect_to_web_server_via_circuit()
        print("Task3 fin")
        # the method for task4:
        self.end_connection_to_web_server()
        self.destroy_circuit()
        print("Task4 fin")
        self.cleanup()
        return

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
    
    def constitute_circuit_path(self, circuit_or_names):
        for or_name in circuit_or_names:
            or_ip = self.dict_descriptors[or_name]['or_ip']
            or_port = self.dict_descriptors[or_name]['or_port']
            or_pubk = self.dict_descriptors[or_name]['or_pubk']
            self.circuit.append({
                'or_name': or_name,
                'or_ip': or_ip,
                'or_port': or_port,
                'or_pubk': or_pubk,
                'DH_private_key': None,
                'symmetric_key': None,
            })

    def connect_to_first_router(self):
        # Open socket to the first relay of the circuit
        self.sock = self.open_new_sock()
        #TODO task1: Open channel to the first hop. Send VERSIONS cell and receive 
        # VERSIONS, CERTS, and NETINFO cell. Send NETINFO cell to finish handshake.
        first_or = self.circuit[0]
        self.sock.connect((first_or['or_ip'], first_or['or_port']))
        
        versions_cell = mini_cell.VERSIONS([3])
        self.sock.sendall(versions_cell.to_bytes())

        header = self.sock.recv(CIRCID_LEN + COMMAND_LEN)
        _, cmd = struct.unpack('!HB', header)
        if cmd != VERSIONS_CELL:
            raise Exception("Not VERSIONS cell")
        vbody_len_content = self.sock.recv(CELL_LENGTH)
        vbody_len = struct.unpack('!H', vbody_len_content)[0]
        self.sock.recv(vbody_len)
        
        header = self.sock.recv(CIRCID_LEN + COMMAND_LEN)
        _, cmd = struct.unpack('!HB', header)
        if cmd != CERTS_CELL:
            raise Exception("Not VERSIONS cell")
        certs_body_bytes = self.sock.recv(CELL_BODY_LEN)
        certs_body = mini_cell.CERTS.from_bytes(certs_body_bytes)

        rec_pubk = mini_crypt.deserialize_public_key_from_bytes(certs_body.pem)
        if not mini_crypt.RSA_verify_sign(rec_pubk, certs_body.pem.rstrip(b'\x00'), certs_body.signature):
            raise Exception("certs_cell_signature fail")
        
        expected_pubk = first_or['or_pubk']
        expected_pubk_bytes = mini_crypt.serialize_public_key_into_bytes(first_or['or_pubk'])
        received_pubk_bytes = certs_body.pem[:len(expected_pubk_bytes)]
        if expected_pubk_bytes != received_pubk_bytes:
            raise Exception("not expected public key")

        header = self.sock.recv(CIRCID_LEN + COMMAND_LEN)
        _, cmd = struct.unpack('!HB', header)
        if cmd != NETINFO_CELL:
            raise Exception("Not VERSIONS cell")
        nbody_len_content = self.sock.recv(CELL_LENGTH)
        nbody_len = struct.unpack('!H', nbody_len_content)[0]
        net_body_bytes = self.sock.recv(nbody_len)
        net_body = mini_cell.NETINFO.from_bytes(net_body_bytes)

        received_or_ip = net_body.my_addr.split(':')[0]
        expected_or_ip = first_or['or_ip']
        if received_or_ip != expected_or_ip:
            raise Exception("onion router ip not identical")

        sending_netinfo = mini_cell.NETINFO(first_or['or_ip'], first_or['or_port'], self.ip, 0)
        self.sock.sendall(sending_netinfo.to_bytes())

        #TODO task1: Open circuit to the first hop. Send CREATE cell and receive CREATED 
        # cell to derive a shared secret key.

        client_dh_priv, client_dh_pub = mini_crypt.DH_gen_key_pair(mini_cell.DH_G, mini_cell.DH_P)
        first_or['DH_private_key'] = client_dh_priv
        
        client_dh_pub_num = mini_crypt.DH_gen_public_num(client_dh_pub)
        client_dh_pub_bytes = format(client_dh_pub_num, 'x').zfill(mini_cell.DH_PUB_NUM_LEN).encode('utf-8')
        
        enc_dh_key = mini_crypt.RSA_encrypt_msg(expected_pubk, client_dh_pub_bytes)
        create_cell = mini_cell.CREATE(self.circ_id, enc_dh_key)
        self.sock.sendall(create_cell.to_bytes())

        header = self.sock.recv(CIRCID_LEN + COMMAND_LEN + CELL_LENGTH)
        _, cmd, length = struct.unpack('!HBH', header)
        if cmd != mini_cell.CELL_CMD_CREATED:
            raise Exception("not a created cell")
        
        body = self.sock.recv(length)
        created_cell = mini_cell.CREATED.from_bytes(body, self.circ_id)

        if not mini_crypt.RSA_verify_sign(expected_pubk, created_cell.dh_pubk, created_cell.signature):
            raise Exception("CREATED signature fail")

        relay_dh_pub_num = int(created_cell.dh_pubk.decode('utf-8'), 16)
        shared_key = mini_crypt.DH_derive_shared_key(mini_cell.DH_G, mini_cell.DH_P, client_dh_priv, relay_dh_pub_num)
        first_or['symmetric_key'] = shared_key


    def extend_circuit(self):
        sock = self.sock

        # TODO task2: Extend circuit. Send RELAY cell with EXTEND command to the first 
        # relay, and let the first relay to extend the circuit. In order to do so 
        # the EXTEND-RELAY cell should have the following: 
        #   1) The next-hop relay's nickname
        #   2) The client's Diffie-Hellman public number encrypted with the next hop's 
        # public key
        # After the RELAY-EXTEND cell is generated, the client should encrypt the RELAY 
        # cell with the derived shared secret key. For example, if the client is asking 
        # second-hop relay to extend the circuit, the RELAY cell should be 
        # encrypted with the secret key shared between the first relay and the 
        # secret key shared between the second relay. 
        # Once the RELAY-EXTEND cell is sent, wait for the RELAY cell with EXTENDED 
        # command sent by the first relay. Then derive the shared secret key with 
        # the seconde relay. Repeat the process to extend the circuit to third hop.

        active_circuit_len = 1
        for i in range(1, len(self.circuit)):
            target_relay = self.circuit[i]
            prev_relay = self.circuit[i-1]

            client_dh_priv, client_dh_pub = mini_crypt.DH_gen_key_pair(mini_cell.DH_G, mini_cell.DH_P)
            client_dh_pub_num = mini_crypt.DH_gen_public_num(client_dh_pub)
            client_dh_pub_bytes = format(client_dh_pub_num, 'x').zfill(mini_cell.DH_PUB_NUM_LEN).encode('utf-8')
            enc_dh_key = mini_crypt.RSA_encrypt_msg(target_relay['or_pubk'], client_dh_pub_bytes)

            nickname = target_relay['or_name'].encode('utf-8')
            nickname_len = len(nickname).to_bytes(1, 'big')
            extend_payload = nickname_len + nickname + enc_dh_key

            relay_cell = mini_cell.RELAY(self.circ_id, mini_cell.RELAY_CMD_EXTEND, 0, 0, extend_payload)
            relay_cell.update_digest()

            cell_bytes = relay_cell.to_bytes()
            body_bytes = cell_bytes[3:]

            for j in range(active_circuit_len -1, -1, -1):
                key = self.circuit[j]['symmetric_key']
                body_bytes = mini_crypt.AES_encrypt(key, body_bytes)
            
            encrypted_cell = cell_bytes[:3] + body_bytes

            self.sock.sendall(encrypted_cell)
            header = self.sock.recv(3)
            _, cmd = struct.unpack('!HB', header)
            if cmd != mini_cell.CELL_CMD_RELAY:
                raise Exception("Not a RELAY cell")

            encrypted_body = self.sock.recv(mini_cell.CELL_FIXED_BODY_LEN)
            decrypted_body = encrypted_body
            for j in range(active_circuit_len):
                key = self.circuit[j]['symmetric_key']
                decrypted_body = mini_crypt.AES_decrypt(key, decrypted_body)

            r_cmd = decrypted_body[0]
            r_recog = int.from_bytes(decrypted_body[1:3], 'big')
            r_digest = int.from_bytes(decrypted_body[3:7], 'big')
            r_len = int.from_bytes(decrypted_body[7:9], 'big')
            r_data = decrypted_body[9:9+r_len]

            if r_cmd != mini_cell.RELAY_CMD_EXTENDED:
                raise Exception("Not relay extended")

            server_dh_pub_bytes = r_data[:mini_cell.DH_PUB_NUM_LEN]
            signature = r_data[mini_cell.DH_PUB_NUM_LEN:mini_cell.DH_PUB_NUM_LEN+mini_cell.RSA2048_SIGN_LEN]
            
            if not mini_crypt.RSA_verify_sign(target_relay['or_pubk'], server_dh_pub_bytes, signature):
                raise Exception("Invalid signature on EXTENDED cell")
            
            server_dh_pub_num = int(server_dh_pub_bytes.decode('utf-8'), 16)
            shared_key = mini_crypt.DH_derive_shared_key(mini_cell.DH_G, mini_cell.DH_P, client_dh_priv, server_dh_pub_num)
            
            target_relay['DH_private_key'] = client_dh_priv
            target_relay['symmetric_key'] = shared_key
            active_circuit_len += 1


    def connect_to_web_server_via_circuit(self):
        sock = self.sock
        # TODO task3: Reach web server via the constructed circuit. Send RELAY cell with 
        # BEGIN command to the third (last) relay. Wait for the RELAY cell with the 
        # CONNECTED command

        # [Step 1] RELAY_BEGIN 셀 생성 및 전송
        target_addr = f"{self.web_server_ip}:{self.web_server_port}"
        target_addr_bytes = target_addr.encode('utf-8')
        
        # Payload: [AddrLen(1)][AddressString]
        begin_payload = len(target_addr_bytes).to_bytes(1, 'big') + target_addr_bytes
        
        relay_cell = mini_cell.RELAY(self.circ_id, mini_cell.RELAY_CMD_BEGIN, 0, 0, begin_payload)
        relay_cell.update_digest()
        
        full_cell = relay_cell.to_bytes()
        body_bytes = full_cell[3:] # 헤더(3바이트) 제외한 바디 부분
        
        # Onion Encryption: N번 암호화 (Relay N -> ... -> Relay 1 순서로 키 사용)
        # 회로의 마지막 노드(Exit Node)의 키부터 사용하여 암호화해야 함
        for i in range(len(self.circuit) - 1, -1, -1):
            key = self.circuit[i]['symmetric_key']
            body_bytes = mini_crypt.AES_encrypt(key, body_bytes)
            
        sock.sendall(full_cell[:3] + body_bytes)
        self.logger.info("Sent RELAY_BEGIN")

        # [Step 2] RELAY_CONNECTED 셀 수신 및 복호화
        header = sock.recv(3)
        encrypted_body = sock.recv(mini_cell.CELL_FIXED_BODY_LEN)
        
        decrypted_body = encrypted_body
        # Onion Decryption: N번 복호화 (Relay 1 -> ... -> Relay N 순서로 키 사용)
        for i in range(len(self.circuit)):
            key = self.circuit[i]['symmetric_key']
            decrypted_body = mini_crypt.AES_decrypt(key, decrypted_body)
            
        r_cmd = decrypted_body[0]
        if r_cmd != mini_cell.RELAY_CMD_CONNECTED:
            raise Exception(f"Expected CONNECTED, got {r_cmd}")
        self.logger.info("Received RELAY_CONNECTED")

        # TODO task3: Send RELAY cell with DATA command. Wait for the RELAY cell with the 
        # DATA command

        # [Step 3] RELAY_DATA (HTTP Request) 전송
        # directly_connect_to_web_server 메소드에 있는 형식 참조
        body_content = 'hello from CS341!'
        http_req = (f'POST /echo HTTP/1.1\r\n' 
                    f'Host: {self.web_server_ip}:{self.web_server_port}\r\n'
                    f'Content-Type: text/plain\r\n'
                    f'Content-Length: {len(body_content)}\r\n\r\n'
                    f'{body_content}')
        
        data_payload = http_req.encode('utf-8')
        relay_cell = mini_cell.RELAY(self.circ_id, mini_cell.RELAY_CMD_DATA, 0, 0, data_payload)
        relay_cell.update_digest()
        
        full_cell = relay_cell.to_bytes()
        body_bytes = full_cell[3:]
        
        # Onion Encryption
        for i in range(len(self.circuit) - 1, -1, -1):
            key = self.circuit[i]['symmetric_key']
            body_bytes = mini_crypt.AES_encrypt(key, body_bytes)
            
        sock.sendall(full_cell[:3] + body_bytes)
        self.logger.info("Sent RELAY_DATA (Request)")

        # [Step 4] RELAY_DATA (HTTP Response) 수신
        header = sock.recv(3)
        encrypted_body = sock.recv(mini_cell.CELL_FIXED_BODY_LEN)
        
        decrypted_body = encrypted_body
        # Onion Decryption
        for i in range(len(self.circuit)):
            key = self.circuit[i]['symmetric_key']
            decrypted_body = mini_crypt.AES_decrypt(key, decrypted_body)
            
        r_cmd = decrypted_body[0]
        r_len = int.from_bytes(decrypted_body[7:9], 'big')
        r_data = decrypted_body[9:9+r_len]
        
        if r_cmd != mini_cell.RELAY_CMD_DATA:
            raise Exception(f"Expected DATA, got {r_cmd}")
            
        response_str = r_data.decode('utf-8')
        self.logger.info(f"Received RELAY_DATA (Response): {response_str}")
        print(f"Web Server Response:\n{response_str}")

    def end_connection_to_web_server(self):
        sock = self.sock
        # TODO task4: Close the connection with the web server. Send RELAY cell with END 
        # command. Does not have to wait for any reply. 
        # Payload는 Padding만 들어가므로 빈 bytes
        relay_cell = mini_cell.RELAY(self.circ_id, mini_cell.RELAY_CMD_END, 0, 0, b'')
        relay_cell.update_digest()
        
        full_cell = relay_cell.to_bytes()
        body_bytes = full_cell[3:] # 헤더 제외한 바디
        
        # Onion Encryption: Relay N(마지막) -> ... -> Relay 1(처음) 순서로 암호화
        for i in range(len(self.circuit) - 1, -1, -1):
            key = self.circuit[i]['symmetric_key']
            body_bytes = mini_crypt.AES_encrypt(key, body_bytes)
            
        # 최종 암호화된 셀 전송
        self.logger.info("Sending RELAY_END command")
        sock.sendall(full_cell[:3] + body_bytes)



    def destroy_circuit(self):
        sock = self.sock
        # TODO task4: Close the circuit. Send DESTROY cell to the first relay. Can 
        # close the socket immediately. 
        if sock:
            try:
                self.logger.info("Sending DESTROY cell")
                destroy_cell = mini_cell.DESTROY(self.circ_id)
                sock.sendall(destroy_cell.to_bytes())
            except Exception as e:
                self.logger.error(f"Error sending DESTROY: {e}")
            finally:
                self.logger.info("Closing client socket")
                sock.close()
                self.sock = None

    def directly_connect_to_web_server(self, body=None):
        sock = self.open_new_sock()
        sock.connect((self.web_server_ip, self.web_server_port))
        if body == None:
            body = 'hello from CS341!'
        header = (f'POST /echo HTTP/1.1\r\n' 
                   f'Host: {self.web_server_ip}:{self.web_server_port}\r\n'
                   f'Content-Type: text/plain\r\n'
                   f'Content-Length: {len(body)}\r\n\r\n')
        self.logger.info(f'sending payload {header+body}')
        sock.sendall((header+body).encode('utf-8'))
        response = sock.recv(4096)
        self.logger.info(f'got response from web server: {response}')
        sock.close()

    def stop(self):
        self.logger.info(f'stop() is called')
        self.running = False
        self.cleanup()

    def cleanup(self):
        self.logger.info(f'cleanup(): cleaning up client') 
        self.sock.close()