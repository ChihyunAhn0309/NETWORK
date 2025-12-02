import struct
from zlib import crc32
import mini_crypt

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

CELL_FIXED_BODY_LEN = 1024
RSA2048_SIGN_LEN = 256
DH_G = 2
DH_P = int("BC6E230F63512CB36605599417DE96B6DE189B93E63250EFAF457462533D8EBB"
           "EF362F478BDBDAEB4E0726F4102F54F6B58CB70C5257A829456D981A2E5FCD7B",
           16)
DH_PUB_NUM_LEN = 128


class VERSIONS:
    def __init__(self, versions_list):
        self.circ_id = 0
        self.command = CELL_CMD_VERSIONS
        self.versions_list = versions_list

    def from_bytes(cell_body:bytes, cell_body_len:int):
        if cell_body_len % 2 != 0: 
            raise Exception(f'VERSIONS cell length(={cell_body_len}) is not multiples of 2')
        versions_list = []
        for i in range(0, cell_body_len, 2):
            versions_list.append(int.from_bytes(cell_body[i:i+2], byteorder='big'))
        return VERSIONS(versions_list)

    def to_bytes(self) -> bytes:
        cell_body = b''
        for version in self.versions_list:
            cell_body += (version).to_bytes(2, byteorder='big')
        cell_len = len(cell_body)
        header = struct.pack('!HBH', self.circ_id, self.command, cell_len)
        return header + cell_body

class CERTS: 
    def __init__(self, PEM: bytes, Signature: bytes):
        self.circ_id = 0
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        self.command = CELL_CMD_CERTS
        self.pem = PEM
        self.signature = Signature

    def from_bytes(cell:bytes):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        PEM = cell[:380].rstrip(b'\x00')
        Signature = cell[380:380+256]
        return CERTS(PEM, Signature)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        if len(self.pem) > 380:
            exact_pem = self.pem[:380].ljust(380, b'\x00')
        else:
            exact_pem = self.pem.ljust(380, b'\x00')
        exact_signature = self.signature[:256].ljust(256, b'\x00')
        padding = b'\x00' * (CELL_FIXED_BODY_LEN - 380 - 256)

        exact_body = exact_pem + exact_signature + padding
        header = struct.pack("!HB", self.circ_id, self.command)
        return header + exact_body

class NETINFO:
    def __init__(self, peer_ip: str, peer_port: int, my_ip: str, my_port: int):
        self.circ_id = 0
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        self.command = CELL_CMD_NETINFO
        self.peer_addr = f"{peer_ip}:{peer_port}"
        self.my_addr = f"{my_ip}:{my_port}"

    def from_bytes(cell:bytes):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        offset = 0
        peer_addr_len = cell[offset]
        offset = offset + 1
        peer_addr = cell[offset : offset + peer_addr_len].decode('utf-8')
        offset = offset + peer_addr_len
        my_addr_len = cell[offset]
        offset = offset + 1
        my_addr = cell[offset : offset + my_addr_len].decode('utf-8')

        peer_ip, peer_port = peer_addr.split(':')
        my_ip, my_port = my_addr.split(':')
        return NETINFO(peer_ip, int(peer_port), my_ip, int(my_port))


    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        peer_addr_bytes = self.peer_addr.encode('utf-8')
        my_addr_bytes = self.my_addr.encode('utf-8')

        body = b''
        body += len(peer_addr_bytes).to_bytes(1, 'big')
        body += peer_addr_bytes
        body += len(my_addr_bytes).to_bytes(1, 'big')
        body += my_addr_bytes

        body_len = len(body)
        header = struct.pack('!HBH', self.circ_id, self.command, body_len)
        return header + body



class CREATE:
    def __init__(self, circ_id, enc_dh_pubk: bytes):
        self.circ_id = circ_id
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        self.command = CELL_CMD_CREATE
        self.enc_dh_pubk = enc_dh_pubk

    def from_bytes(cell:bytes, circ_id):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        return CREATE(circ_id, cell)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        length = len(self.enc_dh_pubk)
        header = struct.pack('!HBH', self.circ_id, self.command, length)
        return header + self.enc_dh_pubk

class CREATED:
    def __init__(self, circ_id, dh_pubk: bytes, signature:bytes):
        self.circ_id = circ_id
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        self.command = CELL_CMD_CREATED
        self.dh_pubk = dh_pubk
        self.signature = signature

    def from_bytes(cell:bytes, circ_id):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        dh_pubk = cell[:DH_PUB_NUM_LEN]
        signature = cell[DH_PUB_NUM_LEN:DH_PUB_NUM_LEN+RSA2048_SIGN_LEN]
        return CREATED(circ_id, dh_pubk, signature)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        body = self.dh_pubk + self.signature
        length = len(body)
        header = struct.pack('!HBH', self.circ_id, self.command, length)
        return header + body

class RELAY:
    def __init__(self, circ_id, relay_cmd, recognized, digest, data):
        self.circ_id = circ_id
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        self.command = CELL_CMD_RELAY
        self.relay_cmd = relay_cmd
        self.recognized = recognized
        self.digest = digest
        self.data = data
        
    def from_bytes(cell:bytes):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        relay_cmd = cell[0]
        recognized = int.from_bytes(cell[1:3], 'big')
        digest = int.from_bytes(cell[3:7], 'big')
        data_len = int.from_bytes(cell[7:9], 'big')
        data = cell[9:9+data_len]
        return RELAY(circ_id, relay_cmd, recognized, digest, data)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        relay_header = struct.pack('!BHIH', self.relay_cmd, self.recognized, self.digest, len(self.data))
        padding_len = CELL_FIXED_BODY_LEN - 9 - len(self.data)
        padding = b'\x00' * padding_len
        body = relay_header + self.data + padding

        header = struct.pack('!HB', self.circ_id, self.command)
        return header + body
    
    # use crc32() checksum to calculate the digest. 
    # e.g., self.digest = crc32(self.body)
    def update_digest(self):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        relay_header = struct.pack('!BHIH', self.relay_cmd, 0, 0, len(self.data))
        padding_len = CELL_FIXED_BODY_LEN - 9 - len(self.data)
        padding = b'\x00' * padding_len
        tmp_body = relay_header + self.data + padding
        self.digest = crc32(tmp_body)

    # Should first update the digest, then encrypt the cell with shared secret key
    def encrypt(self, sym_key):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        self.update_digest()

        full_cell = self.to_bytes()
        current_bytes = full_cell[3:]
        encrypted_body = mini_crypt.AES_encrypt(sym_key, current_bytes)

        return full_cell[:3] + encrypted_body
        
    # Should first decrypt the cell with shared secret key, then check the digest
    def decrypt(self, sym_key, raw_body_bytes):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        decrypted_body = mini_crypt.AES_decrypt(sym_key, raw_body_bytes)

        self.relay_cmd = decrypted_body[0]
        self.recognized = int.from_bytes(decrypted_body[1:3], 'big')
        self.digest = int.from_bytes(decrypted_body[3:7], 'big')
        data_len = int.from_bytes(decrypted_body[7:9], 'big')
        self.data = decrypted_body[9:9+data_len]
        
        tmp_body = decrypted_body[0:3] + b'\x00\x00\x00\x00' + decrypted_body[7:]
        calculated_digest = crc32(tmp_body)

        if self.recognized == 0 and calculated_digest == self.digest:
            return True
        else:
            return False


class DESTROY:
    def __init__(self, circ_id):
        self.circ_id = circ_id
        self.command = CELL_CMD_DESTROY
        self.data = b''.ljust(CELL_FIXED_BODY_LEN, b'\x00')

    def to_bytes(self) -> bytes:
        header = struct.pack('!HB', self.circ_id, self.command)
        return header + self.data

if __name__ == '__main__':
    print('You may test your codes here. This method will not be graded.')
    print('You may also add other classes and new methods for the existing classes.')