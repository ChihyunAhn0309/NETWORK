from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DH_PUB_NUM_LEN = 128
# Generates private key from bytes fo private key written in PEM format.
# private_key_in_bytes should be the bytes read from the PEM file.
def deserialize_private_key_from_bytes(private_key_in_bytes:bytes):
    private_key = serialization.load_ssh_private_key(
        private_key_in_bytes, 
        password = None,
    )
    return private_key

# Generate bytes of private key in PEM format.
def serialize_private_key_into_bytes(private_key:RSAPrivateKey):
    private_key_in_bytes = private_key.private_bytes(
        serialization.Encoding.PEM, 
        serialization.PrivateFormat.OpenSSH, 
        serialization.NoEncryption(),
    )
    return private_key_in_bytes

# Generates public key from bytes of private key written in PEM format.
# public_key_in_bytes should be the bytes read from the PEM file.
def deserialize_public_key_from_bytes(public_key_in_bytes:bytes):
    public_key = serialization.load_ssh_public_key(public_key_in_bytes)
    return public_key

# Generate bytes of public key in PEM format.
def serialize_public_key_into_bytes(public_key:RSAPublicKey):
    public_key_in_bytes = public_key.public_bytes(
        serialization.Encoding.OpenSSH, 
        serialization.PublicFormat.OpenSSH,
    )
    return public_key_in_bytes

# Signs the message with the given private_key.
def RSA_sign_msg(private_key:RSAPrivateKey, message:bytes):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature

# Verifies the signature with the message and the public_key.
def RSA_verify_sign(public_key:RSAPublicKey, message:bytes, signature:bytes):
    try:
        public_key.verify(
            signature, 
            message,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except:
        raise Exception('mini_crypt::RSA_verify_sign(): Incorrect signature')

# Encryptes the message with the public_key.
def RSA_encrypt_msg(public_key:RSAPublicKey, message:bytes):
    cipher_text = public_key.encrypt(
        message,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None,
        )
    )
    return cipher_text

# Decryptes the message with the private_key.
def RSA_decrypt_msg(private_key:RSAPrivateKey, cipher_text:bytes):
    try:
        message = private_key.decrypt(
            cipher_text, 
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None,
            ),
        )
        return message
    except:
        raise Exception('mini_crypt::RSA_decrypt_msg(): Cannot decrypt message!')

def DH_gen_key_pair(g:int, p:int):
    parameters = dh.DHParameterNumbers(p, g).parameters()

    dh_priv_k = parameters.generate_private_key()
    dh_pub_k = dh_priv_k.public_key()
    return dh_priv_k, dh_pub_k

def DH_gen_public_num(dh_pub_k:dh.DHPublicKey):
    return dh_pub_k.public_numbers().y

def DH_derive_shared_key(g:int, p:int, dh_priv_k:dh.DHPrivateKey, public_num:int):
    peer_pub_info = dh.DHPublicNumbers(public_num, dh.DHParameterNumbers(p, g))
    peer_pub_k = peer_pub_info.public_key()
    shared_secrete = dh_priv_k.exchange(peer_pub_k)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(shared_secrete)
    return derived_key

def AES_encrypt(derived_key, message:bytes, iv=b'\0'*16):
    encryptor = Cipher(
        algorithm=algorithms.AES(derived_key),
        mode=modes.CTR(iv),
    ).encryptor()
    return encryptor.update(message) + encryptor.finalize()

def AES_decrypt(derived_key, ciphertext, iv=b'\0'*16):
    decryptor = Cipher(
        algorithm=algorithms.AES(derived_key),
        mode=modes.CTR(iv),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
    

# Usage example
def main():
    private_key_path = 'data/Auth/keys/Authority'
    public_key_path = 'data/Auth/keys/Authority.pub'

    # Read bytes from files, and load keys from bytes
    private_key_in_bytes = b''
    with open(private_key_path, 'rb') as key_file:
        for line in key_file: private_key_in_bytes += line
    private_key = deserialize_private_key_from_bytes(private_key_in_bytes)

    public_key_in_bytes = b''
    with open(public_key_path, 'rb') as key_file:
        for line in key_file: public_key_in_bytes += line
    public_key = deserialize_public_key_from_bytes(public_key_in_bytes)


    # Write keys to bytes.
    serialized_private_key = serialize_private_key_into_bytes(private_key)
    print('private key in bytes: ')
    print(serialized_private_key)
    print()

    serialized_public_key = serialize_public_key_into_bytes(public_key)
    print('public key in bytes: ')
    print(serialized_public_key)
    print()

    # Sign the message with private key.
    message = b'this is a signed message'
    signature = RSA_sign_msg(private_key, message)
    print(f'Signature: {signature}')
    print()

    # Verify the signature with the public key.
    try: is_valid = RSA_verify_sign(public_key, message, signature)
    except: is_valid = False
    print(f'Verifying the authentic signature with the authentic message...')
    print(f'Signature valid: {is_valid}')
    print()

    # Verify the signature with the public key. 
    # Note that the message is modified.
    modified_message = bytearray(message)
    modified_message[0] = 0
    try: is_valid = RSA_verify_sign(public_key, modified_message, signature)
    except: is_valid = False
    print(f'Verifying the authentic signature with the modified messag...')
    print(f'Signature valid: {is_valid}')
    print()

    # Verify the signature with the public key. 
    # Note that the signature is modified.
    modified_signature = bytearray(signature)
    modified_signature[0] = 0
    try: is_valid = RSA_verify_sign(public_key, message, modified_signature)
    except: is_valid = False
    print(f'Verifying the modified signature with the authentic message...')
    print(f'Signature valid: {is_valid}')
    print()

    # Encrypt the message with the public key.
    message = b'this is a secret message'
    message = b'a' * 128
    cipher_text = RSA_encrypt_msg(public_key, message)
    print(f'Cipher text: {cipher_text}')
    print()

    # Decrypt the cipher text with the private key.
    try:
        message = RSA_decrypt_msg(private_key, cipher_text)
        print(f'Original message: {message}')
        print()
    except Exception as e: print(f'{e}\n')

    # Decrypt the cipher text with the private key. 
    # Note that the cipher text is modified.
    modified_cipher_text = bytearray(cipher_text)
    modified_cipher_text[0] = 0
    try:
        message = RSA_decrypt_msg(private_key, bytes(modified_cipher_text))
        print(f'Original message: {message}')
        print()
    except Exception as e: print(f'{e}\n')

    # We will use the same g and p throughout this lab.
    # Diffie Hellman key exchange
    g = 2
    p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" 
           "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 
           16)
    # DH generate key pair
    peer1_private_key, peer1_public_key = DH_gen_key_pair(g, p)
    peer1_public_num = DH_gen_public_num(peer1_public_key)
    peer2_private_key, peer2_public_key = DH_gen_key_pair(g, p)
    peer2_public_num = DH_gen_public_num(peer2_public_key)

    print('public key in int:')
    print(peer1_public_num)
    print(format(peer1_public_num, 'x'))
    print(format(peer1_public_num, 'x').zfill(DH_PUB_NUM_LEN))
    print()

    # DH derived shared key
    peer1_derived_key = DH_derive_shared_key(g, p, peer1_private_key, peer2_public_num)
    peer2_derived_key = DH_derive_shared_key(g, p, peer2_private_key, peer1_public_num)
    print('DH derived keys:')
    print(peer1_derived_key.hex())
    print(peer2_derived_key.hex())
    print()

    # One interesting fact: since, AES uses symmetric key, 
    # encrypt() and decrypt() are interchangable.
    # AES encryption
    message = b'this is a secret message'
    ct = AES_encrypt(peer1_derived_key, message)
    print('AES cipher text:')
    print(ct)
    print()

    # AES decryption
    recovered_message = AES_decrypt(peer2_derived_key, ct)
    print('AES original message:')
    print(recovered_message)
    print()


if __name__ == '__main__':
    main()