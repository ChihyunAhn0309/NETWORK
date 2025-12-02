import time
import signal
import random
from mini_relay import Relay
from mini_auth import Authority
from mini_client import Onion_client
from mini_web_server import Mini_server

AUTH_LIST = []
OR_LIST = []
CLIENT_LIST = []
WEB_SERVER_LIST = []

AUTH_IP = '127.3.4.0'
AUTH_PORT = 34100
OR1_IP = '127.3.4.1'
OR1_PORT = 34101
OR2_IP = '127.3.4.2'
OR2_PORT = 34102
OR3_IP = '127.3.4.3'
OR3_PORT = 34103
WEB_IP = '127.34.41.18'
WEB_PORT = 8080
CLIENT1_IP = '127.100.100.100'
CLIENT2_IP = '127.200.200.200'

def signal_handler(sig, frame):
    print(f'run::signal_handler: got signal {sig}')
    for auth in AUTH_LIST:
        auth.stop()
    for onion_routers in OR_LIST:
        onion_routers.stop()
    for client in CLIENT_LIST:
        client.stop()
    for web in WEB_SERVER_LIST:
        web.stop()

    for auth in AUTH_LIST:
        auth.join()
    print(f'auth joined')
    for onion_routers in OR_LIST:
        onion_routers.join()
    print(f'relays joined')
    for client in CLIENT_LIST:
        client.join()
    print(f'client joined')
    for web in WEB_SERVER_LIST:
        web.join()
    print(f'web server joined')
    exit()

def setup():
    random.seed()
    circ_id_rand_base = random.randint(1001, 5001)

    AUTH_LIST.append(Authority(
        ip = AUTH_IP,
        port = AUTH_PORT,
        nickname = 'Auth',
    ))

    OR_LIST.append(Relay(
        ip = OR1_IP,
        port = OR1_PORT, 
        auth_ip = AUTH_IP,
        auth_port = AUTH_PORT, 
        nickname = 'OnionRouter1',
        circ_id_base = circ_id_rand_base,
    ))
    OR_LIST.append(Relay(
        ip = OR2_IP,
        port = OR2_PORT,
        auth_ip = AUTH_IP,
        auth_port = AUTH_PORT,
        nickname = 'OnionRouter2',
        circ_id_base = circ_id_rand_base + 1000,
    ))
    OR_LIST.append(Relay(
        ip = OR3_IP,
        port = OR3_PORT,
        auth_ip = AUTH_IP,
        auth_port = AUTH_PORT,
        nickname = 'OnionRouter3',
        circ_id_base = circ_id_rand_base + 2000,
    ))

    CLIENT_LIST.append(Onion_client(
        ip = CLIENT1_IP,
        auth_ip = AUTH_IP,
        auth_port = AUTH_PORT,
        nickname = 'Client1',
        web_server_ip = WEB_IP,
        web_server_port = WEB_PORT,
        circuit_or_names = ['OnionRouter1', 'OnionRouter2', 'OnionRouter3'],
        circ_id = random.randint(341, 1000),
    ))

    WEB_SERVER_LIST.append(Mini_server(
        ip = WEB_IP,
        port = WEB_PORT,
        nickname = 'WebServer',
    ))


def main():
    signal.signal(signal.SIGINT, signal_handler)
    setup()

    for web in WEB_SERVER_LIST:
        web.start()

    for auth in AUTH_LIST:
        auth.start()

    for onion_router in OR_LIST:
        onion_router.register_to_authority()

    time.sleep(0.5)

    for onion_router in OR_LIST:
        onion_router.fetch_descriptors_from_auth()

    for onion_router in OR_LIST:
        onion_router.start()

    time.sleep(0.5)
    
    circuit_or_names = ['OnionRouter1', 'OnionRouter2', 'OnionRouter3']
    client = CLIENT_LIST[0]
    client.fetch_descriptors_from_auth()

    try:
        # task 1: create circuit data structure
        client.constitute_circuit_path(circuit_or_names)
        # task 1: establish channel and circuit (first hop)
        client.connect_to_first_router()
        # task 2: extend circuit (all three hops)
        client.extend_circuit()
        # taks 3: connect to web server, interact with it
        client.connect_to_web_server_via_circuit()
        # task 4: end connection to web server
        client.end_connection_to_web_server()
        # task 4: destroy circuit
        client.destroy_circuit()
    except Exception as e:  
        print(f'error occured, end running\n {e}\n')
    time.sleep(0.5)

    for onion_router in OR_LIST:
        onion_router.stop()
    print('onion stopped')
    for auth in AUTH_LIST:
        auth.stop()
    print('auth stopped')
    for web in WEB_SERVER_LIST:
        web.stop()
    print('web server stopped')

    for onion_router in OR_LIST:
        onion_router.join()
    print('onion joined')
    for auth in AUTH_LIST:
        auth.join()
    print('auth joined')
    for web in WEB_SERVER_LIST:
        web.join()
    print('web server joined')


if __name__ == '__main__':
    main()