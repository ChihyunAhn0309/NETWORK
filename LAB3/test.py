#!/usr/bin/python3

# KAIST CS341 SDN Lab Test script

import time
import argparse
import sys
import random

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

from task_topology import Topology
from graph import gen_graph
from dump import dump_clear, dump_net

if __name__ == '__main__':
    # Uncomment below to see verbose log
    #setLogLevel('debug')
    
    parser = argparse.ArgumentParser(prog='CS341 SDN Lab Tester')
    parser.add_argument('--task', metavar='T', type=int, nargs='?', default=1,
                        help='task to test', required=True, choices=range(1,8))
    args = parser.parse_args()
    
    switches, hosts, links = gen_graph(args.task)
    if args.task == 1:
        t = Topology(switches, hosts, links)
        net = Mininet(topo=t)
    else:
        t = Topology(switches, hosts, links)
        net = Mininet(topo=t, controller=RemoteController, listenPort=6633)
        dump_net(net, links)
    
    net.start()
    net.waitConnected()
    domains = []
    processes = []
    if args.task == 4:
        domains = ['task4.com']
    elif args.task == 5:
        domains = ['task5-open.com', 'task5-block.com']
    elif args.task == 6:
        domains = ['task6-open.com', 'task6-block.com']
    elif args.task == 7:
        domains = [] # DIY :)
    if len(domains) >= 1:
        taskhosts = random.sample(net.hosts, len(domains) + 2)
        dnscmd = './dns'
        for domain, host in zip(domains, taskhosts[:-2]):
            processes.append(host.popen(f'./server.py {domain}', shell=True))
            print(f'running {domain} on {host.name}({host.IP()})')
            dnscmd = dnscmd + f' -a {domain}={host.IP()}'
        dnshost, normalhost = taskhosts[-2:]
        processes.append(dnshost.popen(dnscmd, shell=True))
        print(f'running DNS on {dnshost.name}({dnshost.IP()})')
        print('You can test via following commands:')
        for domain, host in zip(domains, taskhosts[:-2]):
            print(f'{normalhost.name} dig @{dnshost.IP()} {domain}')
            print(f'{normalhost.name} curl --resolve {domain}:80:{host.IP()} http://{domain}/')
            print(f'{normalhost.name} curl --resolve {domain}:80:$(dig +short @{dnshost.IP()} {domain} | tail -1) http://{domain}/')
    print('You can also try running new server or dns by following commands:')
    print('<hostname> ./server.py <domain> &')
    print('<hostname> ./dns -a <domain1>=<IP1> -a <domain2>=<IP2> ... &')
    print('You can check background processes by following command:')
    print('<hostname> jobs')
    print('You can kill background process by following command:')
    print('<hostname> kill %<background job number>')


    CLI(net)
    for process in processes:
        process.kill()
    net.stop()