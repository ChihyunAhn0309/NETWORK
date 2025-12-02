#!/usr/bin/python3

import pox.openflow.libopenflow_01 as of
import collections
import heapq
import re

# KAIST CS341 SDN Lab Task 2, 3, 4, 5, 6, 7
#
# All functions in this file runs on the controller:
#   - init(self, net):
#       - runs only once for network, when initialized
#       - the controller should process the given network structure for future behavior
#   - addrule(self, switchname, connection):
#       - runs when the controller connects to a switch
#       - the controller should insert routing rules to the switch
#   - handlePacket(self, packet, connection):
#       - runs when the controller receives unhandled packets from a switch
#       - the controller should decide whether to handle the packet:
#           - let the switch route the packet
#           - drop the packet
#
# Task 2: Getting Familiarized With POX
#   - Let switches "flood" packets
#   - This is not graded
#
# Task 3: Implementing a Simple Routing Protocol
#   - Let switches route via Dijkstra
#   - Match ARP and ICMP over IPv4 packets
#
# Task 4: Redirecting All DNS Request Packets to Controller
#   - Let switches send all DNS request packets to controller
#       - Create proper forwarding rules, send all DNS queries to the controller
#       - DNS responses and HTTP traffic should not be forwarded to the controller
#
# Task 5: Implementing a Simple DNS-Based Censorship
#   - Let switches send only DNS query packets to controller
#       - Create proper forwarding rules, send only DNS queries to the controller
#   - Check if DNS query contains task5-block.com
#       - If such query is found, return empty DNS response instead of routing it
#
# Task 6: Implementing More Efficient DNS-Based Censorship
#   - Let switches send only DNS query packets to controller
#       - Create proper forwarding rules, send only DNS queries to the controller
#   - Check if DNS query contains task6-block.com
#       - If such query is found, insert a new rule to switch to track the DNS response
#           - let the switch route empty DNS response to the controller
#       - When the corresponding DNS response arrived, do followings:
#           - parse DNS response, insert a new rule to block all HTTP traffic from/to the server
#           - reply the DNS request with empty DNS response
#       - For all other packets, route them normally
#
# Task 7: Extending Censorship to a General Network Topology
#   - At any time, HTTP and DNS servers can be changed by following:
#     - Create new server, hosting either task7-block-<one or more digits>.com or task7-open-<one or more digits>.com
#       - DNS server adds new record, HTTP server adds new domain
#     - For certain domain, hosting server changes
#       - DNS server changes record, HTTP server is replaced to another one
#     - For certain domain, hosting stops
#       - DNS server removes record, HTTP server removes the domain
#     - For 3 changes above, HTTP servers and DNS servers are changed instantly
#  - Assume that
#    - single IP might host multiple domains
#      - the IP should be blocked if it hosts at least one task7-block-<one or more digits>.com
#    - Only one IP is assigned to one domain
#      - If you detect different DNS response for same DNS request, assume that previous IP does not host the domain anymore


###
# If you want, you can define global variables, import Python built-in libraries, or do others
###

def install_block_rule(connection, ip_to_block):
    msg_out = of.ofp_flow_mod()
    msg_out.priority = 300
    msg_out.match = of.ofp_match(
        dl_type = 0x0800,
        nw_proto = 6,
        nw_dst = ip_to_block,
        tp_dst = 80
    )

    connection.send(msg_out)

    msg_in = of.ofp_flow_mod()
    msg_in.priority = 300
    msg_in.match = of.ofp_match(
        dl_type = 0x0800,
        nw_proto = 6,
        nw_src = ip_to_block,
        tp_src = 80
    )

    connection.send(msg_in)


def remove_block_rule(connection, ip_to_unblock):
    msg_out = of.ofp_flow_mod()
    msg_out.command = of.OFPFC_DELETE
    msg_out.match = of.ofp_match(
        dl_type = 0x0800,
        nw_proto = 6,
        nw_dst = ip_to_unblock,
        tp_dst = 80
    )

    connection.send(msg_out)

    msg_in = of.ofp_flow_mod()
    msg_in.command = of.OFPFC_DELETE
    msg_in.match = of.ofp_match(
        dl_type = 0x0800,
        nw_proto = 6,
        nw_src = ip_to_unblock,
        tp_src = 80
    )

    connection.send(msg_in)

def propagate_block_rule(controller, ip_to_block):
    for conn in controller.switch_conn.values():
        install_block_rule(conn, ip_to_block)

def propagate_unblock_rule(controller, ip_to_unblock):
    for conn in controller.switch_conn.values():
        remove_block_rule(conn, ip_to_unblock)


def build_routing_table(self):
    ret_routing_table = collections.defaultdict(dict)

    for start_node in self.switches:
        pq = [(0, start_node)]
        find_min = set()
        node_num = tot_node_num = len(self.hosts) + len(self.switches)

        dist = {node: float('inf') for node in self.graph}
        prev_node = {node: None for node in self.graph}
        dist[start_node] = 0

        while pq and len(find_min) < node_num:
            dist2prev, cur_node = heapq.heappop(pq)
        
            if cur_node in find_min:
                continue
            
            find_min.add(cur_node)

            for near_node, cost in self.graph[cur_node].items():
                new_dist = dist2prev + cost
                if new_dist < dist[near_node]:
                    dist[near_node] = new_dist
                    prev_node[near_node] = cur_node
                    heapq.heappush(pq, (new_dist, near_node))

        for dest_node in self.hosts:
            prev_hop = None
            curr_hop = dest_node

            while curr_hop != start_node:
                prev_hop = prev_node.get(curr_hop)

                if prev_hop == None:
                    next_node = None
                    break

                if prev_hop == start_node:
                    next_node = curr_hop
                    break
                
                curr_hop = prev_hop
            
            if next_node:
                out_port = self.port_map.get((start_node, next_node))
                if out_port:
                    ret_routing_table[start_node][dest_node] = out_port

    return ret_routing_table


def init(self, net) -> None:
    #
    # net argument has following structure:
    # 
    # net = {
    #    'hosts': {
    #         'h1': {
    #             'name': 'h1',
    #             'IP': '10.0.0.1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('h1', 1, 's1', 2, 3)
    #             ],
    #         },
    #         ...
    #     },
    #     'switches': {
    #         's1': {
    #             'name': 's1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('s1', 2, 'h1', 1, 3)
    #             ]
    #         },
    #         ...
    #     }
    # }
    #
    pass
    ###
    # YOUR CODE HERE
    self.graph = collections.defaultdict(dict)
    self.routing_table = collections.defaultdict(dict)
    self.port_map = {}
    self.hosts = list(net['hosts'].keys())
    self.switches = list(net['switches'].keys())
    self.switch_conn = {}
    self.ip2host = {}
    self.host2ip = {}
    nodedata = {**net['hosts'], **net['switches']}
    for node_name, node_info in nodedata.items():
        if node_name in self.hosts:
            ip = node_info['IP']
            self.ip2host[ip] = node_name
            self.host2ip[node_name] = ip
        
        for link_con in node_info['links']:
            n1, p1, n2, p2, cost = link_con
            self.graph[n1][n2] = cost
            self.port_map[(n1,n2)] = p1

    self.routing_table = build_routing_table(self)

    self.blocked_ips = set()
    self.blocked_domains = {}
    self.blocked_ip_counts = collections.defaultdict(int)
    self.pending_requests = {}

    ###

def addrule(self, switchname: str, connection) -> None:
    #
    # This function is invoked when a new switch is connected to controller
    # Install table entry to the switch's routing table
    #
    # For more information about POX openflow API,
    # Refer to [POX official document](https://noxrepo.github.io/pox-doc/html/),
    # Especially [ofp_flow_mod - Flow table modification](https://noxrepo.github.io/pox-doc/html/#ofp-flow-mod-flow-table-modification)
    # and [Match Structure](https://noxrepo.github.io/pox-doc/html/#match-structure)
    #
    # your code will be look like:
    # msg = ....
    # connection.send(msg)
    pass
    ###
    # YOUR CODE HERE
    self.switch_conn[switchname] = connection

    dns_msg = of.ofp_flow_mod()
    dns_msg.priority = 100
    dns_msg.match = of.ofp_match(
        dl_type = 0x0800,
        nw_proto = 17,
        tp_dst = 53
    )
    dns_act = of.ofp_action_output(port = of.OFPP_CONTROLLER)
    dns_msg.actions.append(dns_act)
    connection.send(dns_msg)

    port_sets = self.routing_table.get(switchname, {})

    for dest_node, out_port in port_sets.items():
        dest_ip = self.host2ip.get(dest_node)

        if(out_port and dest_ip):
            ip4_msg = of.ofp_flow_mod()
            ip4_msg.priority = 10
            ip4_msg.match = of.ofp_match(
                dl_type = 0x0800,
                nw_dst = dest_ip
            )
            ip4_act = of.ofp_action_output(port = out_port)
            ip4_msg.actions.append(ip4_act)
            connection.send(ip4_msg)

            arp_msg = of.ofp_flow_mod()
            arp_msg.priority = 10
            arp_msg.match = of.ofp_match(
                dl_type = 0x0806,
                nw_dst = dest_ip
            )
            arp_act = of.ofp_action_output(port = out_port)
            arp_msg.actions.append(arp_act)
            connection.send(arp_msg)

    for ip, count in self.blocked_ip_counts.items():
        if count > 0:
            install_block_rule(connection, ip)
    ###

from scapy.all import * # you can use scapy in this task

def handlePacket(self, switchname, event, connection):
    packet = event.parsed
    if not packet.parsed:
        print('Ignoring incomplete packet')
        return
    # Retrieve how packet is parsed
    # Packet consists of:
    #  - various protocol headers
    #  - one content
    # For example, a DNS over UDP packet consists of following:
    # [Ethernet Header][           Ethernet Body            ]
    #                  [IPv4 Header][       IPv4 Body       ]
    #                               [UDP Header][ UDP Body  ]
    #                                           [DNS Content]
    # POX will parse the packet as following:
    #   ethernet --> ipv4 --> udp --> dns
    # If POX does not know how to parse content, the content will remain as `bytes`
    #     Currently, HTTP messages are not parsed, remaining `bytes`. you should parse it manually.
    # You can find all available packet header and content types from pox/pox/lib/packet/
    packetfrags = {}
    p = packet
    while p is not None:
        packetfrags[p.__class__.__name__] = p
        if isinstance(p, bytes):
            break
        p = p.next
    print(packet.dump()) # print out received packet
    # How to know protocol header types? see name of class

    # If you want to send packet back to switch, you can use of.ofp_packet_out() message.
    # Refer to [ofp_packet_out - Sending packets from the switch](https://noxrepo.github.io/pox-doc/html/#ofp-packet-out-sending-packets-from-the-switch)
    # You may learn from [l2_learning.py](pox/pox/forwarding/l2_learning.py), which implements learning switches
    
    # You can access other switches via self.controller.switches
    # For example, self.controller.switches[0].connection.send(msg)

    ###
    # YOUR CODE HERE
    dns_head = packet.find('dns')
    eth_head = packet
    ip_head = packet.find('ipv4')
    udp_head = packet.find('udp')

    if ip_head is None:
        return

    if dns_head and dns_head.qr == 0:
        blocked_domain5 = 'task5-block.com'
        blocked_domain6 = 'task6-block.com'

        original_question = dns_head.questions[0]
        qname = original_question.name

        if re.match(r"task7-block-\d+\.com", qname):
            key = (ip_head.srcip, dns_head.id)
            self.controller.pending_requests[key] = (event, packet)

            dns_res_msg = of.ofp_flow_mod()
            dns_res_msg.priority = 200
            dns_res_msg.idle_timeout = 1
            dns_res_msg.hard_timeout = 3
            dns_res_msg.match = of.ofp_match(
                dl_type = 0x0800,
                nw_proto = 17,
                nw_src = ip_head.dstip,
                nw_dst = ip_head.srcip,
                tp_src = udp_head.dstport,
                tp_dst = udp_head.srcport
            )
            dns_res_act = of.ofp_action_output(port = of.OFPP_CONTROLLER)
            dns_res_msg.actions.append(dns_res_act)
            connection.send(dns_res_msg)

            dest_host = self.controller.ip2host.get(str(ip_head.dstip))
            if dest_host:
                out_port = self.controller.routing_table.get(switchname, {}).get(dest_host)
                if out_port:
                    msg_out = of.ofp_packet_out()
                    msg_out.data = event.data
                    msg_out.actions.append(of.ofp_action_output(port = out_port))
                    connection.send(msg_out)
            

        elif qname == blocked_domain5:

            scapy_qd = DNSQR(
                qname = original_question.name,
                qtype = original_question.qtype,
                qclass = original_question.qclass
            )
            
            dns_resp = DNS(
                id = dns_head.id,
                qr = 1,
                opcode = dns_head.opcode,
                rd = dns_head.rd,
                qd = scapy_qd,
                ancount = 0,
                rcode = 0
            )

            udp_resp = UDP(
                sport = udp_head.dstport,
                dport = udp_head.srcport
            )

            ip_resp = IP(
                src = ip_head.dstip,
                dst = ip_head.srcip
            )

            eth_resp = Ether(
                src = eth_head.dst,
                dst = eth_head.src
            )

            resp_packet = eth_resp / ip_resp / udp_resp / dns_resp

            dns_msg = of.ofp_packet_out()
            dns_msg.data = resp_packet.build()
            dns_act = of.ofp_action_output(port = event.port)
            dns_msg.actions.append(dns_act)
            connection.send(dns_msg)

            return
        
        elif qname == blocked_domain6:
            key = (ip_head.srcip, dns_head.id)
            self.controller.pending_requests[key] = (event, packet)

            dns_res_msg = of.ofp_flow_mod()
            dns_res_msg.priority = 200
            dns_res_msg.match = of.ofp_match(
                dl_type = 0x0800,
                nw_proto = 17,
                nw_src = ip_head.dstip,
                nw_dst = ip_head.srcip,
                tp_src = udp_head.dstport,
                tp_dst = udp_head.srcport
            )
            dns_res_act = of.ofp_action_output(port = of.OFPP_CONTROLLER)
            dns_res_msg.actions.append(dns_res_act)
            connection.send(dns_res_msg)

    
    elif dns_head and dns_head.qr == 1:
        key = (ip_head.dstip, dns_head.id)

        if key in self.controller.pending_requests:
            (original_event, original_packet) = self.controller.pending_requests.pop(key)

            original_question = dns_head.questions[0]
            qname = original_question.name    

            old_ip = self.controller.blocked_domains.get(qname)
            new_ip = None


            if len(dns_head.answers) > 0:
                for answer in dns_head.answers:
                    if answer.qtype == 1:
                        new_ip = str(answer.rddata)
                        break
                                                                                                            
            if old_ip != new_ip:
                if old_ip:
                    self.controller.blocked_ip_counts[old_ip] -= 1
                    current_count = self.controller.blocked_ip_counts[old_ip]
                    if self.controller.blocked_ip_counts[old_ip] <= 0:
                        del self.controller.blocked_ip_counts[old_ip]
                        propagate_unblock_rule(self.controller, old_ip)
                if new_ip:
                    if self.controller.blocked_ip_counts[new_ip] == 0:
                        propagate_block_rule(self.controller, new_ip)
                    self.controller.blocked_ip_counts[new_ip] += 1
                    self.controller.blocked_domains[qname] = new_ip
                
                elif qname in self.controller.blocked_domains:
                    del self.controller.blocked_domains[qname]

            orig_eth = original_packet
            orig_ip = original_packet.find('ipv4')
            orig_udp = original_packet.find('udp')
            orig_dns = original_packet.find('dns')
            orig_q = orig_dns.questions[0]

            scapy_qd = DNSQR(qname = orig_q.name, qtype = orig_q.qtype, qclass = orig_q.qclass)
            dns_reply = DNS(id = orig_dns.id, qr = 1, opcode = orig_dns.opcode, rd = orig_dns.rd, qd = scapy_qd, ancount = 0, rcode = 0)
            udp_reply = UDP(sport = orig_udp.dstport, dport = orig_udp.srcport)
            ip_reply = IP(src = orig_ip.dstip, dst = orig_ip.srcip)
            eth_reply = Ether(src = orig_eth.dst, dst = orig_eth.src)

            reply_packet = eth_reply / ip_reply / udp_reply / dns_reply

            msg_out = of.ofp_packet_out()
            msg_out.data = reply_packet.build()
            msg_out_act = of.ofp_action_output(port = original_event.port)
            msg_out.actions.append(msg_out_act)
            connection.send(msg_out)

            return



    if packet.type == packet.IP_TYPE:
        ip_packet = packet.payload
        dest_ip = str(ip_packet.dstip)

        dest_node = self.controller.ip2host.get(dest_ip)
        if dest_node:
            out_port = self.controller.routing_table.get(switchname, {}).get(dest_node)
        
        msg = of.ofp_packet_out()
        msg.data = event.data
        if out_port:
            act = of.ofp_action_output(port = out_port)
            msg.actions.append(act)
        else:
            act = of.ofp_action_output(port = of.OFPP_FLOOD)
            msg.actions.append(act)
        connection.send(msg)

    ###
