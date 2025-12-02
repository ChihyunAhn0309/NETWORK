import os
import json

def dump_clear():
    os.remove('/tmp/net.json')

# Create net.json from mininet
def dump_net(net, links):

    dump = {
        'hosts': {},
        'switches': {}
    }
    linkmap = {}
    for link in links:
        linkmap[(link[0],link[1])] = link[2]
        linkmap[(link[1],link[0])] = link[2]
    for host in net.hosts:
        hostinfo = {
            'name': host.name,
            'IP': host.IP(),
            'links': None
        }
        links = []
        for intf in host.intfList():
            if str(intf) == 'lo':
                # skip loopback interface
                continue
            p1 = int(intf.link.intf1.name.split('eth', 1)[1])
            h1 = intf.link.intf1.node.name
            p2 = int(intf.link.intf2.name.split('eth', 1)[1])
            h2 = intf.link.intf2.node.name
            c = linkmap[(h1,h2)]
            if h1 == host.name:
                links.append((h1, p1, h2, p2, c))
            else:
                links.append((h2, p2, h1, p1, c))
        hostinfo['links'] = links
        dump['hosts'][host.name] = hostinfo

    for switch in net.switches:
        switchinfo = {
            'name': switch.name,
            'links': None
        }
        links = []
        for intf in switch.intfList():
            if str(intf) == 'lo':
                # Skip loopback interface
                continue
            p1 = int(intf.link.intf1.name.split('eth', 1)[1])
            h1 = intf.link.intf1.node.name
            p2 = int(intf.link.intf2.name.split('eth', 1)[1])
            h2 = intf.link.intf2.node.name
            c = linkmap[(h1,h2)]
            if h1 == switch.name:
                links.append((h1, p1, h2, p2, c))
            else:
                links.append((h2, p2, h1, p1, c))
        switchinfo['links'] = links
        dump['switches'][switch.name] = switchinfo

    json.dump(
        dump,
        open('/tmp/net.json', 'w')
    )

