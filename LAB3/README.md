# Lab 3: Building Your Own Network with SDN

## Content

- [bootstrap.sh](bootstrap.sh): Setup Mininet and POX controller on VM, making VM via vagrant and virtualbox (called by `vagrant up`)
- [controller.py](controller.py): POX controller, working as wrapper of `task_controller.py`
- [dns.c](dns.c): slightly modified [SimpleDNS](https://github.com/mwarning/SimpleDNS)
- [dump.py](dump.py): Dumps network topology to `/tmp/net.json`
- [graph.py](graph.py): Generate random network topology
- **[task_controller](task_controller.py)**: Compute routing rules, pushing them to switches (Lab 2,3,4,5,6,7)
- **[task_topology.py](task_topology.py)**: Generate Mininet topology from given network structure (Lab 1)
- [server.py](server.py): Simple HTTP Server
- [setup.sh](setup.sh): Setup Mininet and POX controller directly on the machine
- [test.py](test.py): Test implementation of logic, opening Mininet CLI
- [Vagrantfile](Vagrantfile): Vagrantfile for setup Mininet and POX controller on VM