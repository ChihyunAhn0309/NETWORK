set -ex
sudo apt-get update; sudo apt-get -y upgrade
sudo apt-get install curl
git clone https://github.com/NetSP-KAIST/mininet.git
./mininet/util/install.sh -nfvp
ln -s ../../../controller.py pox/pox/misc/
make
sudo pip3 install scapy