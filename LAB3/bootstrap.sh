set -ex
sudo apt-get update; sudo apt-get -y upgrade
sudo apt-get install curl
git clone https://github.com/NetSP-KAIST/mininet.git
./mininet/util/install.sh -nfvp
ln -s /vagrant/{*.py,*.c,Makefile,client.sh} /home/vagrant/
ln -s /vagrant/controller.py /home/vagrant/pox/pox/misc/
cd /home/vagrant/
make
sudo pip3 install scapy