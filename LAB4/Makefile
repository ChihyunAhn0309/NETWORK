init:
	mkdir -p data/OnionRouter1/keys data/OnionRouter2/keys data/OnionRouter3/keys \
			data/OnionRouter4/keys data/Client1/keys data/Client2/keys data/Auth/keys data/WebServer
	ssh-keygen -t rsa -b 2048 -N '' -C 'OnionRouter1' -f data/OnionRouter1/keys/OnionRouter1 -q
	ssh-keygen -t rsa -b 2048 -N '' -C 'OnionRouter2' -f data/OnionRouter2/keys/OnionRouter2 -q
	ssh-keygen -t rsa -b 2048 -N '' -C 'OnionRouter3' -f data/OnionRouter3/keys/OnionRouter3 -q
	ssh-keygen -t rsa -b 2048 -N '' -C 'OnionRouter4' -f data/OnionRouter4/keys/OnionRouter4 -q
	ssh-keygen -t rsa -b 2048 -N '' -C 'Client1' -f data/Client1/keys/Client1 -q
	ssh-keygen -t rsa -b 2048 -N '' -C 'Client2' -f data/Client2/keys/Client2 -q
	ssh-keygen -t rsa -b 2048 -N '' -C 'Authority' -f data/Auth/keys/Authority -q

	cp data/Auth/keys/Authority.pub data/OnionRouter1/keys
	cp data/Auth/keys/Authority.pub data/OnionRouter2/keys
	cp data/Auth/keys/Authority.pub data/OnionRouter3/keys
	cp data/Auth/keys/Authority.pub data/OnionRouter4/keys
	cp data/Auth/keys/Authority.pub data/Client1/keys
	cp data/Auth/keys/Authority.pub data/Client2/keys

clean:
	rm -rf data
	rm *.zip

zip:
	echo Name the file with your stedent id
	echo You may add more files to zip
	zip 20250000.zip mini_cell.py mini_client.py mini_crypt.py mini_relay.py