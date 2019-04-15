pbproxy: pbproxy.c
	gcc pbproxy.c -o pbproxy -lcrypto -lssl -pthread
