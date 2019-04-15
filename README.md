Network Security : Proxy Agent 

DESCRIPTION
 
In this project a proxy agent was developed for adding an extra layer of protection to publicly accessible network services. 
The primary program in this assignment in pbproxy.c (The proxy agent). pbproxy acts as the proxy in the connections and has two modes of execution. 
1) Server mode: In server mode pbproxy acts like a server listening on a particular port and forwarding the content read to the actual server which the client wants to connect to. 
2) Client mode In client mode, pbproxy connects to the specified destination IP and port number on behalf of the user. It expects that there will be another instance of pbproxy running on the sever's end with which this pbproxy will communicate. 


All communications are encrypted using AES CTR mode with a key of size 128 bits (16 bytes). 

Consider for example the case of an SSH server with a public IP address. No matter how securely the server has been configured and how strong keys are used, it might suffer from a zero day vulnerability that allows remote code execution even before the completion of the authentication process. This could allow attackers to compromise the server even without having proper authentication credentials. 
The Heartbleed OpenSSL bug is a recent example of such a serious vulnerability against SSL/TLS. 

The proxy agent we developed, named 'pbproxy', adds an extra layer of encryption to connections towards TCP services. Instead of connecting directly to the service, clients connect to pbproxy (running on the same server), which then relays all traffic to the actual service. Before relaying the traffic, pbproxy *always* decrypts it using a static symmetric key. This means that if the data of any connection towards the protected server is not properly encrypted, then it will turn into garbage before reaching the protected service. 

Attackers who might want to exploit a zero day vulnerability in the protected service will first have to know the secret key for having a chance to successfully deliver their attack vector to the server. This of course assumes that the proxy agent does not suffer from any vulnerability itself. Clients who want to access the protected server should proxy their traffic 
through a local instance of proxy, which will encrypt the traffic using the same symmetric key used by the server. In essence, pbproxy can act both as a client-side proxy and as server-side reverse proxy. 

FILE DESCRIPTIONS: 

pbproxy.c - This is the main file that acts as the proxy for communications 
client.h - This file hosts the function required in the client mode of execution. It calls the encrypt/decrypt functions and transfers data between the user and the server. 
server.h - This file hosts the function required in the server mode of execution. It calls the encrypt/decrypt functions and transfers data between the client and the SSH server. 
utils.h - This file contains all the functionalities that are needed by client.h and server.h to transfer the data to and fro and it also includes the encrypt/decrypt functionalities. 
mykey - Key was generated using the urandom tool provided in Ubuntu 
Implementation details: 
pbproxy.c - pbproxy is the file that integrates all the functionalities provided by the other files. When we run the file, the commandline arguments are parsed using getopt. These arguments are then used to decide if the program is to be run in server mode of client mode. 

1. Server mode: pbproxy passes the port number for the server, the key for encryption and the destination ip and port to the start_server function provided by the server.h 
2. Client mode: pbproxy passes the destination address (of the server side pbproxy) and port number along with the secret key to the generate_client function implemented in client.h 

client.h - The main function in this file is the generate_client function. Once called, it creates a socket for the client and connects it to the given destination address and port number. Once the connection is established, the first thing done is the creation and transfer of the Initialisation vector for encryption of future communication. Once this is done, we need to continuously transfer data to and fro between the user and the server. We call the "transfer" function (from utils.h) twice to achieve this, once for each direction of communication. Both these function calls run simultaneously, one in the main thread and one in an auxiliary thread that we created just to transfer content from the server to the user. 

server.h - server.h works very similar to client.h. The main function in this file is the start_server function. Given the details of the server start_server spawns a server which listens on a particular port. In this implementation, once a client tries to connect to the server, the server creates a new thread for the function "handle_connection", which as the name suggests handles all future actions to be taken for this connection. This allows our server to support multiple clients at the same time. The handle_connection function first connects to the SSH server (destination server), receives the Initialisation vector sent by the client, and then proceeds to transfer data to and fro between the client and the SSH server. Like the client side implementation, all data is encrypted and the transfer is done using the "transfer" function (from utils.h) which is called in 2 separate threads, once in the main thread to transfer data from the SSH server to the client and once in a new thread to transfer data from the client to the SSH server. 

utils.h - This file implements the encryption and decryption functions. We use the AES CTR 128 mode implementation of OpenSSL for our encryption needs. Data is encrypted/decrypted block by block and transferred to the receiving party. This file also holds the "transfer" function which takes all the details of a transfer (like source, destination, encrypt/decrypt etc) and uses the cryptography functions to transfer data securely. 

COMMANDLINE USAGE INFORMATION: 
Compilation: make 
make will call the command "gcc pbproxy.c -o pbproxy -lcrypto -lssl -pthread" which will compile the code and create an object file pbproxy 

Execution: 

1) Server mode: ./pbproxy -k mykey -l 2222 localhost 22 
./pbproxy [-l port] -k keyfile destination port 
-l Reverse-proxy mode: listen for inbound connections on <port> and relay 
them to <destination>:<port> 
-k Use the symmetric key contained in <keyfile> (as a hexadecimal string) 
In current implementation the keyfile is "mykey" so that should be passed in the keyfile argument 

2) Client mode: ssh -o "ProxyCommand ./pbproxy -k mykey localhost 2222" localhost 
In client mode we are assuming that the user wants to use the proxy to connect to a remote host using SSH. So we execute pbproxy inside the ProxyCommand part of the SSH command. Note that in the client part of the program we dont need to specify the -l argument while it is necessary in server mode. 

REFERENCES: 
Multiple web articles/tutorials were referred, the major ones are listed. 
1. http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/ 
2. http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/socket.html 
3. https://askubuntu.com/questions/192203/how-to-use-dev-urandom 
4. http://www.geeksforgeeks.org/socket-programming-cc/ 
5. https://computing.llnl.gov/tutorials/pthreads/ 
6. http://timmurphy.org/2010/05/04/pthreads-in-c-a-minimal-working-example/ 
