#define MAX_CLIENTS 10

typedef struct connection_info{
    const char *ssh_ip;
    int ssh_port;
    int client_socket;
    const char *keyFile;
} connection_info;

void *user_to_ssh(void *args) {
    struct data_transfer_info *transfer_data;
    transfer_data = (struct data_transfer_info *) args;
    
    int from = transfer_data-> source;
    int to = transfer_data-> dest;
    char *IV = transfer_data-> i_vec;
    const char *key_file = transfer_data->key_file;
    struct ctr_state *dec_state = transfer_data->enc_dec_state;

    transfer(from, to, DECRYPT, IV, key_file, dec_state);
}


void *handle_connection(void *args);

int start_server(int listen_on_port, const char* ssh_ip, int ssh_port, const char* keyFile)
{
    
    int server_fd, new_socket, num_bytes_read;
    struct sockaddr_in server_addr;
    int opt = 1;
    int addrlen = sizeof(server_addr);
      
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        fprintf(stderr, "\nSocket creation failed\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        fprintf(stderr, "\nSetsockopt error\n");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons( listen_on_port );
      
    if (bind(server_fd, (struct sockaddr *)&server_addr, 
                                 sizeof(server_addr))<0)
    {
        fprintf(stderr, "\nBind failed\n");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CLIENTS) < 0)
    {
        fprintf(stderr, "\nListen on port %d failed\n", listen_on_port);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Listening for connections");

    while (new_socket = accept(server_fd, (struct sockaddr *)&server_addr, 
                       (socklen_t*)&addrlen))
    {
        fprintf(stderr, "\nClient connected on socket: %d\n", new_socket);

        pthread_t conn_process_thread;
        
        connection_info* main_conn = (connection_info*)malloc(sizeof(connection_info));
        main_conn->client_socket = new_socket;
        main_conn->ssh_ip = ssh_ip;
        main_conn->ssh_port = ssh_port;
        main_conn->keyFile = keyFile;

        if (pthread_create(&conn_process_thread, NULL, handle_connection, main_conn) < 0)
        {
            fprintf(stderr, "\nThread creation error\n");
            close(server_fd);
            exit(EXIT_FAILURE);
        }


    }

    if (new_socket < 0)
    {
        fprintf(stderr, "\nConnection accept error\n");
        exit(EXIT_FAILURE);
    }

    close(server_fd);

    
    return 0;
}


void *handle_connection(void *args)
{
    
    connection_info *curr_conn = (connection_info*) args;

    int client_socket = curr_conn->client_socket;    
    const char* ssh_ip = curr_conn->ssh_ip;
    int ssh_port = curr_conn->ssh_port;
    const char *key_file = curr_conn->keyFile;

    struct hostent* host = NULL;

    char buffer[1024] = {0};
    int num_bytes_read = 0;

    char sshdIPAddress[16] = ""; // IPv4 can be at most 255.255.255.255 and last index for '\0'

    int sshdSocket = 0;
    sshdSocket = socket(AF_INET , SOCK_STREAM , 0);

    if (sshdSocket == -1) {
        fprintf(stderr, "\nCan't make socket connection to sshd server\n");
        close(client_socket);
        free(args);
        return NULL;
    }

    struct sockaddr_in sshdServer;

    if ((host = gethostbyname(ssh_ip)) == 0)
    {
        fprintf(stderr, "\nHost not found\n");
        exit(EXIT_FAILURE);
    }

    sshdServer.sin_addr.s_addr = ((struct in_addr*) (host->h_addr))->s_addr;
    sshdServer.sin_family = AF_INET;
    sshdServer.sin_port = htons(ssh_port);
 
    if (connect(sshdSocket, (struct sockaddr *)&sshdServer, sizeof(sshdServer)) < 0)
    {
        fprintf(stderr, "\nCouldn't connect to the sshd through the created socket\n");
        close(client_socket);
        free(args);
        exit(EXIT_FAILURE);
    }

    // get initialisation vector
    unsigned char  IV[AES_BLOCK_SIZE];
    int bytesReceived = read(client_socket, IV , AES_BLOCK_SIZE);
    if (bytesReceived != AES_BLOCK_SIZE) { // AES_BLOCK_SIZE is 16
        fprintf(stderr, "Error in receiving the IV of the proxy-client side.\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // decryption state initialised
    struct ctr_state dec_state_client;
    init_ctr(&dec_state_client, IV);


    struct data_transfer_info *transfer_data = (struct data_transfer_info *) malloc(sizeof(struct data_transfer_info));
    
    transfer_data-> source = client_socket;
    transfer_data-> dest = sshdSocket;
    transfer_data-> i_vec = IV;
    transfer_data->key_file = key_file;
    transfer_data->enc_dec_state = &dec_state_client;
    bzero(buffer , SIZE);

    // Transfer data from client to SSH
    pthread_t user_to_ssh_thread;
    if( pthread_create( & user_to_ssh_thread , NULL , 
        user_to_ssh , (void*) transfer_data) < 0) {
                fprintf(stderr,"Running user_to_ssh_thread failed.\n");
                fflush(stdout);
                close(client_socket);
                free(transfer_data);
                return 0;
    }



    transfer(sshdSocket,  client_socket, ENCRYPT, IV, key_file, &dec_state_client);

    close(client_socket);
    free(curr_conn);
    return 0; 

}
