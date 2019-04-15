void* server_to_user(void* args)
{
    struct data_transfer_info *transfer_data;
    transfer_data = (struct data_transfer_info *) args;
    
    int from = transfer_data-> source;
    int to = transfer_data-> dest;
    char *iv_server = transfer_data-> i_vec;
    const char *key_file = transfer_data->key_file;
    struct ctr_state *dec_state = transfer_data->enc_dec_state;
    transfer(from, to, DECRYPT, iv_server, key_file, dec_state);
}

int generate_client(const char* server_ip, int server_port, const char* key_file)
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    struct hostent * host = NULL;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "\n Socket creation error \n");
        exit(EXIT_FAILURE);
    }
  
    memset(&serv_addr, '0', sizeof(serv_addr));
  

    if ((host = gethostbyname(server_ip)) == 0)
    {
        fprintf(stderr, "\nHost not found\n");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_addr.s_addr = ((struct in_addr*) (host->h_addr))->s_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);
  
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        fprintf(stderr, "\nConnection Failed \n");
        exit(EXIT_FAILURE);
    }

    // initializing the iv and send it to the proxy-server
    unsigned char  IV[AES_BLOCK_SIZE];
    if(!RAND_bytes(IV, AES_BLOCK_SIZE))
    {
        fprintf(stderr, "Cannot create random bytes for initializing the iv.\n");
        close(sock);
        exit(EXIT_FAILURE);
    }


    if (write(sock, IV, AES_BLOCK_SIZE) <= 0) {
        fprintf(stderr, "Cannot send the IV to the proxy-server side.\n");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // initiating the encryption state for client
    struct ctr_state enc_state_client;
    init_ctr(&enc_state_client, IV);

    struct data_transfer_info *transfer_data = (struct data_transfer_info *) 
                                                malloc(sizeof(struct data_transfer_info));
    transfer_data-> source = sock;
    transfer_data-> dest = 1;
    transfer_data-> i_vec = IV;
    transfer_data->key_file = key_file;
    transfer_data->enc_dec_state = &enc_state_client;

    pthread_t server_to_user_thread;
    if( pthread_create( & server_to_user_thread , NULL , 
        server_to_user , (void*) transfer_data) < 0) {
                fprintf(stderr,"Running server_to_user_thread failed.\n");
                close(sock);
                free(transfer_data);
                return 0;
    }

    transfer(0, sock, ENCRYPT, IV, key_file, &enc_state_client);

    return 0;
}
