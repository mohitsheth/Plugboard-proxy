#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h>	
#include <arpa/inet.h>	
#include <ctype.h>


#define SIZE 1024
#define CRYPT_BUFFER_SIZE 1040
#define ENCRYPT 1
#define DECRYPT 0

struct data_transfer_info {
    int source;
    int dest;
    char *i_vec;
    const char *key_file;
    struct ctr_state *enc_dec_state;
};

struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};


int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{

    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
    * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
 
    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);
 
    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}


int encrypt(const char * key_file_name, unsigned char * iv, struct ctr_state * enc_state,
	char * buffer, int num_bytes_read , char * op_buffer) {


    unsigned char enc_key[16];
    FILE * key_file = NULL;
    AES_KEY key;
    int total_bytes_written= 0, total_bytes_read = 0;



    key_file = fopen(key_file_name, "rb");
    
    if(key_file == NULL) {
        fprintf(stderr,"\nError in opening the key_file.\n");
        return -1;
    }
    
    
    if(fread(enc_key, 1, AES_BLOCK_SIZE, key_file) != 16) {
        fprintf(stderr,"\nCouldn't read key.\n");
        fflush(stdout);
        return -1;
    }
    fclose(key_file);
    
    //Initializing the encryption KEY

    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        printf("\nCouldn't set encryption key.\n");
        fflush(stdout);
        return -1;
    }


    //Encrypting the data in blocks of 16 bytes
    while(total_bytes_read < num_bytes_read) {

        unsigned char aes_block_size_buffer[AES_BLOCK_SIZE];
        unsigned char ciphertext[AES_BLOCK_SIZE];
        
        int bytes_read_count = 0, i;
        for (i = total_bytes_read;i < num_bytes_read && i < (total_bytes_read + AES_BLOCK_SIZE); ++i) {
            aes_block_size_buffer[i - total_bytes_read] = buffer[i];
            bytes_read_count++;
        }

        AES_ctr128_encrypt(aes_block_size_buffer, ciphertext, bytes_read_count, &key, enc_state->ivec, enc_state->ecount, &(enc_state->num));
        
        for(i = 0; i < bytes_read_count ; i++ ) {
            op_buffer[total_bytes_written + i] = ciphertext[i];
        }
        
        total_bytes_written +=  bytes_read_count ;
        total_bytes_read += AES_BLOCK_SIZE;
    }       
    return total_bytes_written ; 
}


int decrypt(const char * key_file_name, unsigned char * iv, struct ctr_state * dec_state,
	char * buffer, int num_bytes_read , char * op_buffer) {

    FILE * key_file = fopen(key_file_name, "rb");
    
    if(key_file == NULL) {
        printf("\nError in opening the key_file.\n");
        fflush(stdout);
        return -1;
    }
    
    unsigned char enc_key[16];
    if(fread(enc_key, 1, AES_BLOCK_SIZE, key_file) != 16) {
        printf("\nCan't read key.\n");
        fflush(stdout);
        return -1;
    }

    fclose(key_file);
    
    //Initializing the encryption KEY
    AES_KEY key;
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        printf("\nEncryption key could not be set.\n");
        fflush(stdout);
        return -1;
    }
    

    int total_bytes_written= 0;
    int total_bytes_read = 0;

    //Decrypting block by block 
    while(total_bytes_read < num_bytes_read) {

        unsigned char aes_block_size_buffer[AES_BLOCK_SIZE];
        unsigned char ciphertext[AES_BLOCK_SIZE];

        int bytes_read_count = 0,i;
        for (i = total_bytes_read;i < num_bytes_read && i < (total_bytes_read + AES_BLOCK_SIZE); ++i) {
            ciphertext[i - total_bytes_read] = buffer[i];
            bytes_read_count++;
        }

        
        AES_ctr128_encrypt(ciphertext, aes_block_size_buffer, bytes_read_count, &key, dec_state->ivec, dec_state->ecount, &(dec_state->num));
       
        for(i = 0; i < bytes_read_count ; i++ ) {
            op_buffer[total_bytes_written + i] = aes_block_size_buffer[i];
        }
        
        total_bytes_written +=  bytes_read_count;
        total_bytes_read += AES_BLOCK_SIZE;
    }
    
    return total_bytes_written ;    
}


void transfer(int source, int dest, int encrypt_decrypt, char* iv, const char* key_file, struct ctr_state* enc_dec_state)
{

    int num_bytes_read, num_bytes_write = 0;
    char buffer[SIZE] = {0};
    char crypto_text[CRYPT_BUFFER_SIZE];
    
    while (1)
    {

        num_bytes_read = read(source, buffer, SIZE);
        if (num_bytes_read < 0)
        {
            fprintf(stderr, "\n Problem Reading\n");
            return;
        }

        else if (num_bytes_read == 0)
        {
            fprintf(stderr, "\nConnection Closed\n");
            return;
        }


        else
        {
            int crypt_size;
            if (encrypt_decrypt == ENCRYPT) {
                crypt_size = encrypt(key_file, iv, enc_dec_state, buffer, num_bytes_read, crypto_text);
            }
            else if (encrypt_decrypt == DECRYPT) {
                crypt_size = decrypt(key_file, iv, enc_dec_state, buffer, num_bytes_read, crypto_text);
            }
                
            if (crypt_size < 0) {
                fprintf(stderr, "\nError in encryption/decryption.\n");
                close(source);
                close(dest);
                return;
            }

            int num_bytes_write_total = 0;

            while (num_bytes_write_total < num_bytes_read)
            {
                num_bytes_write = write(dest , buffer+num_bytes_write_total, num_bytes_read - num_bytes_write_total);
                if (num_bytes_write <= 0)
                {
                    fprintf(stderr, "\nConnection Closed\n");
                    close(source);
                    close(dest);

                    return;
                }
                num_bytes_write_total += num_bytes_write;
            }             
                
        }
   
    }
}
