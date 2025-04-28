#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h> 

#define SERVER_ADRESS	"127.0.0.1"
#define SERVER_PORT		55555
#define BUFFER_SIZE		4096
#define SVR_KEY_PATH    "./ClientFs/sample_public.pem"   


enum Cmd{
    CMD_OK      = 0,
    CMD_NOK     = 1,
    CMD_PRINT   = 2
};

typedef struct _msg{
    unsigned int cmd;
    char payload[BUFFER_SIZE-4];
    size_t payload_len;
}msg;


void exit_sys(const char *msg);
int hex_char_to_int(char c) ;
int hexstr_to_bytes(const char *hexstr, unsigned char *out, size_t out_len);
void print_hex(const char *label, const unsigned char *data, int len) ;
int add_padding(unsigned char*buf,size_t buf_len );
int create_packet(char* buf, int buf_size,const msg* message, unsigned char* iv, const AES_KEY* enc_key);
int recv_all(int sock, void *buf, size_t len);
int recv_server_msg(int client_sock, msg* message, AES_KEY* dec_key, unsigned char* iv );
int unpad(unsigned char* buf, size_t size);
void create_key(unsigned char* key, unsigned char* iv );
int safe_delete_and_sync(const char *filepath);
int recv_server_certificate(int client_sock);

int main(void)
{
    int client_sock;
    struct sockaddr_in sin_server;
    struct hostent* hent;
    char buf[BUFFER_SIZE];
    char recv_buf[BUFFER_SIZE];
    char send_buf[BUFFER_SIZE];
    char *str;
    int string_len;
    AES_KEY enc_key;
    AES_KEY dec_key;
    size_t recv_len;
    int result;
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];
    msg message;

    

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    ERR_load_crypto_strings();


    if((client_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        exit_sys("socket");

    /*
    {
        struct sockaddr_in sin_client;
    
        sin_client.sin_family= AF_INET;
        sin_client.sin_port = htons(50000);
        sin_client.sin_addr.s_addr = htonl(INADDR_ANY);
    
        if(bind(client_sock, (struct sockaddr*)&sin_client, sizeof(sin_client)  ) == -1)
            exit_sys("bind");
    }
    */

        sin_server.sin_family = AF_INET;
        sin_server.sin_port = htons(SERVER_PORT);
        
        if((sin_server.sin_addr.s_addr = inet_addr(SERVER_ADRESS)) == -1)
          exit_sys("inet_addr");  

        if((connect(client_sock,(struct sockaddr*)&sin_server, sizeof(sin_server))) == -1)
            exit_sys("connect"); 
        
        if ((recv_len = recv(client_sock, recv_buf, BUFFER_SIZE, 0)) == -1)
	        exit_sys("recv");   
        
        recv_buf[recv_len] = '\0';
        
        if(strcmp("HELLO", recv_buf) != 0)
        {
            printf("Connection Failed\n");
            goto EXIT;   
        }

        if(recv_server_certificate(client_sock) == -1)
        {
            exit_sys("Cannot Recv Server Certificate");
        }

        create_key(key, iv );
        
        AES_set_decrypt_key(key, 256, &dec_key);
        AES_set_encrypt_key(key, 256, &enc_key);
        
        if( send_key(key,iv, client_sock )== -1)
        {
            exit_sys("Key exchange failed!!");
        }

        if(recv_server_msg( client_sock, &message, &dec_key, iv ) == -1)
        {
            exit_sys("Key exchange failed!!"); 
        }

        if(message.cmd != CMD_OK)
        {
            exit_sys("Key exchange failed!!");
        }

        for (;;) 
        {
		    printf("ct>");
		    fflush(stdout);

		    if (fgets(buf, BUFFER_SIZE-4, stdin) == NULL)
			    continue;
		    if ((str = strchr(buf, '\n')) != NULL)
			    *str = '\0';
            
            string_len= strlen(buf);            
            
            message.cmd = CMD_PRINT;

            memcpy(message.payload, buf, string_len);
            message.payload_len = string_len;
            if( (result = create_packet(send_buf, BUFFER_SIZE, &message, iv, &enc_key)) == -1)
            {
                printf("Too Long Data \n");
                continue;
            }
		    if (send(client_sock, send_buf, result, MSG_NOSIGNAL) == -1)
			    exit_sys("send"); 


            if(recv_server_msg( client_sock, &message, &dec_key, iv ) == -1)
            {
                exit_sys("recv_server_msg");
            }
            
            if(message.cmd != CMD_OK)
            {
                printf("Server Failed To Execute The Message !!\n");
            }

            if (!strcmp(buf, "quit"))
			    break;
	    }

EXIT:
	shutdown(client_sock, SHUT_RDWR);
	close(client_sock);

	return 0;
    
}

int recv_server_certificate(int client_sock)
{   
   unsigned int message_len = 0;
   FILE* fptr = 0;
   char buf[BUFFER_SIZE];
   size_t file_size = 0;
   size_t rcv_len = 0;
   size_t total_rcvd_bytes =0;


    safe_delete_and_sync(SVR_KEY_PATH);
    fptr = fopen(SVR_KEY_PATH, "wb");

    if(fptr == NULL)
        return -1;

    if(recv_all(client_sock, &message_len, sizeof(message_len) ) == -1)
    {
        return -1;
    }

    if(message_len != sizeof(file_size))
    {
        return -1;
    }

    if(recv_all(client_sock, &file_size, message_len) == -1)
    {
        return -1;
    }

    for(;;)
    {
        if( (rcv_len = recv(client_sock, buf, 1024, 0)) == -1)
        {
            return -1;
        }
        fwrite(buf,sizeof(char),rcv_len, fptr);
        total_rcvd_bytes += rcv_len;
        if(total_rcvd_bytes >= file_size)
        {
            break;
        }
    }
    fclose(fptr);
    return 0;
}


void create_key(unsigned char* key, unsigned char* iv )
{
    RAND_bytes(key, 32);
    RAND_bytes(iv, AES_BLOCK_SIZE);
}

int send_key(unsigned char* key, unsigned char* iv, int client_sock)
{
    // Load or generate RSA keypair
    RSA *rsa = NULL;
    // load private key from PEM file
    FILE *fp = fopen(SVR_KEY_PATH, "r");
    unsigned int message_len = 0;
    int dec_len;
    char payload[32+ AES_BLOCK_SIZE];
    char buf[BUFFER_SIZE];
    char encrypted[BUFFER_SIZE+1];
    int enc_len = 0;
    msg message;

    if(fp == NULL)
    {
        return -1;
    }
    
    if(PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL) == NULL )
    {
        ERR_print_errors_fp(stderr);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    memcpy(payload, key, 32);
    memcpy((payload + 32), iv, AES_BLOCK_SIZE);

    enc_len = RSA_public_encrypt(48, payload, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);

    memcpy( buf, &enc_len, sizeof(enc_len) );
    memcpy( buf+4, encrypted, enc_len );

    if (send(client_sock, buf, enc_len+sizeof(enc_len), MSG_NOSIGNAL) == -1)
    {
	    return -1;
    }
    return 0;
}

int recv_server_msg(int client_sock, msg* message, AES_KEY* dec_key, unsigned char* iv )
{
    unsigned int message_len;
    unsigned char buf[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];
    int dec_len = 0;

    if(recv_all(client_sock, &message_len, sizeof(message_len) ) == -1)
    {
        return -1;
    }

    if(recv_all(client_sock, buf, message_len) == -1)
    {
        return -1;
    }
    memcpy(iv,buf, AES_BLOCK_SIZE);
    
    fflush(stdout);

    AES_cbc_encrypt(buf+AES_BLOCK_SIZE, decrypted, (size_t)(message_len-AES_BLOCK_SIZE), dec_key, iv, AES_DECRYPT);
    
    fflush(stdout);
    dec_len = unpad(decrypted, message_len-AES_BLOCK_SIZE) ;
    

    memcpy(&message->cmd, decrypted, 4);
    memcpy(message->payload, decrypted, dec_len-4);
    return 0;
}

int recv_all(int sock, void *buf, size_t len) 
{
    size_t total = 0;
    while (total < len) 
    {
        ssize_t n = recv(sock, (char*)buf + total, len - total, 0);
        if (n < 0) exit_sys("recv"); // error or disconnect
        if (n == 0) return -1;
        total += n;
    }
    return 0;
}


int hex_char_to_int(char c) 
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1; // Invalid hex digit
}

int hexstr_to_bytes(const char *hexstr, unsigned char *out, size_t out_len) 
{
    size_t len = strlen(hexstr);
    if (len % 2 != 0 || len / 2 != out_len) return -1;

    for (size_t i = 0; i < out_len; i++) {
        int high = hex_char_to_int(hexstr[2 * i]);
        int low  = hex_char_to_int(hexstr[2 * i + 1]);
        if (high < 0 || low < 0) return -1;

        out[i] = (high << 4) | low;
    }

    return 0;
}

int add_padding(unsigned char*buf,size_t buf_len )
{
    int padding_len =  16 - (buf_len % 16 );
    
    memset(buf+buf_len, padding_len, padding_len);        

    return buf_len+padding_len;
}

void print_hex(const char *label, const unsigned char *data, int len) 
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int create_packet(char* buf, int buf_size,const msg* message, unsigned char* iv, const AES_KEY* enc_key)
{   
    
    int padded_len;
    int len=0;
    char ciphertext[BUFFER_SIZE];
    char tmp_buf[BUFFER_SIZE];
    size_t raw_msg_len;

    memcpy(tmp_buf,&message->cmd, 4);
    memcpy(tmp_buf+4, message->payload, message->payload_len );
    
    raw_msg_len = 4 + message->payload_len;
        
    padded_len = add_padding(tmp_buf,raw_msg_len);
    
    
    if(padded_len > (buf_size-(AES_BLOCK_SIZE+sizeof(len)) ))
    {
        return -1;
    }
    len = padded_len + AES_BLOCK_SIZE;
    memcpy(buf, &len, sizeof(len));
    memcpy(buf+sizeof(len), iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt(tmp_buf, ciphertext, padded_len, enc_key, iv, AES_ENCRYPT);
    // ToDo: Prevent Unnecessary Copy
    memcpy(buf+sizeof(len)+AES_BLOCK_SIZE, ciphertext, padded_len);
    // Return Total Length
    return (padded_len+AES_BLOCK_SIZE+sizeof(len));
}

int unpad(unsigned char* buf, size_t size)
{
    int len_of_padding = buf[size-1];
    if(len_of_padding <= 0)
        return -1;
    
    return size-len_of_padding;
}


int safe_delete_and_sync(const char *filepath) 
{
    // Duplicate filepath because dirname() modifies it
    char *dirpath;
    int dirfd;
    char buf[2048];


    strcpy(buf,filepath);
    buf[strlen(filepath)] = '\0';
    // Get directory name
    dirpath = dirname(buf);
    if (!dirpath) 
    {
        perror("dirname");
        return -1;
    }

    // Open directory
    dirfd = open(dirpath, O_DIRECTORY | O_RDONLY);
    if (dirfd == -1) 
    {
        perror("open directory");
        return -1;printf("%s %d \n", __func__, __LINE__);
    }

    // Unlink (delete) the file
    if (unlink(filepath) == -1) 
    {
        perror("unlink");
        close(dirfd);
        return -1;
    }
    // Fsync the directory
    if (fsync(dirfd) == -1) 
    {
        perror("fsync");
        close(dirfd);
        return -1;
    }
    close(dirfd);

    return 0;
}



void exit_sys(const char *msg)
{
	perror(msg);

	exit(EXIT_FAILURE);
}
