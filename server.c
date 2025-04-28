#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <pthread.h>
#include <stdatomic.h>

#define SERVER_PORT 55555
#define BUFFER_SIZE 4096
#define MAX_CONNECTIONS 3
#define PUB_CER_PATH    "./ServerFs/server_cert.pem"
#define PRV_CER_PATH    "./ServerFs/server_private.pem"

enum Cmd{
    CMD_OK      = 0,
    CMD_NOK     = 1,
    CMD_PRINT   = 2
};

typedef struct tagCLIENT_INFO {
	int sock;
	struct sockaddr_in sin;
} CLIENT_INFO;

typedef struct _msg{
    unsigned int cmd;
    char payload[BUFFER_SIZE-4];
    size_t payload_len;
}msg;


void *client_thread_proc(void *param);
void exit_sys(const char *msg);
int hex_char_to_int(char c) ;
int hexstr_to_bytes(const char *hexstr, unsigned char *out, size_t out_len);
int unpad(unsigned char* buf, size_t size);
int recv_key(unsigned char* key,unsigned char* iv, const CLIENT_INFO* ci );
int recv_all(int sock, void *buf, size_t len);
int connection_num = 0;
int create_packet(char* buf,const unsigned int buf_size,const msg* message, unsigned char *iv, const AES_KEY* enc_key);
void print_hex(const char *label, const unsigned char *data, int len) ;
int send_certificate(CLIENT_INFO* ci);

void print_hex(const char *label, const unsigned char *data, int len) 
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    int server_sock, client_sock;
    struct sockaddr_in sin_server, sin_client;
    socklen_t sin_len;
	pthread_t tid;
	CLIENT_INFO *ci;
	int result;

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    ERR_load_crypto_strings();

    if((server_sock= socket(AF_INET, SOCK_STREAM,0)) == -1)
        exit_sys("socket");
    
    sin_server.sin_family = AF_INET;
    sin_server.sin_port = htons(SERVER_PORT);
    sin_server.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if(bind(server_sock, (struct sockaddr*)&sin_server, sizeof(sin_server)) == -1 )
    {
        exit_sys("bind");
    }

    if(listen(server_sock, 8) == -1)
      exit_sys("listen");  

    printf("waiting for connection\n");
    sin_len = sizeof(sin_client);
    
    for (;;) 
    {   
        client_sock = accept(server_sock, (struct sockaddr*)&sin_client, &sin_len);
        if( client_sock == -1 )
        {
            exit_sys("accept");            
			//exit_sys("send");
        }
        

        if(connectionNum == MAX_CONNECTIONS)
        {  
            printf("Server is busy rejecting connection request.\n");
            
            send(client_sock, "SERVER IS BUSY", 14, 0);
            shutdown(client_sock, SHUT_RDWR);
            close(client_sock);
            continue;
        }
        send(client_sock, "HELLO", 5, MSG_NOSIGNAL);
        connection_num++;
        
        printf("connected client ===> %s:%d\n", inet_ntoa(sin_client.sin_addr), ntohs(sin_client.sin_port));

        if ((ci = (CLIENT_INFO *)malloc(sizeof(CLIENT_INFO))) == NULL) 
        {
			fprintf(stderr, "cannot allocate memory!...\n");
			exit(EXIT_FAILURE);
		}        
         
		ci->sock = client_sock;
		ci->sin = sin_client;

        if ((result = pthread_create(&tid, NULL, client_thread_proc, ci)) != 0) 
        {
			fprintf(stderr, "pthread_create: %s\n", strerror(result));
			exit(EXIT_FAILURE);
		}

		if ((result = pthread_detach(tid)) != 0) 
        {
			fprintf(stderr, "pthread_detach: %s\n", strerror(result));
			exit(EXIT_FAILURE);
		}       
	}    

    shutdown(client_sock, SHUT_RDWR);
    close(server_sock);  
}

void *client_thread_proc(void *param)
{
	char buf[BUFFER_SIZE];
    char decrypted[BUFFER_SIZE+1];
    char send_buf[BUFFER_SIZE];
	char ntopbuf[INET_ADDRSTRLEN];
	unsigned port;
	ssize_t result;
	CLIENT_INFO *ci = (CLIENT_INFO *)param;
    int message_len;
    ssize_t actual_len;
    unsigned char iv[16];
    unsigned char key[32];
    AES_KEY dec_key;
    AES_KEY enc_key;
    msg message;
    msg msg_to_send;
    int send_len;

	inet_ntop(AF_INET, &ci->sin.sin_addr, ntopbuf, INET_ADDRSTRLEN);
	port = (unsigned)ntohs(ci->sin.sin_port);

    if(send_certificate(ci) == -1)
        exit_sys("Cannot send certificate!!");


    if(recv_key(key,iv, ci ) == -1)
        exit_sys("Key Exchange Failed!!");    


    AES_set_decrypt_key(key, 256, &dec_key);
    AES_set_encrypt_key(key, 256, &enc_key);
    
    msg_to_send.cmd = CMD_OK;
    msg_to_send.payload_len = 0;
    

    send_len = create_packet(send_buf, BUFFER_SIZE, &msg_to_send, iv, &enc_key);
    send(ci->sock,send_buf,send_len,MSG_NOSIGNAL);

	for (;;) 
    {   
        if(recv_all(ci->sock, &message_len, sizeof(message_len) ) == -1)
        {
            break;   
        }
        if(recv_all(ci->sock, buf, message_len) == -1)
        {
            break;
        }
        memcpy(iv,buf, AES_BLOCK_SIZE);
        AES_cbc_encrypt(&buf[AES_BLOCK_SIZE], decrypted, message_len-AES_BLOCK_SIZE, &dec_key, iv, AES_DECRYPT);
        actual_len = unpad(decrypted,message_len-AES_BLOCK_SIZE);
        
        if(-1 == actual_len)
            exit_sys("unpad");		

        memcpy(&message.cmd,decrypted,4);
        memcpy(message.payload, decrypted+4, (actual_len-4));
        message.payload_len = actual_len-4;

        if(message.cmd == CMD_PRINT)
        {
            msg_to_send.cmd = CMD_OK;
            msg_to_send.payload_len = 0;
            
            send_len = create_packet(send_buf, BUFFER_SIZE, &msg_to_send, iv, &enc_key);
            send(ci->sock,send_buf,send_len,MSG_NOSIGNAL);
            message.payload[message.payload_len] = '\0';
            printf("%s \n", message.payload);
            
            if (!strcmp(message.payload, "quit"))
			    break;
        }
        else
        {
            msg_to_send.cmd = CMD_NOK;
            msg_to_send.payload_len = 0;
            
            send_len = create_packet(send_buf, BUFFER_SIZE, &msg_to_send, iv, &enc_key);
            send(ci->sock,send_buf,send_len,MSG_NOSIGNAL);
            printf("Unknown Command Received \n");
        }
	}

	printf("client disconnected %s:%u\n", ntopbuf, port);
    
    atomic_fetch_sub(&connection_num, 1);
	
    shutdown(ci->sock, SHUT_RDWR);
	close(ci->sock);

	free(ci);

	return NULL;
}

int send_certificate(CLIENT_INFO* ci)
{
    FILE* fptr;
    size_t f_size = 0;
    char buf[BUFFER_SIZE];
    unsigned int size_of_size_t = (int)sizeof(f_size);
    size_t read_len = 0;
    size_t total_len = 0;

    fptr = fopen(PUB_CER_PATH,"rb");
    if(fptr ==NULL)
    {
        return -1;
    }
    fseek(fptr, 0, SEEK_END);
    f_size = ftell(fptr);
    if(f_size == -1)
    {
        return -1;
    }
    fseek(fptr, 0, SEEK_SET);
    // packet = LEN || FILE_LEN
    memcpy(buf,&size_of_size_t,sizeof(size_of_size_t));
    memcpy(&buf[sizeof(size_of_size_t)],&f_size, size_of_size_t);
    
    if(send(ci->sock, buf, (sizeof(size_of_size_t) + size_of_size_t), MSG_NOSIGNAL) == -1)
    {
        return -1;
    }

    for(;;)
    {
        read_len = fread(buf,sizeof(char),1024,fptr );
        if(send(ci->sock, buf, read_len, MSG_NOSIGNAL) == -1)
        {
            return -1;
        }
        
        total_len += read_len;
        if(total_len == f_size)
            break;
    }
    fclose(fptr);
    return 0;
}


int add_padding(unsigned char*buf,const size_t buf_len )
{
    int padding_len =  16 - (buf_len % 16 );
    /*if(padding_len == 16)
        return buf_len;*/
    
    memset(buf+buf_len, padding_len, padding_len);        

    return buf_len+padding_len;
}

int create_packet(char* buf, const unsigned int buf_size,const msg* message, unsigned char *iv, const AES_KEY* enc_key)
{   
    int padded_len;
    int len=0;
    char ciphertext[BUFFER_SIZE];
    char tmpBuf[BUFFER_SIZE];
    size_t tmp_buf_size;
    
    memcpy(tmpBuf,&message->cmd, 4);
    memcpy(tmpBuf+4, message->payload, message->payload_len );
    tmp_buf_size= 4+ message->payload_len;
    
    padded_len = add_padding(tmpBuf,tmp_buf_size);
    
    if(padded_len > (buf_size-(AES_BLOCK_SIZE+sizeof(len)) ))
    {
        return -1;
    }
    len = padded_len + AES_BLOCK_SIZE;
    memcpy(buf, &len, sizeof(len));
    memcpy(buf+sizeof(len), iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt(tmpBuf, ciphertext, padded_len, enc_key, iv, AES_ENCRYPT);
    // ToDo: Prevent Unnecessary Copy
    memcpy(buf+sizeof(len)+AES_BLOCK_SIZE, ciphertext, padded_len);

    return (padded_len+AES_BLOCK_SIZE+sizeof(len));
}

int recv_key(unsigned char* key,unsigned char* iv, const CLIENT_INFO* ci )
{
    // Load or generate RSA keypair
    RSA *rsa = NULL;
    // load private key from PEM file
    FILE *fp = fopen(PRV_CER_PATH, "r");
    unsigned int message_len = 0;
    int dec_len;
    char buf[BUFFER_SIZE];
    char decrypted[BUFFER_SIZE+1];

    if(PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL) == NULL )
    {
        ERR_print_errors_fp(stderr);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if(recv_all(ci->sock, &message_len, sizeof(message_len) ) == -1)
    {
        return -1;
    }
    if(recv_all(ci->sock, buf, message_len) == -1)
    {
        return -1;
    }
    dec_len = RSA_private_decrypt(message_len, buf, decrypted, rsa, RSA_PKCS1_OAEP_PADDING );

    memcpy(key, decrypted, 32);
    memcpy(iv, decrypted + 32, 16);
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
int unpad(unsigned char* buf, size_t size)

{
    unsigned char padding_value = buf[size - 1];

    // Padding must be between 1 and 16
    if (padding_value < 1 || padding_value > 16) {
        return 0; // No padding detected
    }

    // Check that all padding bytes are correct
    for (int i = 0; i < padding_value; i++) {
        if (buf[size - 1 - i] != padding_value) {
            return 0; // No padding detected
        }
    }

    return size - padding_value;

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




void exit_sys(const char *msg)
{
	perror(msg);

	exit(EXIT_FAILURE);
}
