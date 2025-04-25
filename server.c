#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdatomic.h>

#define SERVER_PORT 55555
#define BUFFER_SIZE 4096
#define MAX_CONNECTIONS 3

const char* g_key_string = "f0edeccfa143a5b61e1998606f71b9710216ac7d8a1830b1236eed60e2747a43";
const char* g_iv_string  = "edd98e3918bfab446883c42cce292e22";
unsigned char g_key[32];
AES_KEY g_dec_key;


void *client_thread_proc(void *param);
void exit_sys(const char *msg);
int hex_char_to_int(char c) ;
int hexstr_to_bytes(const char *hexstr, unsigned char *out, size_t out_len);
int unpad(unsigned char* buf, size_t size);
int connectionNum = 0;


typedef struct tagCLIENT_INFO {
	int sock;
	struct sockaddr_in sin;
} CLIENT_INFO;



int main(void)
{
    int server_sock, client_sock;
    struct sockaddr_in sin_server, sin_client;
    socklen_t sin_len;
	pthread_t tid;
	CLIENT_INFO *ci;
	int result;
    
    hexstr_to_bytes(g_key_string,g_key, sizeof(g_key));
    AES_set_decrypt_key(g_key, 256, &g_dec_key);


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
            printf("%d \n", client_sock);
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
        send(client_sock, "HELLO", 5, 0);
        connectionNum++;
        printf("%d\n", connectionNum);
        
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
    close(client_sock);

    close(server_sock);  

}

void *client_thread_proc(void *param)
{
	char buf[BUFFER_SIZE+1];
    char decrypted[BUFFER_SIZE+1];
	char ntopbuf[INET_ADDRSTRLEN];
	unsigned port;
	ssize_t result;
	CLIENT_INFO *ci = (CLIENT_INFO *)param;
    int message_len;
    ssize_t actual_len;
    unsigned char iv[16];

	inet_ntop(AF_INET, &ci->sin.sin_addr, ntopbuf, INET_ADDRSTRLEN);
	port = (unsigned)ntohs(ci->sin.sin_port);

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
        
        AES_cbc_encrypt(&buf[AES_BLOCK_SIZE], decrypted, message_len-AES_BLOCK_SIZE, &g_dec_key, iv, AES_DECRYPT);
        
        actual_len = unpad(decrypted,message_len-AES_BLOCK_SIZE);
        
        if(-1 == actual_len)
            exit_sys("unpad");		

        decrypted[actual_len] = '\0';
		if (!strcmp(decrypted, "quit"))
			break;
		printf("%ld byte(s) received: \"%s\"\n", actual_len, decrypted);
        
		//if (send(ci->sock, buf, result, 0) 1== -1)
			//exit_sys("send");
	}

	printf("client disconnected %s:%u\n", ntopbuf, port);
    
    atomic_fetch_sub(&connectionNum, 1);
	
    shutdown(ci->sock, SHUT_RDWR);
	close(ci->sock);

	free(ci);

	return NULL;
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
    int len_of_padding = buf[size-1];
    if(len_of_padding <= 0)
        return -1;
    
    return size-len_of_padding;
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
