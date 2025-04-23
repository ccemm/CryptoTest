#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define SERVER_PORT 55555
#define BUFFER_SIZE 4096


const char* key_string = "f0edeccfa143a5b61e1998606f71b9710216ac7d8a1830b1236eed60e2747a43";
const char* iv_string  = "edd98e3918bfab446883c42cce292e22";

void exit_sys(const char *msg);
int hex_char_to_int(char c) ;
int hexstr_to_bytes(const char *hexstr, unsigned char *out, size_t out_len);
int unpad(unsigned char* buf, size_t size);


int main(void)
{
    int server_sock, client_sock;
    struct sockaddr_in sin_server, sin_client;
    socklen_t sin_len;
    char buf[BUFFER_SIZE+1];
    char decrypted[BUFFER_SIZE+1];
    ssize_t padded_len;
    ssize_t actual_len;
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY dec_key;

    hexstr_to_bytes(key_string,key, sizeof(key));
    hexstr_to_bytes(iv_string, iv, sizeof(iv));
    AES_set_decrypt_key(key, 256, &dec_key);


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
    
    client_sock = accept(server_sock, (struct sockaddr*)&sin_client, &sin_len);
    if( client_sock == -1 )
    {
        printf("%d \n", client_sock);
        exit_sys("accept");
    }
    printf("connected client ===> %s:%d\n", inet_ntoa(sin_client.sin_addr), ntohs(sin_client.sin_port));

    for (;;) 
    {
		if ((padded_len = recv(client_sock, buf, BUFFER_SIZE, 0)) == -1)
			exit_sys("recv");
		if (padded_len == 0)
			break;
        
        AES_cbc_encrypt(buf, decrypted, padded_len, &dec_key, iv, AES_DECRYPT);
        
        actual_len = unpad(decrypted,padded_len);
        if(-1 == actual_len)
            exit_sys("unpad");		

        decrypted[actual_len] = '\0';
		if (!strcmp(decrypted, "quit"))
			break;
		printf("%ld byte(s) received: \"%s\"\n", actual_len, decrypted);
	}    


    shutdown(client_sock, SHUT_RDWR);
    close(client_sock);

    close(server_sock);  

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
