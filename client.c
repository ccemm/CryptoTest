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

#define SERVER_ADRESS	"127.0.0.1"
#define SERVER_PORT		55555
#define BUFFER_SIZE		4096

const char* key_string = "f0edeccfa143a5b61e1998606f71b9710216ac7d8a1830b1236eed60e2747a43";
const char* iv_string  = "edd98e3918bfab446883c42cce292e22";

void exit_sys(const char *msg);
int hex_char_to_int(char c) ;
int hexstr_to_bytes(const char *hexstr, unsigned char *out, size_t out_len);

int add_padding(unsigned char*buf,size_t buf_len )
{
    int padding_len =  16 - (buf_len % 16 );
    if(padding_len == 16)
        return buf_len;
    
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

int main(void)
{
    int client_sock;
    struct sockaddr_in sin_server;
    struct hostent* hent;
    char buf[BUFFER_SIZE];
    char ciphertext[BUFFER_SIZE];
    char *str;
    size_t padded_len;
    int string_len;
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];
    AES_KEY enc_key;
            
    hexstr_to_bytes(key_string,key, sizeof(key));
    hexstr_to_bytes(iv_string, iv, sizeof(iv));
    AES_set_encrypt_key(key, 256, &enc_key);
    

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

        if(connect(client_sock,(struct sockaddr*)&sin_server, sizeof(sin_server)) == -1)
            exit_sys("coonect"); 
 

        for (;;) 
        {
		    printf("csd>");
		    fflush(stdout);

		    if (fgets(buf, BUFFER_SIZE, stdin) == NULL)
			    continue;
		    if ((str = strchr(buf, '\n')) != NULL)
			    *str = '\0';
            
            string_len= strlen(buf);            

            padded_len = add_padding(buf,string_len);

            AES_cbc_encrypt(buf, ciphertext, padded_len, &enc_key, iv, AES_ENCRYPT);

            print_hex("Ciphertext", ciphertext, padded_len);                     

		    if (send(client_sock, ciphertext, padded_len, MSG_NOSIGNAL) == -1)
			    exit_sys("send");
		   
            buf[string_len] = '\0';
            printf("%s \n", buf);  
            if (!strcmp(buf, "quit"))
			    break;
	    }

	shutdown(client_sock, SHUT_RDWR);
	close(client_sock);

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



void exit_sys(const char *msg)
{
	perror(msg);

	exit(EXIT_FAILURE);
}
