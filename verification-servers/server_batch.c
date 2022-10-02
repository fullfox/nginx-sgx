#include "server_common.h"

#include <time.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include <semaphore.h>

#define LOGGING         1
#define LOG_REQ         0

#define BACKLOG         10000
#define KEY_LENGTH      256
#define MAX_REQ_SIZE    8192

int buffer_size = 10;
int buffer_i = 0;

#define AES_PASSWORD    "tortue"

long counter = 0;

// Proto
int analyse(char * req);
void * process_request(void * arg);


EVP_PKEY * public_key;
RSA * rsa;
unsigned char aes_key[32];

pthread_mutex_t lock;
sem_t buffer_lock;

void print_hex(unsigned char * data, int len){
	for (int i = 0; i < len; i++)
	{
		printf("%02x", data[i]);
	}
	printf("\n");
}

int main(int argc, char const *argv[]){

    if(argc < 2 || argc > 3){printf("Usage: ./server [port] [buffer_size]\n"); exit(1);}
    int s = atoi(argv[2]);
    if(s > 0)
        buffer_size = s;
    printf("buffer_size = %i\n", buffer_size);

    #if PING
        printf("PING mode\n");
    #elif AES_SIG
        printf("AES 256bits mode\n");
        const char *password = AES_PASSWORD;
        unsigned char iv[EVP_MAX_IV_LENGTH]; memset(iv, 0, EVP_MAX_IV_LENGTH);
        EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), NULL,
            (unsigned char *) password,
            (int) strlen(password), 1, aes_key, iv);
    #else
        printf("RSA 2048bits mode\n");
        public_key = EVP_PKEY_new();
        FILE * pkey_file = fopen("public.pem", "r");
        rsa = PEM_read_RSA_PUBKEY(pkey_file, NULL, NULL, NULL);
        EVP_PKEY_assign_RSA(public_key, rsa);
	#endif



    int yes = 1;
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[1]));
    addr.sin_addr.s_addr = INADDR_ANY;

    char ip4[40];
    bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));   
    inet_ntop(addr.sin_family, &((struct sockaddr_in * ) &addr)->sin_addr, ip4, INET_ADDRSTRLEN);
    printf("debug %s\n", ip4);

    // Listen
    if( listen(sockfd, BACKLOG) ){ printf("Could not listen.\n"); return -1;}
    printf("Listening...\n");

    pthread_mutex_init( &lock, NULL);    
    sem_init(&buffer_lock, 1, 0);
    while (1) {

        struct sockaddr addr_client;
        socklen_t addr_client_socklen;
        
        pthread_t thread_id;

        int * sockclient = malloc(sizeof(int));
        *sockclient = accept(sockfd, &addr_client, &addr_client_socklen);
        //printf("Client accepted...  \n");
        int err = pthread_create(&thread_id, NULL, process_request, (void *) sockclient);
        pthread_detach(thread_id);
        if(err != 0){printf("%i\n", err);}     
    }
    

    close(sockfd);
}






void * process_request(void * arg){
    int sockclient = *((int *) arg);

    struct timeval stop, start, delta;
    gettimeofday(&start, NULL);
    //------------------
        char c, req[MAX_REQ_SIZE] = {'\0'};
        int req_len = 0;

        while (recv(sockclient, &c, 1, 0) > 0) {
            req[req_len++] = c;
            #if LOG_REQ
            printf("%c",c);
            #endif
            if(strcmp(req+req_len-4, "\r\n\r\n") == 0)
                break;
        }

        pthread_mutex_lock(&lock);
        buffer_i = (buffer_i+1) % buffer_size;

        if(buffer_i == 0){
            //Sig
            #if LOGGING
            printf("n%i unlock\n", buffer_i);
            #endif
            pthread_mutex_unlock(&lock);

            for (size_t i = 0; i < buffer_size; i++)
                sem_post(&buffer_lock);
        } else {
            #if LOGGING
            printf("n%i lock\n", buffer_i);
            #endif
            pthread_mutex_unlock(&lock);

            sem_wait(&buffer_lock);
        }
        

        int code = analyse(req);

        // Response
        char resp[1024];
        char log[100];
        if(code == 0) {
            sprintf(log, "200 OK: \033[0;32mSucessfully verified packet !\033[0m");
            generate_http_response(resp, "OK 200: Sucessfully verified packet !", "200 OK");
            
        } else if(code == -2) {
            sprintf(log, "401 Unauthorized: \033[0;31mFailed verifying packet, wrong signature.\033[0m");
            generate_http_response(resp, "401 Unauthorized: Failed verifying packet, wrong signature.", "401 Unauthorized");
        } else if(code == -3) {
            sprintf(log, "PING");
            generate_http_response(resp, "ping", "200 OK");
        } else {
            sprintf(log, "400 Bad Request: \033[0;31mFailed parsing packet\033[0m");
            generate_http_response(resp, "400 Bad Request: Failed parsing packet", "400 Bad Request");
        }
        
        send_safe(sockclient, resp, strlen(resp), 0);
    //------------------
    gettimeofday(&stop, NULL);
    timersub(&stop, &start, &delta);

    #if LOGGING
    pthread_mutex_lock(&lock);
    printf("%s [ done (%i bytes), took %.2lfms ]\n", log, req_len, (double) delta.tv_sec*1000 + (double) delta.tv_usec/1000);
    printf("c %ld\n", counter++);
    pthread_mutex_unlock(&lock);
    #endif

    close(sockclient);
    free(arg);

    pthread_exit(NULL);
}












int analyse(char * req){
    // may crash if req is not a correct http packet

    #if PING
    return -3;
    #endif

    if(strlen(req) == 0)
        return -1;

    
    
    char method[8] = {'\0'};
    if(retrieve_method(req, method) == -1) return -1;
    
    char uri[2048] = {'\0'};
    if(retrieve_uri(req, uri) == -1) return -1;

    char cookie[2048] = {'\0'};
    retrieve_header_value(req, "Cookie:", cookie);
    
    char decision[32] = {'\0'};
    if(retrieve_header_value(req, "X-Decision:", decision) == -1) return -1;

    char signature[2048] = {'\0'};
    if(retrieve_header_value(req, "X-Signature:", signature) == -1) return -1;

    
    

    char data[2048 + 2048 + 32 + 8 + 1] = {'\0'};
    sprintf(data, "%s %s %s %s", method, uri, cookie, decision);

    unsigned char signature_bytes[KEY_LENGTH];
    hex_to_bytes(signature_bytes, signature);

    int res;
    #if AES_SIG
        unsigned char hmac[32];
        int siglen;
        HMAC_CTX * ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, aes_key, 32, EVP_sha256(), NULL);
		HMAC_Update(ctx, (const unsigned char *) data, strlen(data));
		HMAC_Final(ctx, hmac, (unsigned int *) &siglen);
		HMAC_CTX_free(ctx);
        res = (CRYPTO_memcmp(signature_bytes, hmac, 32) == 0);

    #else
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        EVP_MD_CTX_init(md_ctx);

        EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), EVP_PKEY_get0_engine(public_key), public_key);
        EVP_DigestVerifyUpdate(md_ctx, data, strlen(data));
        res = EVP_DigestVerifyFinal(md_ctx, signature_bytes, KEY_LENGTH);
        EVP_MD_CTX_free(md_ctx);
    #endif

    if(res == 1) return 0;
    return -2;
}