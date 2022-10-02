#include <iostream>
#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/opensslconf.h>
#include <openssl/hmac.h>

#include "../flags.h"

extern "C" {
    #include <ngx_core.h>
    #include <ngx_config.h>
    #include <ngx_http.h>
};


#define ngx_str_set_v2(str, text)                                               \
    (str)->len = strlen(text); (str)->data = (u_char *) text

int round_robin = 0;
char * batch_buffer;



// PROTOTYPES
void ocall_print_string(const char *str) {printf("%s", str);}

char * ngx_http_upstream_custom_registration(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_http_upstream_custom_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_custom_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_custom_load_balancer_peer(ngx_peer_connection_t *pc, void *data);
void ngx_http_upstream_free_custom_load_balancer_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static ngx_int_t ngx_http_custom_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_custom_handler_init(ngx_conf_t *cf);

int bytes_to_hex(unsigned char * bytes, size_t len, char * hex, bool add_space);
int native_sign_http_request(char * http_request, int request_length, char * decision_u, char * signature_u);

int native_sign_batch_http_request(char * batch_buffer, char * decision_u, char * signature_u);


void print_hex(unsigned char * data, int len){
	for (int i = 0; i < len; i++)
	{
		printf("%02x", data[i]);
	}
	printf("\n");
}



// STRUCT

typedef struct {
	struct sockaddr sockaddr;
	socklen_t socklen;
	char name[32];
} peer_t;

typedef struct {
	int len;
	peer_t * peers;
	unsigned char digest[32];
} peers_list_t;

peers_list_t * peers_ptr;

typedef struct {
    peer_t * peer;
} data_t;

sgx_enclave_id_t global_eid = 0;
EVP_PKEY * private_key;
unsigned char aes_key[64];

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("sgx error %i\n", ret);
        return -1;
    }
    return 0;
}


// Module context
static ngx_http_module_t  ngx_http_custom_load_balancer_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_custom_handler_init,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


// Directive declaration
// https://www.nginx.com/resources/wiki/extending/api/configuration/
static ngx_command_t  ngx_http_custom_load_balancer_commands[] = {
    { ngx_string("truc"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_custom_registration, // registration function
      0,
      0,
      NULL },

      ngx_null_command
};



// Module declaration
// https://www.nginx.com/resources/wiki/extending/api/main/#c-ngx-module-t
ngx_module_t ngx_http_custom_load_balancer_module = {
    NGX_MODULE_V1,
    &ngx_http_custom_load_balancer_module_ctx,      /* module context */
    ngx_http_custom_load_balancer_commands,  /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};


// Registration function
char * ngx_http_upstream_custom_registration(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    printf("registration function\n");

    // Loading client_lib.so for double attestation
    void *handle;
    int (*attest_enclave)(uint64_t);
    peers_list_t * (*get_peers)(void);
    char *error;
    handle = dlopen ("./client_lib.so", RTLD_LAZY);
    if (!handle) {fprintf (stderr, "%s\n", dlerror()); exit(1);}
    dlerror();

    // Link functions from client_lib.so
    attest_enclave = (int (*)(uint64_t)) dlsym(handle, "_Z14attest_enclavem"); //fix this!
    get_peers = (peers_list_t * (*)(void)) dlsym(handle, "get_peers");
    if ((error = dlerror()) != NULL) { fprintf (stderr, "%s\n", error); exit(1); }

    // Initialize enclave
    if(initialize_enclave() < 0) { printf("Failed initializing enclave\n"); exit(1); }

    // Double attestation
    (*attest_enclave)(global_eid);

    // Get private key if no sgx
    if(NO_SGX_FOR_SIG){
    FILE * keyfile = fopen("key.pem", "r");
	RSA * rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    private_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(private_key, rsa);


    if(AES_SIG){
	const char *password = AES_PASSWORD;
	unsigned char iv[EVP_MAX_IV_LENGTH]; memset(iv, 0, EVP_MAX_IV_LENGTH);

	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), NULL,
        (unsigned char *) password,
        (int) strlen(password), 1, aes_key, iv);
	}

    /*
    unsigned char pd[256], pe[4], pmod[256];
	BN_bn2bin(RSA_get0_d(rsa), pd);
	BN_bn2bin(RSA_get0_e(rsa), pe);
	BN_bn2bin(RSA_get0_n(rsa), pmod);
	
	printf("\n d=");
	print_hex(pd, 256);
	printf("\n mod=");
	print_hex(pe, 4);
	printf("\n e=");
	print_hex(pmod, 256);
	printf("\n");
    */
    }

    // Get peers from the lib, then pass it to the enclave
    int signature_verified = -2;
    peers_ptr = get_peers();
    ecall_check_and_store_peers_to_enclave(global_eid, &signature_verified, (void *) peers_ptr);
    if(signature_verified != 0) { printf("Peer List Signature is wrong\n"); exit(1); }



    // Close client_lib.so
    // dlclose(handle);

    // NGINX API to redefine upstream chain
    ngx_http_upstream_srv_conf_t  *uscf;
    uscf = (ngx_http_upstream_srv_conf_t *) ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    uscf->peer.init_upstream = ngx_http_upstream_custom_init;
    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_CONNS
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
 }


// Upstream initialization function
ngx_int_t ngx_http_upstream_custom_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us) {

    printf("upstream initialization function\n");

    if(BATCH_MODE){
        batch_buffer = (char *) malloc(BATCH_SIZE*MAX_REQ_SIZE);
    }

    us->peer.init = ngx_http_upstream_custom_init_peer;

    printf("List of peers:\n");
    for (int i = 0; i < peers_ptr->len; i++) {   
        peer_t * peer = &peers_ptr->peers[i];
        sockaddr_in * addr = (sockaddr_in *) &peer->sockaddr;

        char ip[40];
        inet_ntop(AF_INET, &addr->sin_addr, ip, peer->socklen);
        u_int16_t port = ntohs(addr->sin_port);
        
        printf("    ↳ Peer n°%i:\n", i);
        printf("        ↳ name: %s\n", peers_ptr->peers[i].name);
        printf("        ↳ domain: %s:%i\n", ip, port);
    }
    printf("\n");

    if(NO_SGX_FOR_SIG){
        printf("=> NO SGX FOR SIGNATURE\n");
    }
    if(BATCH_MODE){
        printf("=> BATCHMODE ON (%i)\n", BATCH_SIZE);
    }
    if(EMPTY_ECALL){
        printf("=> EMPTY ECALL (no sig)\n");
    }
    if(NO_ECALL){
        printf("=> NO ECALL (no sig)\n");
    }
    if(AES_SIG){
        printf("=> AES HMAC instead of RSA SIG\n");
    }

    if(PREVENT_LOGGING){
        printf("=> LOGGING DISABLED, this is the last log u'll see.\n");
        close(STDOUT_FILENO);
    }
    
    us->peer.data = peers_ptr;

    return NGX_OK;
}






// Peer initialization function (10µs)
static ngx_int_t ngx_http_upstream_custom_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {

    // Parsing
    peers_list_t * peers = (peers_list_t *) us->peer.data;

    // NGINX API
    r->upstream->peer.free = ngx_http_upstream_free_custom_load_balancer_peer;
    r->upstream->peer.get = ngx_http_upstream_get_custom_load_balancer_peer;
    r->upstream->peer.tries = 1;
    

    // Retrieve enclave's decision
    data_t * data = (data_t *) malloc(sizeof(data_t));

    int headers_len = r->headers_in.headers.part.nelts;
    ngx_table_elt_t * headers = (ngx_table_elt_t*) r->headers_in.headers.part.elts;
    char * decision = (char *) headers[headers_len - 2].value.data;
    // Searching corresponding peer
    data->peer = NULL;
    for (int i = 0; i < peers_ptr->len; i++) {
        peer_t * peer = &peers_ptr->peers[i];
        if(!strcmp(peer->name, decision)){
            data->peer = peer;
            printf("=> Peer n°%i: %s\n",i, peer->name);
        }
    }
    if(data->peer == NULL){printf("Could not find enclave's choosed peer."); exit(1);}

    r->upstream->peer.data = (void *) data;

    return NGX_OK;
}


// Final load balancing redirection (1µs)
static ngx_int_t ngx_http_upstream_get_custom_load_balancer_peer(ngx_peer_connection_t *pc, void *data_r) {

    data_t * data = (data_t *) data_r;
    peer_t * peer = data->peer;


    ngx_str_t * name = (ngx_str_t *) malloc(sizeof(ngx_str_t));
    name->data = (u_char *) &"debug";
    name->len = 6;
    
    //ngx_str_set_v2(&name, peer->name);
    
    pc->sockaddr = &peer->sockaddr;
    pc->socklen  = peer->socklen;
    pc->name     = name;

    return NGX_OK;
}


// After redirection (free memory, maybe do some stats)
void ngx_http_upstream_free_custom_load_balancer_peer(ngx_peer_connection_t *pc, void *data_r, ngx_uint_t state) {
    printf("free\n");

    // Free memory
    data_t * data = (data_t *) data_r;
    free(data);

    pc->tries = 0;

    // Stats
}


// Handler init (1µs)
static ngx_int_t ngx_http_custom_handler_init(ngx_conf_t *cf){

    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt       *h;
    cmcf = (ngx_http_core_main_conf_t *) ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = (ngx_http_handler_pt *) ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    *h = ngx_http_custom_handler;  

    return NGX_OK;
}

// Handler (10ms)
int counter = 0;
static ngx_int_t ngx_http_custom_handler(ngx_http_request_t *r) {

    //struct timeval stop, start;
    //gettimeofday(&start, NULL);

    // This function is called at the very beginning of the request processing chain, 
    // it allows to add new headers in the request
    printf("Handling...\n");


    // Data to sign
    char http_request[MAX_REQ_SIZE] = {'\0'};
    if(!EMPTY_ECALL){
    
    // Extract cookie header value
    ngx_str_t * cookie = NULL;
    ngx_table_elt_t * headers = ((ngx_table_elt_t *) r->headers_in.headers.part.elts);
    for (size_t i = 0; i < r->headers_in.headers.part.nelts; i++) {
        if(strcmp((char *) headers[i].key.data, "Cookie") == 0){
            cookie = &headers[i].value;
            break;
        }
    }


    // Extract Method and URI, then building http_request
    strncpy(http_request, (char *) r->method_name.data, r->method_name.len);
    strcat(http_request, " ");
    strncat(http_request, (char *) r->uri_start, r->uri_end - r->uri_start);
    strcat(http_request, " ");
    if(cookie != NULL) strncat(http_request, (char *) cookie->data, cookie->len);
    strcat(http_request, " ");

    }


    // For debugging purposes
    //printf("http_request = <%s>\n", http_request);


    // The enclave makes the decision, then sign <http request,decision>
    // then return the decision and the signature
    char * decision = (char *) ngx_pnalloc(r->pool,MAX_LENGTH_DECISION); memset(decision, 0, MAX_LENGTH_DECISION);
    char signature[SIGNATURE_LENGTH]; memset(signature, 0, SIGNATURE_LENGTH);
    int e = 0;

    #if BATCH_MODE
        if( (counter/peers_ptr->len) == (BATCH_SIZE - 1) ){
            printf("BATCH SIGNATURE %i\n", counter);
            #if NO_SGX_FOR_SIG
                native_sign_http_request(http_request, strlen(http_request), decision, signature);
            #else
                ecall_sign_http_request(global_eid, &e, http_request, strlen(http_request), decision, signature);
            #endif
        } else {
            printf("BATCH NOSIG %i\n", counter);
            strcpy(decision, peers_ptr->peers[round_robin].name);
            round_robin = (round_robin+1) % peers_ptr->len;
        }
        counter++;
        counter = counter % (peers_ptr->len*BATCH_SIZE);
    #elif NO_SGX_FOR_SIG
        native_sign_http_request(http_request, strlen(http_request), decision, signature);
    #elif EMPTY_ECALL || NO_ECALL
        strcpy(decision, peers_ptr->peers[round_robin].name);
        round_robin = (round_robin+1) % peers_ptr->len;

        #if !NO_ECALL
        ecall_empty(global_eid);
        #endif
    #else
        // SIG IN ENCLAVE HERE
        ecall_sign_http_request(global_eid, &e, http_request, strlen(http_request), decision, signature);
    #endif

    
    // Currently in HEX, should be upgraded to BASE64
    char * signature_hex = (char *) ngx_pnalloc(r->pool,2*SIGNATURE_LENGTH + 1); memset(signature_hex, 0, 2*SIGNATURE_LENGTH+1);
    bytes_to_hex((unsigned char *) signature, SIGNATURE_LENGTH, signature_hex, false);
    
    printf("d=<%s>\ns=<%s>\ne=%i\n", decision, signature_hex, e);

    // Adding the corresponding headers (pls factorize this)
    
    ngx_table_elt_t * decision_header = (ngx_table_elt_t *) ngx_list_push(&r->headers_in.headers);
    decision_header->hash = 1;
    ngx_str_set(&decision_header->key, "X-Decision");
    ngx_str_set_v2(&decision_header->value, decision);
    decision_header->lowcase_key = (u_char *) ngx_pnalloc(r->pool, decision_header->key.len);
    ngx_strlow(decision_header->lowcase_key, decision_header->key.data, decision_header->key.len);

    ngx_table_elt_t * signature_header = (ngx_table_elt_t *) ngx_list_push(&r->headers_in.headers);
    signature_header->hash = 1;
    ngx_str_set(&signature_header->key, "X-Signature");
    ngx_str_set_v2(&signature_header->value, signature_hex);
    signature_header->lowcase_key = (u_char *) ngx_pnalloc(r->pool, signature_header->key.len);
    ngx_strlow(signature_header->lowcase_key, signature_header->key.data, signature_header->key.len);

    ngx_list_part_t * part = &r->headers_in.headers.part;

    //gettimeofday(&stop, NULL);
    //printf("duration %ldµs\n", (stop.tv_sec * 1000000 + stop.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));

    return NGX_DECLINED;
}

// hex should be 2*len+1 or 3*len+1 (depending of add_space)
int bytes_to_hex(unsigned char * bytes, size_t len, char * hex, bool add_space){
    for (size_t i = 0; i < len; i++){
        char c[3];
        snprintf(c, 3, "%02x", bytes[i]);
        if(add_space) strcat(hex, " ");
        strcat(hex, c);
    }
    return 0;
}



// (3ms)
int native_sign_http_request(char * http_request, int request_length, char * decision_u, char * signature_u){

	// DECISION
	strcpy(decision_u, peers_ptr->peers[round_robin].name);
	round_robin = (round_robin+1) % peers_ptr->len;

	uint8_t signature[1024];

    size_t siglen;
    #if AES_SIG
		HMAC_CTX * ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, aes_key, SIGNATURE_LENGTH, EVP_sha256(), NULL);
		HMAC_Update(ctx, (const unsigned char *) http_request, request_length);
		HMAC_Update(ctx, (const unsigned char *) decision_u, (int) strlen(decision_u));
		HMAC_Final(ctx, (unsigned char *) signature, (unsigned int *) &siglen);
		HMAC_CTX_free(ctx);
	#else
		EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
		EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key);
		EVP_DigestSignUpdate(md_ctx, (const uint8_t *) http_request, (int) strlen(http_request));
		EVP_DigestSignUpdate(md_ctx, (const uint8_t *) decision_u, (int) strlen(decision_u));
		int e = EVP_DigestSignFinal(md_ctx, (unsigned char *) signature, &siglen);
		EVP_MD_CTX_free(md_ctx);
        //char buf[256];
	    //ERR_error_string(ERR_get_error(), buf);
	    //printf("error = %i, %s\n", e, buf);
	#endif
    printf("siglen=%li\n", siglen);
	
	memcpy(signature_u, signature, SIGNATURE_LENGTH);

	return 1;
}





int native_sign_batch_http_request(char * batch_buffer, char * decision_u, char * signature_u){
	char decision[32] = {'\0'};

	// DECISION
	strcpy(decision, peers_ptr->peers[round_robin].name);
	round_robin = (round_robin+1) % peers_ptr->len;

	//sgx_ecdsa_sign better, maybe later
	uint8_t signature[SIGNATURE_LENGTH];

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);

    size_t siglen;
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key);

    for (int i = 0; i < BATCH_SIZE; i++){
        const char * buf_ptr = batch_buffer + i*MAX_REQ_SIZE;
        EVP_DigestSignUpdate(md_ctx, buf_ptr, (int) strlen(buf_ptr));
    }
    EVP_DigestSignUpdate(md_ctx, (const uint8_t *) decision, (int) strlen(decision));
    EVP_DigestSignFinal(md_ctx, signature, &siglen);

    EVP_MD_CTX_free(md_ctx);
	
	memcpy(signature_u, signature, SIGNATURE_LENGTH);
	memcpy(decision_u, decision, 32);

	return 1;


}