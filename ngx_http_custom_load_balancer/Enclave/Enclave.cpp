/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef _WIN32
#include "../config.h"
#endif
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <sgx_utils.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include "../flags.h"

#include <assert.h>
#include <cstdio>
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif
int printf(const char* fmt, ...);
#if defined(__cplusplus)
}
#endif

uint8_t nonce[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
sgx_ra_key_128_t session_key;
EVP_PKEY * private_key;

unsigned char aes_key[64];


int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void print_hex(unsigned char * data, int len){
	for (int i = 0; i < len; i++)
	{
		printf("%02x", data[i]);
	}
	printf("\n");
}

typedef struct _ra_msg5_t
{
	uint32_t id;
    char log[128];
	uint8_t serialized_private_key[2048];
	int serialized_len;
} sgx_ra_msg5_t;


int ecall_decrypt_msg5(void * encrypted_data, int len){
	sgx_ra_msg5_t decrypted_data;

	sgx_aes_ctr_decrypt(&session_key, (const uint8_t *) encrypted_data, (int) len, nonce, 128, (uint8_t *) &decrypted_data);

	// Store the provisioned private_key
	private_key = EVP_PKEY_new();

	unsigned char * serialkey = (unsigned char *) OPENSSL_malloc(2048);
	memcpy(serialkey, decrypted_data.serialized_private_key, decrypted_data.serialized_len);

	//print_hex((unsigned char *) decrypted_data.serialized_private_key, decrypted_data.serialized_len);

	#if AES_SIG
		const char *password = AES_PASSWORD;
		unsigned char iv[EVP_MAX_IV_LENGTH]; memset(iv, 0, EVP_MAX_IV_LENGTH);
		EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), NULL,
			(unsigned char *) password,
			(int) strlen(password), 1, aes_key, iv);
		printf("\nAES KEY 256 bits\n");
	#else
		RSA * rsa;
		d2i_RSAPrivateKey(&rsa, (const unsigned char **) &serialkey, decrypted_data.serialized_len);
    	EVP_PKEY_assign_RSA(private_key, rsa);
		printf("\n RSA KEY %i bits (%i bytes serialized)\n", RSA_size(rsa)*8, decrypted_data.serialized_len);
	#endif

	/*
	//DEBUG
	unsigned char pd[256], pe[4], pmod[256];
	BN_bn2bin(RSA_get0_d(rsa), pd);
	BN_bn2bin(RSA_get0_e(rsa), pe);
	BN_bn2bin(RSA_get0_n(rsa), pmod);
	
	printf("\nenc d=");
	print_hex(pd, 256);
	printf("\nenc mod=");
	print_hex(pe, 4);
	printf("\nenc e=");
	print_hex(pmod, 256);
	printf("\n");
	*/

	// just for debug, may cause security issue
	printf("decrypted_log=<%s>\n",decrypted_data.log);

	return 0;
}

struct sockaddr {
	char sa_data[14];
};

typedef struct {
	struct sockaddr sockaddr;
	unsigned int socklen;
	char name[32];
} peer_t;

typedef struct {
	int len;
	peer_t * peers;
	unsigned char digest[32];
} peers_list_t;

peers_list_t peers_trusted;
int round_robin = 0;

// Homemade Implementations
char * strcat(char * dest, const char * src){strncpy(dest+strlen(dest), src, strlen(src)+1);return dest;}

char * strcpy(char * dest, const char * src){strncpy(dest, src, strlen(src)+1); return dest;}

int bytes_to_hex(unsigned char * bytes, size_t len, char * hex, bool add_space){
    for (size_t i = 0; i < len; i++){
        char c[3];
        snprintf(c, 3, "%02x", bytes[i]);
        if(add_space) strcat(hex, " ");
        strcat(hex, c);
    }
    return 0;
}

int a = 0;
void ecall_empty(){
	a = (a + 1) % 2;
	printf("empty ecall\n");
}


int ecall_check_and_store_peers_to_enclave(void * ptr){
	// Check HMAC
	peers_list_t * peers_ptr_u= (peers_list_t *) ptr;
	unsigned char digest_u[SGX_SHA256_HASH_SIZE];
	sgx_hmac_sha256_msg((unsigned char *) peers_ptr_u->peers, (peers_ptr_u->len * (int) sizeof(peer_t)), session_key, 16, digest_u, SGX_SHA256_HASH_SIZE);
	
	if(!memcmp(digest_u, peers_ptr_u->digest, SGX_SHA256_HASH_SIZE)){
		// if HMAC valid
		// Copy to `peers` global var
		peers_trusted.len = peers_ptr_u->len;
		memcpy(peers_trusted.digest, peers_ptr_u->digest, SGX_SHA256_HASH_SIZE);
		peers_trusted.peers = (peer_t *) malloc(peers_ptr_u->len * (int) sizeof(peer_t));
		memcpy(peers_trusted.peers, peers_ptr_u->peers, peers_trusted.len * (int) sizeof(peer_t));
		return 0;
	}
	return -1; 
}



char * buffer = (char *) malloc(6160 * 10);

int ecall_sign_http_request(char * http_request, int request_length, char * decision_u, char * signature_u){

	// DECISION
	strcpy(decision_u, peers_trusted.peers[round_robin].name);
	int decision_len = (int) strlen(decision_u);
	round_robin = (round_robin+1) % peers_trusted.len;

	
	int e = 0;
	uint8_t signature[1024];
    size_t siglen;

	#if AES_SIG
		HMAC_CTX * ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, aes_key, SIGNATURE_LENGTH, EVP_sha256(), NULL);
		HMAC_Update(ctx, (const unsigned char *) http_request, request_length);
		HMAC_Update(ctx, (const unsigned char *) decision_u, decision_len);
		e = HMAC_Final(ctx, (unsigned char *) signature, (unsigned int *) &siglen);
		HMAC_CTX_free(ctx);
	#else
		//sgx_ecdsa_sign better, maybe later
		EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
		EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key);
		EVP_DigestSignUpdate(md_ctx, http_request, request_length);
		EVP_DigestSignUpdate(md_ctx, decision_u, decision_len);
		e = EVP_DigestSignFinal(md_ctx, (unsigned char *) signature, &siglen);
		EVP_MD_CTX_free(md_ctx);
	#endif
   
	#if PREVENT_LOGGING
	char buf[256];
	ERR_error_string(ERR_get_error(), buf);
	printf("error = %i, %s\n", e, buf);
	#endif

	memcpy(signature_u, signature, SIGNATURE_LENGTH);
	return e;
}









#define BATCH_SIZE       10
#define MAX_REQ_SIZE     6160

int ecall_sign_batch_http_request(char * batch_buffer, char * decision_u, char * signature_u){
	char decision[MAX_LENGTH_DECISION] = {'\0'};

	// DECISION
	strcpy(decision, peers_trusted.peers[round_robin].name);
	round_robin = (round_robin+1) % peers_trusted.len;

	int w_len = 0; int total_w_len = 0;
	char concat_data_to_hash[BATCH_SIZE*MAX_REQ_SIZE + MAX_LENGTH_DECISION + 1] = {'\0'};
	for (size_t i = 0; i < BATCH_SIZE; i++)
	{
		char * current_ptr = batch_buffer + i*MAX_REQ_SIZE;
		w_len = (int) strlen(current_ptr);
		memcpy(concat_data_to_hash+total_w_len, current_ptr, w_len);
		total_w_len+=w_len;
	}

	memcpy(concat_data_to_hash+total_w_len, decision, strlen(decision));

	//sgx_ecdsa_sign better, maybe later
	sgx_rsa3072_signature_t signature;

	int e = 0;
	//e = sgx_rsa3072_sign((const uint8_t *) concat_data_to_hash, (int) strlen(concat_data_to_hash), &private_key, &signature);
	
	memcpy(signature_u, signature, SIGNATURE_LENGTH);
	memcpy(decision_u, decision, 32);

	return e;
}




static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, NULL, report);
#else
	return sgx_create_report(target_info, NULL, report);
#endif
}

#ifdef _WIN32
size_t get_pse_manifest_size ()
{
	return sizeof(sgx_ps_sec_prop_desc_t);
}

sgx_status_t get_pse_manifest(char *buf, size_t sz)
{
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;

	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));

	sgx_close_pse_session();

	return status;
}
#endif

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

#ifdef _WIN32
	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_close_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}
#else
	ra_status= sgx_ra_init(&key, 0, ctx);
#endif

	return ra_status;
}

sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx,
	sgx_status_t *pse_status)
{
	return enclave_ra_init(def_service_public_key, b_pse, ctx, pse_status);
}

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);

	char hex_key[33] = {'\0'};
	for (size_t i = 0; i < 16; i++)
		snprintf(hex_key, 35, "%s%02x",hex_key, k[i]);
	if(type == SGX_RA_KEY_SK){
		// Keep commented ! Only for debug, cause huge security issue
		// printf("session key = <%s>\n", hex_key);

		memcpy(session_key, k, sizeof(k));
	} else if(type == SGX_RA_KEY_MK){
		// Keep commented ! Only for debug, cause huge security issue
		//printf("masking key = <%s>\n", hex_key);
	}
	
	
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	/* Now generate a SHA hash */

	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sigh.

	/* Let's be thorough */

	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}