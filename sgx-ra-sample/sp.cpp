/*

Copyright 2019 Intel Corporation

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
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <intrin.h>
#include <openssl/applink.c>
#include "win32/getopt.h"
#else
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_key_exchange.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <sgx_tcrypto.h>

#include "json.hpp"
#include "common.h"
#include "hexutil.h"
#include "fileio.h"
#include "crypto.h"
#include "byteorder.h"
#include "msgio.h"
#include "protocol.h"
#include "base64.h"
#include "iasrequest.h"
#include "logfile.h"
#include "settings.h"
#include "enclave_verify.h"


using namespace json;
using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
#define strdup(x) _strdup(x)
#endif


#define KEY_LENGTH        256
static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

void hex_encode(char * hex_str, unsigned char * bytes, int len){
	strcpy(hex_str,"");
	for (int i = 0; i < len; i++){
		char hex[3] = {'\0'};
		sprintf(hex, "%02x", bytes[i]);
		strcat(hex_str, hex);
	}
}

void hex_decode(unsigned char * bytes, const char * hex_str){
    int i;
    for (i = 0; i < strlen(hex_str); i+=2){
        char hex[3] = {'\0'};
        strncpy(hex, hex_str+i, 2);
        bytes[i/2] = (unsigned char) strtol(hex, NULL, 16);
    }
}

void print_hex(unsigned char * data, int len);
void print_hex(unsigned char * data, int len){
	for (int i = 0; i < len; i++)
	{
		printf("%02x", data[i]);
	}
	printf("\n");
}



typedef struct ra_session_struct {
	unsigned char g_a[64];
	unsigned char g_b[64];
	unsigned char kdk[16];
	unsigned char smk[16];
	unsigned char sk[16];
	unsigned char mk[16];
	unsigned char vk[16];
} ra_session_t;

typedef struct config_struct {
	sgx_spid_t spid;
	unsigned char pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE+1];
	unsigned char sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE+1];
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	char *proxy_server;
	char *ca_bundle;
	char *user_agent;
	unsigned int proxy_port;
	unsigned char kdk[16];
	X509_STORE *store;
	X509 *signing_ca;
	unsigned int apiver;
	int strict_trust;
	sgx_measurement_t req_mrsigner;
	sgx_prod_id_t req_isv_product_id;
	sgx_isv_svn_t min_isvsvn;
	int allow_debug_enclave;
} config_t;


void usage();
#ifndef _WIN32
void cleanup_and_exit(int signo);
#endif

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a,
	config_t *config);

int process_msg01 (MsgIO *msg, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config,
	ra_session_t *session);

int process_msg3 (MsgIO *msg, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config, ra_session_t *session);

int process_msg5(MsgIO *msg, IAS_Connection *ias, char **sigrl, config_t *config, ra_session_t *session);
void load_private_key(unsigned char * prikey);
void reverse_str(int len,uint8_t *str);

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sigrl, uint32_t *msg2);

int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, sgx_ps_sec_prop_desc_t sec_prop, ra_msg4_t *msg4,
	int strict_trust);

int get_proxy(char **server, unsigned int *port, const char *url);

char debug = 0;
char verbose = 0;
/* Need a global for the signal handler */
MsgIO *msgio = NULL;

int main(int argc, char *argv[])
{
	char flag_spid = 0;
	char flag_pubkey = 0;
	char flag_api_key = 0;
	char flag_ca = 0;
	char flag_usage = 0;
	char flag_noproxy= 0;
	char flag_prod= 0;
	char flag_stdio= 0;
	char flag_isv_product_id= 0;
	char flag_min_isvsvn= 0;
	char flag_mrsigner= 0;
	char *sigrl = NULL;
	config_t config;
	int oops;
	IAS_Connection *ias= NULL;
	char *port= NULL;
#ifndef _WIN32
	struct sigaction sact;
#endif

	/* Command line options */

	static struct option long_opt[] =
	{
		{"ias-signing-cafile",		required_argument,	0, 'A'},
		{"ca-bundle",				required_argument,	0, 'B'},
		{"no-debug-enclave",		no_argument,		0, 'D'},
		{"list-agents",				no_argument,		0, 'G'},
		{"ias-pri-api-key-file",	required_argument,	0, 'I'},
		{"ias-sec-api-key-file",	required_argument,	0, 'J'},
		{"service-key-file",		required_argument,	0, 'K'},
		{"mrsigner",				required_argument,  0, 'N'},
		{"production",				no_argument,		0, 'P'},
		{"isv-product-id",			required_argument,	0, 'R'},
		{"spid-file",				required_argument,	0, 'S'},
		{"min-isv-svn",				required_argument,  0, 'V'},
		{"strict-trust-mode",		no_argument,		0, 'X'},
		{"debug",					no_argument,		0, 'd'},
		{"user-agent",				required_argument,	0, 'g'},
		{"help",					no_argument, 		0, 'h'},
		{"ias-pri-api-key",			required_argument,	0, 'i'},
		{"ias-sec-api-key",			required_argument,	0, 'j'},
		{"key",						required_argument,	0, 'k'},
		{"linkable",				no_argument,		0, 'l'},
		{"proxy",					required_argument,	0, 'p'},
		{"api-version",				required_argument,	0, 'r'},
		{"spid",					required_argument,	0, 's'},
		{"verbose",					no_argument,		0, 'v'},
		{"no-proxy",				no_argument,		0, 'x'},
		{"stdio",					no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Create a logfile to capture debug output and actual msg data */

	fplog = create_logfile("sp.log");
	fprintf(fplog, "Server log started\n");

	/* Config defaults */

	memset(&config, 0, sizeof(config));

	config.apiver= IAS_API_DEF_VERSION;

	/*
	 * For demo purposes only. A production/release enclave should
	 * never allow debug-mode enclaves to attest.
	 */
	config.allow_debug_enclave= 1;

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;
		off_t offset = IAS_SUBSCRIPTION_KEY_SIZE;
		int ret = 0;
		char *eptr= NULL;
		unsigned long val;

		c = getopt_long(argc, argv,
			"A:B:DGI:J:K:N:PR:S:V:X:dg:hk:lp:r:s:i:j:vxz",
			long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {

		case 0:
			break;

		case 'A':
			if (!cert_load_file(&config.signing_ca, optarg)) {
				crypto_perror("cert_load_file");
				eprintf("%s: could not load IAS Signing Cert CA\n", optarg);
				return 1;
			}

			config.store = cert_init_ca(config.signing_ca);
			if (config.store == NULL) {
				eprintf("%s: could not initialize certificate store\n", optarg);
				return 1;
			}
			++flag_ca;

			break;

		case 'B':
			config.ca_bundle = strdup(optarg);
			if (config.ca_bundle == NULL) {
				perror("strdup");
				return 1;
			}

			break;

		case 'D':
			config.allow_debug_enclave= 0;
			break;
		case 'G':
			ias_list_agents(stdout);
			return 1;

		case 'I':
			// Get Size of File, should be IAS_SUBSCRIPTION_KEY_SIZE + EOF
			ret = from_file(NULL, optarg, &offset); 

			if ((offset != IAS_SUBSCRIPTION_KEY_SIZE+1) || (ret == 0)) {
				eprintf("IAS Primary Subscription Key must be %d-byte hex string.\n",
					IAS_SUBSCRIPTION_KEY_SIZE);
				return 1;
			}

			// Remove the EOF
			offset--;

			// Read the contents of the file
			if (!from_file((unsigned char *)&config.pri_subscription_key, optarg, &offset)) {
				eprintf("IAS Primary Subscription Key must be %d-byte hex string.\n",
					IAS_SUBSCRIPTION_KEY_SIZE);
					return 1;
			}
			break;

		case 'J':
			// Get Size of File, should be IAS_SUBSCRIPTION_KEY_SIZE + EOF
			ret = from_file(NULL, optarg, &offset);

			if ((offset != IAS_SUBSCRIPTION_KEY_SIZE+1) || (ret == 0)) {
				eprintf("IAS Secondary Subscription Key must be %d-byte hex string.\n",
					IAS_SUBSCRIPTION_KEY_SIZE);
				return 1;
			}

			// Remove the EOF
			offset--;

			// Read the contents of the file
			if (!from_file((unsigned char *)&config.sec_subscription_key, optarg, &offset)) {
				eprintf("IAS Secondary Subscription Key must be %d-byte hex string.\n",
					IAS_SUBSCRIPTION_KEY_SIZE);
					return 1;
			}

			break;

		case 'K':
			if (!key_load_file(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load_file");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;

		case 'N':
			if (!from_hexstring((unsigned char *)&config.req_mrsigner,
				optarg, 32)) {

				eprintf("MRSIGNER must be 64-byte hex string\n");
				return 1;
			}
			++flag_mrsigner;
			break;

        case 'P':
			flag_prod = 1;
			break;

		case 'R':
			eptr= NULL;
			val= strtoul(optarg, &eptr, 10);
			if ( *eptr != '\0' || val > 0xFFFF ) {
				eprintf("Product Id must be a positive integer <= 65535\n");
				return 1;
			}
			config.req_isv_product_id= val;
			++flag_isv_product_id;
			break;

		case 'S':
			if (!from_hexstring_file((unsigned char *)&config.spid, optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;

			break;

		case 'V':
			eptr= NULL;
			val= strtoul(optarg, &eptr, 10);
			if ( *eptr != '\0' || val > (unsigned long) 0xFFFF ) {
				eprintf("Minimum ISV SVN must be a positive integer <= 65535\n");
				return 1;
			}
			config.min_isvsvn= val;
			++flag_min_isvsvn;
			break;

		case 'X':
			config.strict_trust= 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'g':
			config.user_agent= strdup(optarg);
			if ( config.user_agent == NULL ) {
				perror("malloc");
				return 1;
			}
			break;

		case 'i':
			if (strlen(optarg) != IAS_SUBSCRIPTION_KEY_SIZE) {
				eprintf("IAS Subscription Key must be %d-byte hex string\n",IAS_SUBSCRIPTION_KEY_SIZE);
				return 1;
			}

			strncpy((char *) config.pri_subscription_key, optarg, IAS_SUBSCRIPTION_KEY_SIZE);

			break;

		case 'j':
			if (strlen(optarg) != IAS_SUBSCRIPTION_KEY_SIZE) {
				eprintf("IAS Secondary Subscription Key must be %d-byte hex string\n",
				IAS_SUBSCRIPTION_KEY_SIZE);
				return 1;
			}

			strncpy((char *) config.sec_subscription_key, optarg, IAS_SUBSCRIPTION_KEY_SIZE);

			break;

		case 'k':
			if (!key_load(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;

		case 'l':
			config.quote_type = SGX_LINKABLE_SIGNATURE;
			break;

		case 'p':
			if ( flag_noproxy ) usage();
			if (!get_proxy(&config.proxy_server, &config.proxy_port, optarg)) {
				eprintf("%s: could not extract proxy info\n", optarg);
				return 1;
			}
			// Break the URL into host and port. This is a simplistic algorithm.
			break;

		case 'r':
			config.apiver= atoi(optarg);
			if ( config.apiver < IAS_MIN_VERSION || config.apiver >
				IAS_MAX_VERSION ) {

				eprintf("version must be between %d and %d\n",
					IAS_MIN_VERSION, IAS_MAX_VERSION);
				return 1;
			}
			break;

		case 's':
			if (strlen(optarg) < 32) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			if (!from_hexstring((unsigned char *)&config.spid, (unsigned char *)optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'x':
			if ( config.proxy_server != NULL ) usage();
			flag_noproxy=1;
			break;

		case 'z':
			flag_stdio= 1;
			break;

		case 'h':
		case '?':
		default:
			usage();
		}
	}

	/* We should have zero or one command-line argument remaining */

	argc-= optind;
	if ( argc > 1 ) usage();

	/* The remaining argument, if present, is the port number. */

	if ( flag_stdio && argc ) {
		usage();
	} else if ( argc ) {
		port= argv[optind];
	} else {
		port= strdup(DEFAULT_PORT);
		if ( port == NULL ) {
			perror("strdup");
			return 1;
		}
	}

	if ( debug ) {
		eprintf("+++ IAS Primary Subscription Key set to '%c%c%c%c........................%c%c%c%c'\n",
			config.pri_subscription_key[0],
        	config.pri_subscription_key[1],
        	config.pri_subscription_key[2],
        	config.pri_subscription_key[3],
        	config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -4 ],
        	config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -3 ],
        	config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -2 ],
        	config.pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -1 ]
		);

		eprintf("+++ IAS Secondary Subscription Key set to '%c%c%c%c........................%c%c%c%c'\n",
        	config.sec_subscription_key[0],
        	config.sec_subscription_key[1],
        	config.sec_subscription_key[2],
        	config.sec_subscription_key[3],
        	config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -4 ],
        	config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -3 ],
        	config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -2 ],
        	config.sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE -1 ] 
		);
	}


	/* Use the default CA bundle unless one is provided */

	if ( config.ca_bundle == NULL ) {
		config.ca_bundle= strdup(DEFAULT_CA_BUNDLE);
		if ( config.ca_bundle == NULL ) {
			perror("strdup");
			return 1;
		}
		if ( debug ) eprintf("+++ Using default CA bundle %s\n",
			config.ca_bundle);
	}

	/*
	 * Use the hardcoded default key unless one is provided on the
	 * command line. Most real-world services would hardcode the
	 * key since the public half is also hardcoded into the enclave.
	 */

	if (config.service_private_key == NULL) {
		if (debug) {
			eprintf("Using default private key\n");
		}
		config.service_private_key = key_private_from_bytes(def_service_private_key);
		if (config.service_private_key == NULL) {
			crypto_perror("key_private_from_bytes");
			return 1;
		}

	}

	if (debug) {
		eprintf("+++ using private key:\n");
		PEM_write_PrivateKey(stderr, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
		PEM_write_PrivateKey(fplog, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
	}

	if (!flag_spid) {
		eprintf("--spid or --spid-file is required\n");
		flag_usage = 1;
	}

	if (!flag_ca) {
		eprintf("--ias-signing-cafile is required\n");
		flag_usage = 1;
	}

	if ( ! flag_isv_product_id ) {
		eprintf("--isv-product-id is required\n");
		flag_usage = 1;
	}
	
	if ( ! flag_min_isvsvn ) {
		eprintf("--min-isvsvn is required\n");
		flag_usage = 1;
	}
	
	if ( ! flag_mrsigner ) {
		eprintf("--mrsigner is required\n");
		flag_usage = 1;
	}

	if (flag_usage) usage();

	/* Initialize out support libraries */

	crypto_init();

	/* Initialize our IAS request object */

	try {
		ias = new IAS_Connection(
			(flag_prod) ? IAS_SERVER_PRODUCTION : IAS_SERVER_DEVELOPMENT,
			0,
			(char *)(config.pri_subscription_key),
			(char *)(config.sec_subscription_key)
		);
	}
	catch (...) {
		oops = 1;
		eprintf("exception while creating IAS request object\n");
		return 1;
	}

	if ( flag_noproxy ) ias->proxy_mode(IAS_PROXY_NONE);
	else if (config.proxy_server != NULL) {
		ias->proxy_mode(IAS_PROXY_FORCE);
		ias->proxy(config.proxy_server, config.proxy_port);
	}

	if ( config.user_agent != NULL ) {
		if ( ! ias->agent(config.user_agent) ) {
			eprintf("%s: unknown user agent\n", config.user_agent);
			return 0;
		}
	}

	/* 
	 * Set the cert store for this connection. This is used for verifying 
	 * the IAS signing certificate, not the TLS connection with IAS (the 
	 * latter is handled using config.ca_bundle).
	 */
	ias->cert_store(config.store);

	/*
	 * Set the CA bundle for verifying the IAS server certificate used
	 * for the TLS session. If this isn't set, then the user agent
	 * will fall back to it's default.
	 */
	if ( strlen(config.ca_bundle) ) ias->ca_bundle(config.ca_bundle);

	/* Get our message IO object. */
	
	if ( flag_stdio ) {
		msgio= new MsgIO();
	} else {
		try {
			msgio= new MsgIO(NULL, (port == NULL) ? DEFAULT_PORT : port);
		}
		catch(...) {
			return 1;
		}
	}

#ifndef _WIN32
	/* 
	 * Install some rudimentary signal handlers. We just want to make 
	 * sure we gracefully shutdown the listen socket before we exit
	 * to avoid "address already in use" errors on startup.
	 */

	sigemptyset(&sact.sa_mask);
	sact.sa_flags= 0;
	sact.sa_handler= &cleanup_and_exit;

	if ( sigaction(SIGHUP, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGINT, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGTERM, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGQUIT, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
#endif

 	/* If we're running in server mode, we'll block here.  */

	while ( msgio->server_loop() ) {
		ra_session_t session;
		sgx_ra_msg1_t msg1;
		sgx_ra_msg2_t msg2;
		ra_msg4_t msg4;

		memset(&session, 0, sizeof(ra_session_t));

		/* Read message 0 and 1, then generate message 2 */

		if ( ! process_msg01(msgio, ias, &msg1, &msg2, &sigrl, &config,
			&session) ) {

			eprintf("error processing msg1\n");
			goto disconnect;
		}

		/* Send message 2 */

		/*
	 	* sgx_ra_msg2_t is a struct with a flexible array member at the
	 	* end (defined as uint8_t sig_rl[]). We could go to all the 
	 	* trouble of building a byte array large enough to hold the
	 	* entire struct and then cast it as (sgx_ra_msg2_t) but that's
	 	* a lot of work for no gain when we can just send the fixed 
	 	* portion and the array portion by hand.
	 	*/

		dividerWithText(stderr, "Copy/Paste Msg2 Below to Client");
		dividerWithText(fplog, "Msg2 (send to Client)");

		msgio->send_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
		fsend_msg_partial(fplog, (void *) &msg2, sizeof(sgx_ra_msg2_t));

		msgio->send(sigrl, msg2.sig_rl_size);
		fsend_msg(fplog, sigrl, msg2.sig_rl_size); 

		edivider();

		/* Read message 3, and generate message 4 */

		if ( ! process_msg3(msgio, ias, &msg1, &msg4, &config, &session) ) {
			eprintf("error processing msg3\n");
			goto disconnect;
		}

		if ( ! process_msg5(msgio, ias, &sigrl, &config,&session) ) {
			eprintf("error processing msg5\n");
			goto disconnect;
		}

disconnect:
		msgio->disconnect();
	}

	crypto_destroy();

	return 0;
}

int process_msg3 (MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config, ra_session_t *session)
{
	sgx_ra_msg3_t *msg3;
	size_t blen= 0;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	char *buffer= NULL;
	char *b64quote;
	sgx_mac_t vrfymac;
	sgx_quote_t *q;

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg3\n");

	/*
	 * Read message 3
	 *
	 * CMACsmk(M) || M
	 *
	 * where
	 *
	 * M = ga || PS_SECURITY_PROPERTY || QUOTE
	 *
	 */

	rv= msgio->read((void **) &msg3, &sz);
	if ( rv == -1 ) {
		eprintf("system error reading msg3\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg3\n");
		return 0;
	}
	if ( debug ) {
		eprintf("+++ read %lu bytes\n", sz);
	}

	/*
	 * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
	 * since msg3.quote is a flexible array member.
	 *
	 * Total message size is sz/2 since the income message is in base16.
	 */
	quote_sz = (uint32_t)((sz / 2) - sizeof(sgx_ra_msg3_t));
	if ( debug ) {
		eprintf("+++ quote_sz= %lu bytes\n", quote_sz);
	}

	/* Make sure Ga matches msg1 */

	if ( debug ) {
		eprintf("+++ Verifying msg3.g_a matches msg1.g_a\n");
		eprintf("msg1.g_a.gx = %s\n",
			hexstring(&msg1->g_a.gx, sizeof(msg1->g_a.gx)));
		eprintf("msg1.g_a.gy = %s\n",
			hexstring(&msg1->g_a.gy, sizeof(msg1->g_a.gy)));
		eprintf("msg3.g_a.gx = %s\n",
			hexstring(&msg3->g_a.gx, sizeof(msg3->g_a.gx)));
		eprintf("msg3.g_a.gy = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
	}
	if ( CRYPTO_memcmp(&msg3->g_a, &msg1->g_a, sizeof(sgx_ec256_public_t)) ) {
		eprintf("msg1.g_a and mgs3.g_a keys don't match\n");
		free(msg3);
		return 0;
	}

	/* Validate the MAC of M */

	cmac128(session->smk, (unsigned char *) &msg3->g_a,
		sizeof(sgx_ra_msg3_t)-sizeof(sgx_mac_t)+quote_sz,
		(unsigned char *) vrfymac);
	if ( debug ) {
		eprintf("+++ Validating MACsmk(M)\n");
		eprintf("msg3.mac   = %s\n", hexstring(msg3->mac, sizeof(sgx_mac_t)));
		eprintf("calculated = %s\n", hexstring(vrfymac, sizeof(sgx_mac_t)));
	}
	if ( CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t)) ) {
		eprintf("Failed to verify msg3 MAC\n");
		free(msg3);
		return 0;
	}

	/* Encode the report body as base64 */

	b64quote= base64_encode((char *) &msg3->quote, quote_sz);
	if ( b64quote == NULL ) {
		eprintf("Could not base64 encode the quote\n");
		free(msg3);
		return 0;
	}
	q= (sgx_quote_t *) msg3->quote;

	if ( verbose ) {

		edividerWithText("Msg3 Details (from Client)");
		eprintf("msg3.mac                 = %s\n",
			hexstring(&msg3->mac, sizeof(msg3->mac)));
		eprintf("msg3.g_a.gx              = %s\n",
			hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
		eprintf("msg3.g_a.gy              = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
		eprintf("msg3.ps_sec_prop         = %s\n",
			hexstring(&msg3->ps_sec_prop, sizeof(msg3->ps_sec_prop)));
		eprintf("msg3.quote.version       = %s\n",
			hexstring(&q->version, sizeof(uint16_t)));
		eprintf("msg3.quote.sign_type     = %s\n",
			hexstring(&q->sign_type, sizeof(uint16_t)));
		eprintf("msg3.quote.epid_group_id = %s\n",
			hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
		eprintf("msg3.quote.qe_svn        = %s\n",
			hexstring(&q->qe_svn, sizeof(sgx_isv_svn_t)));
		eprintf("msg3.quote.pce_svn       = %s\n",
			hexstring(&q->pce_svn, sizeof(sgx_isv_svn_t)));
		eprintf("msg3.quote.xeid          = %s\n",
			hexstring(&q->xeid, sizeof(uint32_t)));
		eprintf("msg3.quote.basename      = %s\n",
			hexstring(&q->basename, sizeof(sgx_basename_t)));
		eprintf("msg3.quote.report_body   = %s\n",
			hexstring(&q->report_body, sizeof(sgx_report_body_t)));
		eprintf("msg3.quote.signature_len = %s\n",
			hexstring(&q->signature_len, sizeof(uint32_t)));
		eprintf("msg3.quote.signature     = %s\n",
			hexstring(&q->signature, q->signature_len));

		edividerWithText("Enclave Quote (base64) ==> Send to IAS");

		eputs(b64quote);

		eprintf("\n");
		edivider();
	}

	/* Verify that the EPID group ID in the quote matches the one from msg1 */

	if ( debug ) {
		eprintf("+++ Validating quote's epid_group_id against msg1\n");
		eprintf("msg1.egid = %s\n", 
			hexstring(msg1->gid, sizeof(sgx_epid_group_id_t)));
		eprintf("msg3.quote.epid_group_id = %s\n",
			hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
	}

	if ( memcmp(msg1->gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t)) ) {
		eprintf("EPID GID mismatch. Attestation failed.\n");
		free(b64quote);
		free(msg3);
		return 0;
	}


	if ( get_attestation_report(ias, config->apiver, b64quote,
		msg3->ps_sec_prop, msg4, config->strict_trust) ) {

		unsigned char vfy_rdata[64];
		unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

		sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;

		memset(vfy_rdata, 0, 64);

		/*
		 * Verify that the first 64 bytes of the report data (inside
		 * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
		 *
		 * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
		 *
		 * where || denotes concatenation.
		 */

		/* Derive VK */

		cmac128(session->kdk, (unsigned char *)("\x01VK\x00\x80\x00"),
				6, session->vk);

		/* Build our plaintext */

		memcpy(msg_rdata, session->g_a, 64);
		memcpy(&msg_rdata[64], session->g_b, 64);
		memcpy(&msg_rdata[128], session->vk, 16);

		/* SHA-256 hash */

		sha256_digest(msg_rdata, 144, vfy_rdata);

		if ( verbose ) {
			edividerWithText("Enclave Report Verification");
			if ( debug ) {
				eprintf("VK                 = %s\n", 
					hexstring(session->vk, 16));
			}
			eprintf("SHA256(Ga||Gb||VK) = %s\n",
				hexstring(vfy_rdata, 32));
			eprintf("report_data[64]    = %s\n",
				hexstring(&r->report_data, 64));
		}

		if ( CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data,
			64) ) {

			eprintf("Report verification failed.\n");
			free(b64quote);
			free(msg3);
			return 0;
		}

		/*
		 * The service provider must validate that the enclave
		 * report is from an enclave that they recognize. Namely,
		 * that the MRSIGNER matches our signing key, and the MRENCLAVE
		 * hash matches an enclave that we compiled.
		 *
		 * Other policy decisions might include examining ISV_SVN to 
		 * prevent outdated/deprecated software from successfully
		 * attesting, and ensuring the TCB is not out of date.
		 *
		 * A real-world service provider might allow multiple ISV_SVN
		 * values, but for this sample we only allow the enclave that
		 * is compiled.
		 */

#ifndef _WIN32
/* Windows implementation is not available yet */

		if ( ! verify_enclave_identity(config->req_mrsigner, 
			config->req_isv_product_id, config->min_isvsvn, 
			config->allow_debug_enclave, r) ) {

			eprintf("Invalid enclave.\n");
			msg4->status= NotTrusted;
		}
#endif

		if ( verbose ) {
			edivider();

			// The enclave report is valid so we can trust the report
			// data.

			edividerWithText("Enclave Report Details");

			eprintf("cpu_svn     = %s\n",
				hexstring(&r->cpu_svn, sizeof(sgx_cpu_svn_t)));
			eprintf("misc_select = %s\n",
				hexstring(&r->misc_select, sizeof(sgx_misc_select_t)));
			eprintf("attributes  = %s\n",
				hexstring(&r->attributes, sizeof(sgx_attributes_t)));
			eprintf("mr_enclave  = %s\n",
				hexstring(&r->mr_enclave, sizeof(sgx_measurement_t)));
			eprintf("mr_signer   = %s\n",
				hexstring(&r->mr_signer, sizeof(sgx_measurement_t)));
			eprintf("isv_prod_id = %04hX\n", r->isv_prod_id);
			eprintf("isv_svn     = %04hX\n", r->isv_svn);
			eprintf("report_data = %s\n",
				hexstring(&r->report_data, sizeof(sgx_report_data_t)));
		}


		edividerWithText("Copy/Paste Msg4 Below to Client"); 

		/* Serialize the members of the Msg4 structure independently */
		/* vs. the entire structure as one send_msg() */

		msgio->send_partial(&msg4->status, sizeof(msg4->status));
		msgio->send(&msg4->platformInfoBlob, sizeof(msg4->platformInfoBlob));

		fsend_msg_partial(fplog, &msg4->status, sizeof(msg4->status));
		fsend_msg(fplog, &msg4->platformInfoBlob,
			sizeof(msg4->platformInfoBlob));
		edivider();

		/*
		 * If the enclave is trusted, derive the MK and SK. Also get
		 * SHA256 hashes of these so we can verify there's a shared
		 * secret between us and the client.
		 */

		if ( msg4->status == Trusted ) {
			unsigned char hashmk[32], hashsk[32];

			if ( debug ) eprintf("+++ Deriving the MK and SK\n");
			cmac128(session->kdk, (unsigned char *)("\x01MK\x00\x80\x00"),
				6, session->mk);
			cmac128(session->kdk, (unsigned char *)("\x01SK\x00\x80\x00"),
				6, session->sk);

			sha256_digest(session->mk, 16, hashmk);
			sha256_digest(session->sk, 16, hashsk);

			if ( verbose ) {
				if ( debug ) {
					eprintf("MK         = %s\n", hexstring(session->mk, 16));
					eprintf("SK         = %s\n", hexstring(session->sk, 16));
				}
				eprintf("SHA256(MK) = %s\n", hexstring(hashmk, 32));
				eprintf("SHA256(SK) = %s\n", hexstring(hashsk, 32));
			}
		}

	} else {
		eprintf("Attestation failed\n");
		free(msg3);
		free(b64quote);
		return 0;
	}

	free(b64quote);
	free(msg3);

	return 1;
}
























typedef struct {
    struct sockaddr sockaddr;
    socklen_t socklen;
    char name[32];
} peer_t;

typedef struct {
    int len;
    peer_t * peers;
} peers_list_t;

int peer_constructor(const char * ip, uint16_t port, const char * name, peer_t * peer){
	strcpy(peer->name, name);
	peer->socklen = sizeof(struct sockaddr_in);
	((struct sockaddr_in *) &peer->sockaddr)->sin_family = AF_INET;
	((struct sockaddr_in *) &peer->sockaddr)->sin_port = htons(port);
	inet_pton(AF_INET, ip, &((struct sockaddr_in *) &peer->sockaddr)->sin_addr);

	return 0;
}

typedef struct _ra_msg5_t {
	uint32_t id;
    char log[128];
	uint8_t serialized_private_key[2048];
	int serialized_len;
} sgx_ra_msg5_t;


/* MESSAGE 5: BONJOUR */
int process_msg5 (MsgIO *msgio, IAS_Connection *ias, char **sigrl, config_t *config, ra_session_t *session) {
	size_t sz;
	uint8_t nonce[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	// Data to encrypt (log + private_key)
	sgx_ra_msg5_t msg5; memset(&msg5, 0, sizeof(msg5));
	msg5.id = 0;
	strcpy(msg5.log, "Ici des clefs publiques par exemple !");
	
	/*
	msg5.serialized_private_key = {
	    {0xf5, 0x2b, 0x4a, 0x91, 0x72, 0xac, 0xde, 0x74, 0xc8, 0x88, 0x81, 0x0b, 0x05, 0x53, 0x6a, 0x9c, 0xd2, 0x26, 0x44, 0x20, 0xa4, 0x37, 0x98, 0x17, 0x96, 0x24, 0x60, 0x5e, 0x67, 0x07, 0xe1, 0x68, 0xaf, 0x79, 0x54, 0xc8, 0xbc, 0x86, 0x21, 0xea, 0x43, 0x7a, 0x5f, 0xd5, 0x76, 0x59, 0xea, 0x73, 0x0b, 0xbc, 0x3c, 0x8a, 0x1e, 0xf4, 0x59, 0x14, 0x7e, 0xcd, 0xf7, 0xbc, 0xe3, 0x84, 0x35, 0xf8, 0x27, 0x1e, 0x9f, 0xaf, 0xe9, 0xd5, 0x38, 0x15, 0x48, 0x01, 0x54, 0x91, 0xa0, 0x69, 0x53, 0x05, 0xce, 0x28, 0x53, 0x53, 0x0b, 0x38, 0xf9, 0x7f, 0xa5, 0x00, 0x76, 0xa4, 0x04, 0x2b, 0xd3, 0x62, 0x8b, 0x18, 0x97, 0x27, 0x4b, 0x7e, 0x95, 0x52, 0x2f, 0x36, 0x6f, 0x3e, 0xa3, 0x3c, 0x86, 0x24, 0x3d, 0xf6, 0x5b, 0x34, 0xa5, 0xf4, 0x21, 0x3f, 0x9f, 0x88, 0x4a, 0x9d, 0x92, 0x06, 0x9c, 0xe6, 0x7a, 0x81, 0x2c, 0xf3, 0x3a, 0x47, 0x0a, 0xd7, 0x4e, 0xd8, 0xf3, 0x70, 0xb1, 0xc6, 0x63, 0x1a, 0x38, 0x98, 0x38, 0x48, 0xe5, 0x5a, 0xe4, 0x47, 0x18, 0xfa, 0x44, 0x92, 0xc7, 0x42, 0xfd, 0x1a, 0xe5, 0x85, 0x0e, 0x11, 0xea, 0xbd, 0x52, 0x7f, 0xe4, 0x29, 0x07, 0xbc, 0xc4, 0x1e, 0xf7, 0x5a, 0xb8, 0x6b, 0x61, 0x34, 0xe6, 0x0e, 0xbc, 0x9f, 0x61, 0xce, 0xeb, 0x84, 0x4b, 0x54, 0x2a, 0xc1, 0x01, 0xe1, 0xd1, 0x11, 0x72, 0xc5, 0x02, 0xb2, 0xa4, 0xbc, 0x29, 0x38, 0x4e, 0x5d, 0x78, 0x2b, 0x52, 0xef, 0x8d, 0xe3, 0x60, 0x12, 0xbb, 0x11, 0xf4, 0x9d, 0x5e, 0x10, 0x94, 0x2c, 0xc3, 0x2f, 0x58, 0x31, 0x99, 0x77, 0x54, 0x23, 0x64, 0x23, 0xbf, 0x9d, 0x2e, 0x44, 0xa6, 0x19, 0x88, 0xd4, 0x39, 0x30, 0x1f, 0x86, 0xd8, 0xe2, 0xad, 0x07, 0x7c, 0xf8, 0x00, 0x68, 0x0c, 0x2c, 0xec, 0xa5, 0x57, 0x6a, 0x37, 0x5b, 0x92, 0xb4, 0x29, 0x72, 0xd3, 0x8c, 0x5e, 0x62, 0xc9, 0xa4, 0x2d, 0x45, 0x61, 0x3d, 0xef, 0xd6, 0xb3, 0x08, 0xe1, 0x87, 0xef, 0x79, 0xef, 0x05, 0xad, 0xfa, 0xc9, 0x0b, 0x49, 0xc4, 0x40, 0x1d, 0xd2, 0x4e, 0xda, 0xe7, 0xff, 0xb1, 0xae, 0x68, 0x51, 0x68, 0xe9, 0xfb, 0x60, 0xd1, 0xb7, 0xff, 0x7e, 0xb2, 0xe4, 0xb5, 0xe8, 0xba, 0x61, 0x2f, 0xc5, 0x43, 0xa3, 0x7c, 0x50, 0x6b, 0x46, 0x55, 0x46, 0x9f, 0x5a, 0x61, 0x9b, 0x34, 0xc9, 0xf3, 0x36, 0x38, 0x48, 0xe9, 0xca, 0x19, 0x65, 0x29, 0x24, 0x6d, 0xc1, 0x14, 0xe4, 0x00, 0x34, 0xea, 0x34, 0x11, 0x68, 0xe2, 0x7e, 0xbd, 0xf6, 0x65, 0xb6, 0x0a, 0x5d, 0xd1, 0x71, 0x64, 0x0b, 0xff, 0x7a, 0x4f, 0xe9, 0xc6, 0x1b, 0x6a, 0x00, 0x10, 0xea, 0x09, 0xec, 0x55, 0x55, 0xd3, 0xa1, 0x70, 0x30, 0x76, 0x4d, 0xbc}
	,   {0xc5, 0xef, 0x07, 0x8b, 0xc4, 0xfc, 0xb3, 0x03, 0x91, 0x54, 0xf8, 0xaa, 0x91, 0x36, 0xb0, 0xf9, 0x99, 0x1f, 0xf8, 0x91, 0xfc, 0x73, 0x37, 0xec, 0x22, 0x73, 0x7a, 0x7e, 0xe4, 0xdd, 0x84, 0xd8, 0x19, 0x69, 0xcd, 0x84, 0xa6, 0xff, 0x3d, 0x44, 0x0e, 0x5f, 0xb5, 0xb0, 0xbb, 0x70, 0x88, 0xc8, 0x88, 0x7f, 0x56, 0xc5, 0x83, 0x66, 0xee, 0x46, 0x37, 0xff, 0xaf, 0x63, 0x8a, 0x89, 0x4e, 0x0f, 0xa2, 0xde, 0xdd, 0xfd, 0xb5, 0x04, 0x00, 0xbe, 0x6b, 0xfd, 0x18, 0xdc, 0x40, 0x0b, 0x5a, 0xf6, 0x4c, 0xb5, 0xfe, 0xf9, 0x4d, 0x31, 0x33, 0xac, 0x5d, 0x28, 0x41, 0xd6, 0xee, 0xf9, 0x13, 0x07, 0xef, 0x17, 0x42, 0x19, 0xec, 0x1a, 0x25, 0x7c, 0x35, 0xfe, 0x0b, 0x29, 0x1c, 0x02, 0xce, 0xf3, 0x5d, 0x78, 0x88, 0x10, 0x0d, 0x97, 0x0a, 0x7b, 0xcb, 0x51, 0x49, 0x9f, 0x1e, 0x41, 0x3f, 0x6f, 0x96, 0x80, 0xad, 0xb6, 0xe9, 0x10, 0x96, 0x0a, 0xc7, 0xcb, 0x57, 0x36, 0x55, 0x59, 0xb2, 0xbf, 0x3c, 0xe5, 0x16, 0xe3, 0xdc, 0xac, 0xfd, 0x5f, 0x5f, 0xe5, 0xe4, 0x61, 0x80, 0x80, 0x97, 0xea, 0x44, 0x11, 0x32, 0xb4, 0x8c, 0xe3, 0x41, 0x42, 0xa4, 0x30, 0xdb, 0x3d, 0x61, 0x28, 0xf3, 0xa4, 0x6c, 0x05, 0x70, 0x4f, 0x62, 0x56, 0xfd, 0xab, 0x2f, 0x92, 0x83, 0xbd, 0x0a, 0x90, 0x32, 0x61, 0x0e, 0xe9, 0xc8, 0x0f, 0xac, 0x90, 0x5f, 0x15, 0x9a, 0x0f, 0xee, 0x6c, 0x9a, 0x10, 0xab, 0xc2, 0xd1, 0xfc, 0xac, 0xfe, 0x58, 0x52, 0x0e, 0x9e, 0x19, 0x07, 0x91, 0x1e, 0x54, 0x75, 0x08, 0x58, 0xdb, 0x72, 0xbd, 0x29, 0x8d, 0x9c, 0x9a, 0x3d, 0x8b, 0x3b, 0x63, 0xf7, 0x34, 0xb4, 0xca, 0xdb, 0xdc, 0xf6, 0x1e, 0x62, 0x56, 0x35, 0x1f, 0x5c, 0x3d, 0x0d, 0x20, 0xfa, 0x4e, 0x64, 0xb7, 0xc1, 0x24, 0xe1, 0x9e, 0x4e, 0x76, 0x70, 0x55, 0xf3, 0x48, 0xa5, 0x16, 0xa8, 0xfb, 0xd2, 0x2f, 0x33, 0x4e, 0xd0, 0x17, 0x18, 0x3f, 0x14, 0x47, 0xac, 0x4a, 0x43, 0xa4, 0xc4, 0x76, 0xcd, 0xb5, 0xc1, 0x9b, 0xff, 0xf1, 0x83, 0x2d, 0x7e, 0x67, 0xc5, 0x71, 0x7c, 0xe3, 0x84, 0x0b, 0xa3, 0x5d, 0xf6, 0xfb, 0x0b, 0x44, 0xb7, 0x5c, 0x9a, 0xc4, 0x7e, 0xbe, 0x22, 0xff, 0x58, 0xfa, 0xdd, 0x5c, 0x55, 0x96, 0xf6, 0x89, 0xec, 0x31, 0x02, 0x07, 0x61, 0xe8, 0x65, 0xf9, 0x3b, 0xda, 0x47, 0xe7, 0x57, 0x64, 0xe8, 0x70, 0x91, 0x06, 0x03, 0xf1, 0x23, 0x8d, 0x32, 0x4d, 0x31, 0x41, 0xca, 0x52, 0xf4, 0xd7, 0x45, 0xed, 0xf1, 0x0b, 0xa3, 0x1b, 0x15, 0x8f, 0x92, 0x44, 0x4c, 0x40, 0xa5, 0x6e, 0x20, 0xc1, 0x8b, 0xcb, 0xfc, 0x8c, 0x12, 0xfd, 0x06, 0xd6, 0x88, 0x09, 0xd3, 0x84, 0xbb, 0x23, 0x9d}
	,   {0x01, 0x00, 0x01, 0x00}
	};
	*/


	FILE * keyfile = fopen("key.pem", "r");
	RSA * rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);

	unsigned char * serial_key_str = NULL;
	msg5.serialized_len = i2d_RSAPrivateKey(rsa,0);
	i2d_RSAPrivateKey(rsa,  &serial_key_str);

	print_hex((unsigned char *) serial_key_str, msg5.serialized_len);

	printf("msg5.serialized_len = %i\n", msg5.serialized_len);
	memcpy((uint8_t *) msg5.serialized_private_key, (const uint8_t *) serial_key_str, msg5.serialized_len);


	// Encrypting (log + private_key)
	sgx_ra_msg5_t msg5_encrypted; memset(&msg5_encrypted, 0, sizeof(msg5_encrypted));
	int encrypted_len = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, (unsigned char*) session->sk, nonce);
	EVP_EncryptUpdate(ctx, (unsigned char *) &msg5_encrypted, &encrypted_len, (unsigned char *) &msg5, sizeof(msg5));
	EVP_EncryptFinal_ex(ctx, (unsigned char *) (&msg5_encrypted + encrypted_len), &encrypted_len);
	EVP_CIPHER_CTX_free(ctx);

	// Sending (log + private_key)
	
	msgio->send(&msg5_encrypted, sizeof(sgx_ra_msg5_t));
	printf("<%.128s> sent.\n", msg5.log);
 
	//To send again (idk how to avoid that)
	char * nil; msgio->read((void **) &nil, &sz);
	

	
	// Define backend servers
	peers_list_t peers;

	FILE *fp;
	fp = fopen("upstream.conf", "r");
	if(fp != NULL){
		
		char buf[100];
		int len = 0;
		while(fgets(buf,sizeof(buf),fp) != NULL){
			if(strlen(buf) > 1) len++;		
		}
		rewind(fp);

		peers.len = len;
		peers.peers = (peer_t *) malloc(sizeof(peer_t) * peers.len);

		int r = 0;
		int n = 0;
		for (size_t i = 0; i < len; i++){
			char ip[39];
			int port;
			char nom[32];
			r = fscanf(fp, "%s %i %s", ip, &port, nom);
			printf("-- %s %i %s -- (%i)\n", ip, port, nom, r);

			if(r == 3){
				peer_constructor(ip, port, nom, &peers.peers[n++]);
			} else {
				printf("upstream.conf invalid !\n");
				exit(1);
			}
		}
				
		fclose(fp);
	} else {
		peers.len = 4;
		peers.peers = (peer_t *) malloc(sizeof(peer_t) * peers.len);
		peer_constructor("127.0.0.1", 4000, "backend-1", &peers.peers[0]);
		peer_constructor("127.0.0.1", 4001, "backend-2", &peers.peers[1]);
		peer_constructor("127.0.0.1", 4002, "backend-3", &peers.peers[2]);
		peer_constructor("127.0.0.1", 4003, "backend-4", &peers.peers[3]);
	}



	


	// Sending + signing backend server list
	msgio->send_partial(&peers.len, sizeof(int));
	unsigned char digest[SHA256_DIGEST_LENGTH]; unsigned int digest_len;
	HMAC_CTX * ctx_hmac; ctx_hmac = HMAC_CTX_new();
	HMAC_Init_ex(ctx_hmac, session->sk, 16, EVP_sha256(), NULL);
	for (size_t i = 0; i < peers.len; i++){
		HMAC_Update(ctx_hmac, (unsigned char *) &peers.peers[i], sizeof(peer_t));
		msgio->send_partial(&peers.peers[i], sizeof(peer_t));
	}
	HMAC_Final(ctx_hmac, digest, &digest_len);
	HMAC_CTX_free(ctx_hmac);
	msgio->send(digest, digest_len);

	free(peers.peers);
	
	return 1;
}

void load_private_key(uint8_t * prikey){	
	/*
	BN_bn2bin(RSA_get0_d(rsa), prikey->d);
	BN_bn2bin(RSA_get0_e(rsa), prikey->e);
	BN_bn2bin(RSA_get0_n(rsa), prikey->mod);
	
    reverse_str(384,prikey->d);
	reverse_str(384,prikey->mod);
    reverse_str(4,prikey->e);

	
	printf("\nd=");
	print_hex(prikey->d, 384);
	printf("\nmod=");
	print_hex(prikey->mod, 384);
	printf("\ne=");
	print_hex(prikey->e, 4);
	printf("\n");
	*/

}


void reverse_str(int len,uint8_t *str)
{
    uint8_t tmp;
    for(int i=0;i<len/2;i++)
    {
        tmp = str[i];
        str[i] = str[len-i-1];
        str[len-i-1] = tmp;
    }
}






















/*
 * Read and process message 0 and message 1. These messages are sent by
 * the client concatenated together for efficiency (msg0||msg1).
 */

int process_msg01 (MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config, ra_session_t *session)
{
	struct msg01_struct {
		uint32_t msg0_extended_epid_group_id;
		sgx_ra_msg1_t msg1;
	} *msg01;
	size_t blen= 0;
	char *buffer= NULL;
	unsigned char digest[32], r[32], s[32], gb_ga[128];
	EVP_PKEY *Gb;
	int rv;

	memset(msg2, 0, sizeof(sgx_ra_msg2_t));

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg0||msg1\n");

	rv= msgio->read((void **) &msg01, NULL);
	if ( rv == -1 ) {
		eprintf("system error reading msg0||msg1\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg0||msg1\n");
		return 0;
	}

	if ( verbose ) {
		edividerWithText("Msg0 Details (from Client)");
		eprintf("msg0.extended_epid_group_id = %u\n",
			 msg01->msg0_extended_epid_group_id);
		edivider();
	}

	/* According to the Intel SGX Developer Reference
	 * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
	 * server should verify this value is zero. If the Intel(R) EPID group ID 
	 * is not zero, the server aborts remote attestation"
	 */

	if ( msg01->msg0_extended_epid_group_id != 0 ) {
		eprintf("msg0 Extended Epid Group ID is not zero.  Exiting.\n");
		free(msg01);
		return 0;
	}

	// Pass msg1 back to the pointer in the caller func
	memcpy(msg1, &msg01->msg1, sizeof(sgx_ra_msg1_t));

	if ( verbose ) {
		edividerWithText("Msg1 Details (from Client)");
		eprintf("msg1.g_a.gx = %s\n",
			hexstring(&msg1->g_a.gx, sizeof(msg1->g_a.gx)));
		eprintf("msg1.g_a.gy = %s\n",
			hexstring(&msg1->g_a.gy, sizeof(msg1->g_a.gy)));
		eprintf("msg1.gid    = %s\n",
			hexstring( &msg1->gid, sizeof(msg1->gid)));
		edivider();
	}

	/* Generate our session key */

	if ( debug ) eprintf("+++ generating session key Gb\n");

	Gb= key_generate();
	if ( Gb == NULL ) {
		eprintf("Could not create a session key\n");
		free(msg01);
		return 0;
	}

	/*
	 * Derive the KDK from the key (Ga) in msg1 and our session key.
	 * An application would normally protect the KDK in memory to 
	 * prevent trivial inspection.
	 */

	if ( debug ) eprintf("+++ deriving KDK\n");

	if ( ! derive_kdk(Gb, session->kdk, msg1->g_a, config) ) {
		eprintf("Could not derive the KDK\n");
		free(msg01);
		return 0;
	}

	if ( debug ) eprintf("+++ KDK = %s\n", hexstring(session->kdk, 16));

	/*
 	 * Derive the SMK from the KDK 
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00) 
	 */

	if ( debug ) eprintf("+++ deriving SMK\n");

	cmac128(session->kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7,
		session->smk);

	if ( debug ) eprintf("+++ SMK = %s\n", hexstring(session->smk, 16));

	/*
	 * Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga) 
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (32 bytes)
	 * Gb     = Service Provider's session key
	 *          (32 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 * 
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian 
	 * format, meaning the byte streams need to be reversed.
	 *
	 * For SigRL, send:
	 *
	 *  SigRL_size || SigRL_contents
	 *
	 * where sigRL_size is a 32-bit uint (4 bytes). This matches the
	 * structure definition in sgx_ra_msg2_t
	 */

	key_to_sgx_ec256(&msg2->g_b, Gb);
	memcpy(&msg2->spid, &config->spid, sizeof(sgx_spid_t));
	msg2->quote_type= config->quote_type;
	msg2->kdf_id= 1;

	/* Get the sigrl */

	if ( ! get_sigrl(ias, config->apiver, msg1->gid, sigrl,
		&msg2->sig_rl_size) ) {

		eprintf("could not retrieve the sigrl\n");
		free(msg01);
		return 0;
	}

	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(session->g_b, &msg2->g_b, 64);

	memcpy(&gb_ga[64], &msg1->g_a, 64);
	memcpy(session->g_a, &msg1->g_a, 64);

	if ( debug ) eprintf("+++ GbGa = %s\n", hexstring(gb_ga, 128));

	ecdsa_sign(gb_ga, 128, config->service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	if ( debug ) {
		eprintf("+++ sha256(GbGa) = %s\n", hexstring(digest, 32));
		eprintf("+++ r = %s\n", hexstring(r, 32));
		eprintf("+++ s = %s\n", hexstring(s, 32));
	}

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */

	cmac128(session->smk, (unsigned char *) msg2, 148,
		(unsigned char *) &msg2->mac);

	if ( verbose ) {
		edividerWithText("Msg2 Details");
		eprintf("msg2.g_b.gx      = %s\n",
			hexstring(&msg2->g_b.gx, sizeof(msg2->g_b.gx)));
		eprintf("msg2.g_b.gy      = %s\n",
			hexstring(&msg2->g_b.gy, sizeof(msg2->g_b.gy)));
		eprintf("msg2.spid        = %s\n",
			hexstring(&msg2->spid, sizeof(msg2->spid)));
		eprintf("msg2.quote_type  = %s\n",
			hexstring(&msg2->quote_type, sizeof(msg2->quote_type)));
		eprintf("msg2.kdf_id      = %s\n",
			hexstring(&msg2->kdf_id, sizeof(msg2->kdf_id)));
		eprintf("msg2.sign_ga_gb  = %s\n",
			hexstring(&msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga)));
		eprintf("msg2.mac         = %s\n",
			hexstring(&msg2->mac, sizeof(msg2->mac)));
		eprintf("msg2.sig_rl_size = %s\n",
			hexstring(&msg2->sig_rl_size, sizeof(msg2->sig_rl_size)));
		edivider();
	}

	free(msg01);

	return 1;
}

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a,
	config_t *config)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
	 * Compute the shared secret using the peer's public key and a generated
	 * public/private key.
	 */

	Ga= key_from_sgx_ec256(&g_a);
	if ( Ga == NULL ) {
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		crypto_perror("key_shared_secret");
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	if ( debug ) eprintf("+++ shared secret= %s\n", hexstring(Gab_x, slen));

	reverse_bytes(Gab_x, Gab_x, slen);

	if ( debug ) eprintf("+++ reversed     = %s\n", hexstring(Gab_x, slen));

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
	 * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
	 */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sig_rl, uint32_t *sig_rl_size)
{
	IAS_Request *req= NULL;
	int oops= 1;
	string sigrlstr;

	try {
		oops= 0;
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		oops = 1;
	}

	if (oops) {
		eprintf("Exception while creating IAS request object\n");
		delete req;
		return 0;
	}
 
        ias_error_t ret = IAS_OK;

	while (1) {

		ret =  req->sigrl(*(uint32_t *) gid, sigrlstr);
		if ( debug ) {
			eprintf("+++ RET = %zu\n, ret");
			eprintf("+++ SubscriptionKeyID = %d\n",(int)ias->getSubscriptionKeyID());
                }
	
		if ( ret == IAS_UNAUTHORIZED && (ias->getSubscriptionKeyID() == IAS_Connection::SubscriptionKeyID::Primary))
		{

		        if ( debug ) {
				eprintf("+++ IAS Primary Subscription Key failed with IAS_UNAUTHORIZED\n");
				eprintf("+++ Retrying with IAS Secondary Subscription Key\n");
			}	

			// Retry with Secondary Subscription Key
			ias->SetSubscriptionKeyID(IAS_Connection::SubscriptionKeyID::Secondary);
			continue;
		}	
		else if (ret != IAS_OK ) {

			delete req;
			return 0;
		}

		break;
	}
	size_t size;

	*sig_rl = (char *)base64_decode(sigrlstr.c_str(), &size);
	if ( *sig_rl == NULL ) {
		eprintf("Could not decode SigRL\n");
		delete req;
		return 0;
	}

	*sig_rl_size = (uint32_t)size;
	delete req;

	return 1;
}

int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t *msg4,
	int strict_trust) 
{
	IAS_Request *req = NULL;
	map<string,string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;

	try {
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		eprintf("Exception while creating IAS request object\n");
		if ( req != NULL ) delete req;
		return 0;
	}

	payload.insert(make_pair("isvEnclaveQuote", b64quote));
	
	status= req->report(payload, content, messages);
	if ( status == IAS_OK ) {
		JSON reportObj = JSON::Load(content);

		if ( verbose ) {
			edividerWithText("Report Body");
			eprintf("%s\n", content.c_str());
			edivider();
			if ( messages.size() ) {
				edividerWithText("IAS Advisories");
				for (vector<string>::const_iterator i = messages.begin();
					i != messages.end(); ++i ) {

					eprintf("%s\n", i->c_str());
				}
				edivider();
			}
		}

		if ( verbose ) {
			edividerWithText("IAS Report - JSON - Required Fields");
			if ( version >= 3 ) {
				eprintf("version               = %d\n",
					reportObj["version"].ToInt());
			}
			eprintf("id:                   = %s\n",
				reportObj["id"].ToString().c_str());
			eprintf("timestamp             = %s\n",
				reportObj["timestamp"].ToString().c_str());
			eprintf("isvEnclaveQuoteStatus = %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			eprintf("isvEnclaveQuoteBody   = %s\n",
				reportObj["isvEnclaveQuoteBody"].ToString().c_str());

			edividerWithText("IAS Report - JSON - Optional Fields");

			eprintf("platformInfoBlob  = %s\n",
				reportObj["platformInfoBlob"].ToString().c_str());
			eprintf("revocationReason  = %s\n",
				reportObj["revocationReason"].ToString().c_str());
			eprintf("pseManifestStatus = %s\n",
				reportObj["pseManifestStatus"].ToString().c_str());
			eprintf("pseManifestHash   = %s\n",
				reportObj["pseManifestHash"].ToString().c_str());
			eprintf("nonce             = %s\n",
				reportObj["nonce"].ToString().c_str());
			eprintf("epidPseudonym     = %s\n",
				reportObj["epidPseudonym"].ToString().c_str());
			if ( version >= 4 ) {
				int i;

				eprintf("advisoryURL       = %s\n",
					reportObj["advisoryURL"].ToString().c_str());
				eprintf("advisoryIDs       = ");
				/* This is a JSON array */
				for(i= 0; i< reportObj["advisoryIDs"].length(); ++i) {
					eprintf("%s%s", (i)?",":"", reportObj["advisoryIDs"][i].ToString().c_str());
				}
				eprintf("\n");
			}
			edivider();
		}

    /*
     * If the report returned a version number (API v3 and above), make
     * sure it matches the API version we used to fetch the report.
	 *
	 * For API v3 and up, this field MUST be in the report.
     */

	if ( reportObj.hasKey("version") ) {
		unsigned int rversion= (unsigned int) reportObj["version"].ToInt();
		if ( verbose )
			eprintf("+++ Verifying report version against API version\n");
		if ( version != rversion ) {
			eprintf("Report version %u does not match API version %u\n",
				rversion , version);
			delete req;
			return 0;
		}
	} else if ( version >= 3 ) {
		eprintf("attestation report version required for API version >= 3\n");
		delete req;
		return 0;
	}

	/*
	 * This sample's attestion policy is based on isvEnclaveQuoteStatus:
	 * 
	 *   1) if "OK" then return "Trusted"
	 *
 	 *   2) if "CONFIGURATION_NEEDED", "SW_HARDENING_NEEDED", or
	 *      "CONFIGURATION_AND_SW_HARDENING_NEEDED", then return
	        "NotTrusted_ItsComplicated" when in --strict-trust-mode
	         and "Trusted_ItsComplicated" otherwise
	 *
	 *   3) return "NotTrusted" for all other responses
	 *
	 * In case #2, this is ultimatly a policy decision. Do you want to
	 * trust a client that is running with a configuration that weakens
	 * its security posture? Even if you ultimately choose to trust the
	 * client, the "Trusted_ItsComplicated" response is intended to 
	 * tell the client "I'll trust you (for now), but inform the user
	 * that I may not trust them in the future unless they take some 
	 * action". A real service would provide some guidance to the
	 * end user based on the advisory URLs and advisory IDs.
 	 */

	/*
	 * Simply check to see if status is OK, else enclave considered 
	 * not trusted
	 */

	memset(msg4, 0, sizeof(ra_msg4_t));

	if ( verbose ) edividerWithText("ISV Enclave Trust Status");

	if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
		msg4->status = Trusted;
		if ( verbose ) eprintf("Enclave TRUSTED\n");
	} else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED"))) {
		if ( strict_trust ) {
			msg4->status = NotTrusted_ItsComplicated;
			if ( verbose ) eprintf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
		} else {
			if ( verbose ) eprintf("Enclave TRUSTED and COMPLICATED - Reason: %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			msg4->status = Trusted_ItsComplicated;
		}
	} else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE"))) {
		msg4->status = Trusted; //instead of NotTrusted_ItsComplicated
		if ( verbose ) eprintf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
			reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
	} else {
		msg4->status = NotTrusted;
		if ( verbose ) eprintf("Enclave NOT TRUSTED - Reason: %s\n",
			reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
	}


	/* Check to see if a platformInfoBlob was sent back as part of the
	 * response */

	if (!reportObj["platformInfoBlob"].IsNull()) {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

		/* The platformInfoBlob has two parts, a TVL Header (4 bytes),
		 * and TLV Payload (variable) */

		string pibBuff = reportObj["platformInfoBlob"].ToString();

		/* remove the TLV Header (8 base16 chars, ie. 4 bytes) from
		 * the PIB Buff. */

		pibBuff.erase(pibBuff.begin(), pibBuff.begin() + (4*2)); 

		int ret = from_hexstring ((unsigned char *)&msg4->platformInfoBlob, 
			pibBuff.c_str(), pibBuff.length()/2);
	} else {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
	}

		delete req;
		return 1;
	}

	eprintf("attestation query returned %lu: \n", status);

	switch(status) {
		case IAS_QUERY_FAILED:
			eprintf("Could not query IAS\n");
			break;
		case IAS_BADREQUEST:
			eprintf("Invalid payload\n");
			break;
		case IAS_UNAUTHORIZED:
			eprintf("Failed to authenticate or authorize request\n");
			break;
		case IAS_SERVER_ERR:
			eprintf("An internal error occurred on the IAS server\n");
			break;
		case IAS_UNAVAILABLE:
			eprintf("Service is currently not able to process the request. Try again later.\n");
			break;
		case IAS_INTERNAL_ERROR:
			eprintf("An internal error occurred while processing the IAS response\n");
			break;
		case IAS_BAD_CERTIFICATE:
			eprintf("The signing certificate could not be validated\n");
			break;
		case IAS_BAD_SIGNATURE:
			eprintf("The report signature could not be validated\n");
			break;
		default:
			if ( status >= 100 && status < 600 ) {
				eprintf("Unexpected HTTP response code\n");
			} else {
				eprintf("An unknown error occurred.\n");
			}
	}

	delete req;

	return 0;
}

// Break a URL into server and port. NOTE: This is a simplistic algorithm.

int get_proxy(char **server, unsigned int *port, const char *url)
{
	size_t idx1, idx2;
	string lcurl, proto, srv, sport;

	if (url == NULL) return 0;

	lcurl = string(url);
	// Make lower case for sanity
	transform(lcurl.begin(), lcurl.end(), lcurl.begin(), ::tolower);

	idx1= lcurl.find_first_of(":");
	proto = lcurl.substr(0, idx1);
	if (proto == "https") *port = 443;
	else if (proto == "http") *port = 80;
	else return 0;

	idx1 = lcurl.find_first_not_of("/", idx1 + 1);
	if (idx1 == string::npos) return 0;
	
	idx2 = lcurl.find_first_of(":", idx1);
	if (idx2 == string::npos) {
		idx2 = lcurl.find_first_of("/", idx1);
		if (idx2 == string::npos) srv = lcurl.substr(idx1);
		else srv = lcurl.substr(idx1, idx2 - idx1);
	}
	else {
		srv= lcurl.substr(idx1, idx2 - idx1);
		idx1 = idx2+1;
		idx2 = lcurl.find_first_of("/", idx1);

		if (idx2 == string::npos) sport = lcurl.substr(idx1);
		else sport = lcurl.substr(idx1, idx2 - idx1);

		try {
			*port = (unsigned int) ::stoul(sport);
		}
		catch (...) {
			return 0;
		}
	}

	try {
		*server = new char[srv.length()+1];
	}
	catch (...) {
		return 0;
	}

	memcpy(*server, srv.c_str(), srv.length());
	(*server)[srv.length()] = 0;

	return 1;
}

#ifndef _WIN32

/* We don't care which signal it is since we're shutting down regardless */

void cleanup_and_exit(int signo)
{
	/* Signal-safe, and we don't care if it fails or is a partial write. */

	ssize_t bytes= write(STDERR_FILENO, "\nterminating\n", 13);

	/*
	 * This destructor consists of signal-safe system calls (close,
	 * shutdown).
	 */

	delete msgio;

	exit(1);
}
#endif

#define NNL <<endl<<endl<<
#define NL <<endl<<

void usage () 
{
	cerr << "usage: sp [ options ] [ port ]" NL
"Required:" NL
"  -A, --ias-signing-cafile=FILE" NL
"                           Specify the IAS Report Signing CA file." NNL
"  -N, --mrsigner=HEXSTRING" NL
"                           Specify the MRSIGNER value of enclaves that" NL
"                           are allowed to attest. Enclaves signed by" NL
"                           other signing keys are rejected." NNL
"  -R, --isv-product-id=INT" NL
"                           Specify the ISV Product Id for the service." NL
"                           Only Enclaves built with this Product Id" NL
"                           will be accepted." NNL
"  -V, --min-isv-svn=INT" NL
"                           The minimum ISV SVN that the service provider" NL
"                           will accept. Enclaves with a lower ISV SVN" NL
"                           are rejected." NNL
"Required (one of):" NL
"  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte" NL
"                           ASCII hex string." NNL
"  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string." NNL
"Required (one of):" NL
"  -I, --ias-pri-api-key-file=FILE" NL
"                           Set the IAS Primary Subscription Key from a" NL
"                           file containing a 32-byte ASCII hex string." NNL
"  -i, --ias-pri-api-key=HEXSTRING" NL
"                           Set the IAS Primary Subscription Key from a" NL
"                           32-byte ASCII hex string." NNL
"Required (one of):" NL
"  -J, --ias-sec-api-key-file=FILE" NL
"                           Set the IAS Secondary Subscription Key from a" NL
"                           file containing a 32-byte ASCII hex string." NNL
"  -j, --ias-sec-api-key=HEXSTRING" NL
"                           Set the IAS Secondary Subscription Key from a" NL
"                           32-byte ASCII hex string." NNL
"Optional:" NL
"  -B, --ca-bundle-file=FILE" NL
"                           Use the CA certificate bundle at FILE (default:" NL
"                           " << DEFAULT_CA_BUNDLE << ")" NNL
"  -D, --no-debug-enclave   Reject Debug-mode enclaves (default: accept)" NNL
"  -G, --list-agents        List available user agent names for --user-agent" NNL
"  -K, --service-key-file=FILE" NL
"                           The private key file for the service in PEM" NL
"                           format (default: use hardcoded key). The " NL
"                           client must be given the corresponding public" NL
"                           key. Can't combine with --key." NNL
"  -P, --production         Query the production IAS server instead of dev." NNL
"  -X, --strict-trust-mode  Don't trust enclaves that receive a " NL
"                           CONFIGURATION_NEEDED response from IAS " NL
"                           (default: trust)" NNL
"  -d, --debug              Print debug information to stderr." NNL
"  -g, --user-agent=NAME    Use NAME as the user agent for contacting IAS." NNL
"  -k, --key=HEXSTRING      The private key as a hex string. See --key-file" NL
"                           for notes. Can't combine with --key-file." NNL
"  -l, --linkable           Request a linkable quote (default: unlinkable)." NNL
"  -p, --proxy=PROXYURL     Use the proxy server at PROXYURL when contacting" NL
"                           IAS. Can't combine with --no-proxy" NNL
"  -r, --api-version=N      Use version N of the IAS API (default: " << to_string(IAS_API_DEF_VERSION) << ")" NNL
"  -v, --verbose            Be verbose. Print message structure details and" NL
"                           the results of intermediate operations to stderr." NNL
"  -x, --no-proxy           Do not use a proxy (force a direct connection), " NL
"                           overriding environment." NNL
"  -z  --stdio              Read from stdin and write to stdout instead of" NL
"                           running as a network server." <<endl;

	::exit(1);
}

/*
# vim:ts=4:
*/

