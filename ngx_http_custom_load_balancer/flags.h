// OPTIONS:

//Modes: (only one at a time)
    // Signature, no SGX
    #define NO_SGX_FOR_SIG          0 // If enabled, do the signature outside of the enclave

    // No signature, SGX
    #define EMPTY_ECALL             0 // Decision outside of enclave, but still do an empty ecall (so no sig), for delay measuring purpose

    // No signature, no SGX
    #define NO_ECALL                0 // Dont do the ecall (so the module is doin the same as the original nginx one)



// Logging
#define PREVENT_LOGGING         0 // If enabled, override printf with empty func to avoid logging latency

// Encryption
#define AES_SIG                 0
#define AES_PASSWORD            "tortue" // any string, define the AES symetric encryption key.

// Batch
#define BATCH_MODE              0
#define BATCH_SIZE              10



// Misc, do not modify
#if AES_SIG
    #define SIGNATURE_LENGTH        32
#else
    #define SIGNATURE_LENGTH        256
#endif

#define MAX_LENGTH_DECISION     32
#define MAX_REQ_SIZE            6160
