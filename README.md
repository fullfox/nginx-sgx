
# ngx_http_sgx_load_balancer
**ngx_http_sgx_load_balancer** is a load-balancing module for _**NGINX**_, that uses _**Intel SGX technology**_


## Getting started
First, setup the environnement:
 ```
 ./setup_nginx_env
 ```


Then configure nginx Makefiles with:
```
./custom_configure
```

Then compile both the module and nginx with:
```
./compile
```

Finally, nginx is ready to be run through ``./nginx``. It is needed to run the attestation server ( at startup of nginx only, it's useless after ), with ``cd sgx-ra-sample && ./run-server``.

## Modes
The nginx module can run in different modes, they are defined in the ``ngx_http_custom_load_balancer/flags.h`` file.


## Requirements
Intel SGX SDK should be installed in ``/opt/intel/sgxsdk``.
When running the RSA signature mode, the ``key.pem`` file containing the RSA private key must be found by the ``nginx`` binary.

## Shared libs
Two shared libraries can be found at the root of the directory:
- ``client_lib.so``, for the attestation on startup
- ``enclave.signed.so``, even if the enclave is not used because of the mode, it is still needed at startup to decode the peers list from the attestation server.


## 
**Verification servers** are detailed in README.md file is in ``verification-servers/``
The **load injection** is explained in the README.md file is in ``load-injection/``

## To improve
Signatures or HMACS are currently passed in hexadecimal throught a custom HTTP header, it can be improved by using Base64 instead.