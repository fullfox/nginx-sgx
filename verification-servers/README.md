
# verification servers
Compile with ``make``, 
the available servers are:
- ``AESserver`` ( verify AES 256bits HMACS, at every request )
- ``RSAserver`` ( verify RSA 2048bits signature, at every request )
- ``PINGserver`` ( simply answer 'ping' at every request )

- ``batch[Previous servers]`` ( bufferize requests until it receives the *buffer_size*-th one, then verify and process requests )
## Usage
``./[server binary] [port]``
or
``./[server binary] [port] [buffer_size]`` for batch modes

## Flags
- if ``LOGGING`` is true, will print data and stats for every received and processed request.
- if ``LOG_REQ`` is true, every received request will be printed to STDOUT.
- if ``AES_SIG`` is true, server will verify AES HMAC instead of RSA Signature.
- if ``PING`` is true, the server just answer 'ping' at every request.

## Required file
When in RSA mode, the server must found the ``public.pem`` file containing the RSA public key.