all: server.c server_batch.c server_common.h
	gcc -g -Wall -Wno-deprecated-declarations -o bin/AESserver server.c -lcrypto -pthread -DAES_SIG=1
	gcc -g -Wall -Wno-deprecated-declarations -o bin/RSAserver server.c -lcrypto -pthread -DAES_SIG=0
	gcc -g -Wall -Wno-deprecated-declarations -o bin/PINGserver server.c -lcrypto -pthread -DPING=1
	gcc -g -Wall -Wno-deprecated-declarations -o bin/batchAESserver server_batch.c -lcrypto -pthread -DAES_SIG=1
	gcc -g -Wall -Wno-deprecated-declarations -o bin/batchRSAserver server_batch.c -lcrypto -pthread -DAES_SIG=0
	gcc -g -Wall -Wno-deprecated-declarations -o bin/batchPINGserver server_batch.c -lcrypto -pthread -DPING=1
#gcc -g -Wall -o bin/client client.c -lcrypto -pthread

clean: 
	$(RM) bin/*
