#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netdb.h>

#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>

#define TIMEOUT 10

long max(long a, long b) {
    if(a>b) return a;
    return b;
}

long min(long a, long b) {
    if(a>b) return b;
    return a;
}

int send_safe(int fd, void * buf, size_t len, int flags);
void * HTTPrequest(void * arg);
void generateStats();
void generateJSON(const char * filename, const char * name);


typedef struct {
    int id;
    int status;
    long start;
    long stop;
    long delay;
} request_stats_t;


struct sockaddr_in addr;
char * req_ptr;
long requests_number = 0;
int r_per_sec, duration_sec;

request_stats_t * request_stats_list_ptr, * request_stats_list_ptr_final;

int main(int argc, char const *argv[])
{

    if(argc != 5 && argc != 6){printf("Usage: ./client [ip] [port] [request per sec] [duration] [filename.json (optional)]\n"); exit(1);}

    // Load param
    r_per_sec = atoi(argv[3]);
    duration_sec = atoi(argv[4]);
    requests_number = duration_sec * r_per_sec;

    // Request param
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    inet_aton(argv[1], &addr.sin_addr);
    addr.sin_addr.s_addr = INADDR_ANY;    

    char req[] = 
    "GET / HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Accept: text/html\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Connection: close\r\n"
    "\r\n";
    req_ptr = req;

    request_stats_list_ptr = malloc(sizeof(request_stats_t) * requests_number);
    memset(request_stats_list_ptr, 0, sizeof(request_stats_t) * requests_number);

    // Threading
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN/2);

    pthread_t thread_id[requests_number];
    for (int sec = 0; sec < duration_sec; sec++)
    {
        for (int i = 0; i < r_per_sec; i++){
            int * id = malloc(sizeof(int));
            *id = sec*r_per_sec +i;
            int err = pthread_create(&thread_id[*id], &attr, HTTPrequest, (void *) id);
            if(err != 0){printf("err %i\n\n", err);}
            pthread_detach(thread_id[sec*r_per_sec +i]);

            printf("\r%i%%",   (int) ((100 *(sec*r_per_sec+i+1))/(requests_number)));fflush(stdout);
        }
        sleep(1);
    }
    printf("\n");


    request_stats_list_ptr_final = malloc(sizeof(request_stats_t) * requests_number);
    memcpy(request_stats_list_ptr_final, request_stats_list_ptr, sizeof(request_stats_t) * requests_number);



    generateStats();
    char name[32] = {'\0'}; sprintf(name, "r-%ix%i",r_per_sec, duration_sec);

    if(argc == 6){
        generateJSON(argv[5], name);
    } else {
        generateJSON("data.json", name);
    }
    

    free(request_stats_list_ptr_final);
    return 0;
}


// Status:
//          0: requete pas finis
//          1: requete terminé correctement
//         -1: paquet recu invalide
//         -2: connexion non établie
void * HTTPrequest(void * arg){

    int id = * ((int *) arg);
    request_stats_list_ptr[id].id = id;

    char resp[1024] = {'\0'};
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    struct timeval stop, start;


    gettimeofday(&start, NULL);
    if(connect(sockfd,(struct sockaddr *) &addr, INET_ADDRSTRLEN) != -1) {
    send_safe(sockfd,req_ptr, strlen(req_ptr), 0);
    recv(sockfd, resp, 1024, 0);
    } else {
        request_stats_list_ptr[id].status = -2;
    }
    gettimeofday(&stop, NULL);

    char check[5] = {'\0'}; strncpy(check, resp, 4);
    if(strcmp(check,"HTTP") == 0) {
        request_stats_list_ptr[id].status = 1;
    } else {
        request_stats_list_ptr[id].status = -1;
    }

    request_stats_list_ptr[id].delay = (stop.tv_sec * 1000000 + stop.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec);

    request_stats_list_ptr[id].start = start.tv_sec * 1000000 + start.tv_usec;
    request_stats_list_ptr[id].stop = stop.tv_sec * 1000000 + stop.tv_usec;
    

    close(sockfd);
    free(arg);
    return (void *) NULL;
}

void generateStats(){

    long delay_max = 0;
    long delay_min = __INT_MAX__;
    long drop = 0;

    for (size_t i = 0; i < requests_number; i++) {

        if(request_stats_list_ptr_final[i].status == 1){
            long delay = request_stats_list_ptr_final[i].delay;
            delay_max = max(delay_max, delay);
            delay_min = min(delay_min, delay);
        } else {drop++;}
    }
    
    printf("rate = %ireq/s  , duration = %is\n", r_per_sec, duration_sec);
    printf("max: %.2lf ms\n",(float) delay_max/1000);
    printf("min: %.2lf ms\n",(float) delay_min/1000);
    printf("loss: %ld of %ld (%ld%%)\n", drop, requests_number, 100*drop/requests_number);
    printf("output rate: %ld responses per second\n", (requests_number-drop)/duration_sec); 
}

void generateJSON(const char * filename, const char * name){
    FILE *fptr;
    fptr = fopen(filename,"r+");

    if(fptr == NULL){
        fptr = fopen(filename,"w+");
        fprintf(fptr,"{");
    } else {
        fseek(fptr, -1, SEEK_END);
        fprintf(fptr,",");
    }

    fprintf(fptr,"\n\"%s\":{\"requests_per_sec\":%i,\"duration\":%i,", name, r_per_sec, duration_sec);

    //delay
    fprintf(fptr,"\n\"delay\":[");
    for (size_t i = 0; i < requests_number; i++) {
        fprintf(fptr,"%ld,", request_stats_list_ptr_final[i].delay);        
    }
    fseek(fptr, -1, SEEK_CUR);
    fprintf(fptr,"], \n\"status\":[");

    //status
    for (size_t i = 0; i < requests_number; i++) {
        fprintf(fptr,"%i,", request_stats_list_ptr_final[i].status);        
    }
    fseek(fptr, -1, SEEK_CUR);
    fprintf(fptr,"]}}");


    
    fclose(fptr);
}

int send_safe(int fd, void * buf, size_t len, int flags){
    int ret, sent = 0;
    while (sent != len) {
        ret = send(fd, buf+sent, len-sent, flags);
        if(ret == -1) return -1;
        sent+=ret;
    }
    return len;
}