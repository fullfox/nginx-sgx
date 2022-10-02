#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <unistd.h>
#include <pthread.h>



// Proto
int generate_http_response(char * buf, const char * msg, char * status);
int retrieve_header_value(char * req, const char * header, char * value);
int retrieve_uri(char * req, char * uri);
int retrieve_method(char * req, char * method);
int hex_to_bytes(unsigned char * signature_bytes, char * signature);
int send_safe(int fd, void * buf, size_t len, int flags);



int generate_http_response(char * buf, const char * msg, char * status){
    char date[100];
    time_t now = time(0);
    struct tm tm = *gmtime(&now);
    strftime(date, 100, "%a, %d %b %Y %H:%M:%S %Z", &tm);  

    return sprintf(buf,"HTTP/1.1 %s\r\n"
        "Date: %s\r\n"
        "Server: HTTP-SRV-C\r\n"
        "Content-Length: %i\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "%s", status, date, (int) strlen(msg), msg);
}


int retrieve_header_value(char * req, const char * header, char * value){
    char * header_ptr = strstr(req, header);
    if(header_ptr == NULL) return -1;

    char * value_start_ptr = strstr(header_ptr, ": ");
    if(value_start_ptr == NULL) return -1;
    value_start_ptr+=2;

    char * value_end_ptr = strstr(value_start_ptr, "\r\n");
    if(value_end_ptr == NULL) return -1;

    strncpy(value, value_start_ptr, value_end_ptr-value_start_ptr);
    return 0;
}

int retrieve_uri(char * req, char * uri){
    char * uri_start_ptr = strstr(req, " ");
    if(uri_start_ptr == NULL) return -1;
    uri_start_ptr+=1;

    char * uri_end_ptr = strstr(uri_start_ptr, " ");
    if(uri_end_ptr == NULL) return -1;

    strncpy(uri, uri_start_ptr, uri_end_ptr-uri_start_ptr);   
    return 0;    
}

int retrieve_method(char * req, char * method){
    char * method_end_ptr = strstr(req, " ");
    if(method_end_ptr == NULL) return -1;

    int method_len = method_end_ptr - req;
    if(method_len > 7) return -1;

    strncpy(method, req, method_len);

    return 0;
}

int hex_to_bytes(unsigned char * signature_bytes, char * signature){
    int i;
    for (i = 0; i < strlen(signature); i+=2){
        char hex[3] = {'\0'};
        strncpy(hex, signature+i, 2);
        signature_bytes[i/2] = (unsigned char) strtol(hex, NULL, 16);
    }
    return i/2;
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