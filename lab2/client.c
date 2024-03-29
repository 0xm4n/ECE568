#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#define HOST "localhost"
#define PORT 8765
#define KEYFILE "alice.pem"
#define PASSWORD "password"
#define SERVER_CN "Bob's Server"
#define SERVER_EMAIL "ece568bob@ecf.utoronto.ca"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

int tcp_connect(char *host, int port);
void check_cert(SSL *ssl);
int read_write(SSL *ssl, char *req, char *res);

int main(int argc, char **argv)
{
    int sock;
	int port = PORT;
    char *host = HOST;
    char buf[256];
    char *secret = "What's the question?";
    SSL_CTX *ctx;
	SSL *ssl;
    BIO *sbio;

    /*Parse command line arguments*/
    switch (argc)
    {
		case 1:
			break;
		case 3:
			host = argv[1];
			port = atoi(argv[2]);
			if (port < 1 || port > 65535)
			{
				fprintf(stderr, "invalid port number");
				exit(0);
			}
			break;
		default:
			printf("Usage: %s server port\n", argv[0]);
			exit(0);
    }

    /* Connect the TCP socket*/
    sock = tcp_connect(host, port);

    /* Build the SSL context*/
    ctx = initialize_ctx(KEYFILE, PASSWORD);
	
	/* Set the SSL version*/
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	
    /* Set the cipher list*/
    SSL_CTX_set_cipher_list(ctx, "SHA1");

    /* Connect the SSL socket */
    ssl = SSL_new(ctx);
    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
	
    if (SSL_connect(ssl) <= 0)
        berr_exit(FMT_CONNECT_ERR);
	
    check_cert(ssl);

    /* read and write */
    read_write(ssl, secret, buf);

    /* this is how you output something for the marker to pick up */
    printf(FMT_OUTPUT, secret, buf);

	destroy_ctx(ctx);
    close(sock);
    return 1;
}

int tcp_connect(char *host, int port)
{
	int sock;
    struct sockaddr_in addr;
    struct hostent *host_entry;
	
    /*get ip address of the host*/
    host_entry = gethostbyname(host);
	
    if (!host_entry)
    {
        fprintf(stderr, "Couldn't resolve host");
        exit(0);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr = *(struct in_addr *)host_entry->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr), port);

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        perror("socket");
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        perror("connect");

    return sock;
}

void check_cert(SSL *ssl)
{
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];
    char peer_certificate_issuer[256];

    if (SSL_get_verify_result(ssl) != X509_V_OK)
        berr_exit(FMT_NO_VERIFY);

    peer = SSL_get_peer_certificate(ssl);
	
    /*Check the common name*/
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    
	/*Check the email*/
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);

    if (strcasecmp(peer_CN, SERVER_CN))
        err_exit(FMT_CN_MISMATCH);

    if (strcasecmp(peer_email, SERVER_EMAIL))
        err_exit(FMT_EMAIL_MISMATCH);
	
	/*Get the certificate issuer*/
	X509_NAME_get_text_by_NID(X509_get_issuer_name(peer), NID_commonName, peer_certificate_issuer, 256);

    printf(FMT_SERVER_INFO, peer_CN, peer_email, peer_certificate_issuer);
}

int read_write(SSL *ssl, char *req, char *res)
{
	int w, r, s;
	int txt_len = strlen(req);
	
	/* Write bytes to a SSL connection.*/
	w = SSL_write(ssl, req, txt_len);
	switch(SSL_get_error(ssl,w)){      
		case SSL_ERROR_NONE:
			if(txt_len != w)
				err_exit("Incomplete Write");
			break;
		case SSL_ERROR_SYSCALL:
			berr_exit(FMT_INCORRECT_CLOSE);
		default:
			BIO_printf(bio_err, FMT_OUTPUT, "SSL connect error", "");
            ERR_print_errors(bio_err);
			exit(1);
    }
	
	/* Read bytes from a SSL connection*/
	while(1){
		r = SSL_read(ssl, res, BUFSIZZ);
		switch(SSL_get_error(ssl, r)) {
			case SSL_ERROR_NONE:
				res[r] = '\0';
				return 0;
			case SSL_ERROR_ZERO_RETURN:
				s = SSL_shutdown(ssl);
				switch (s) {
					case 1:
						break;
					default:
						berr_exit("Failed to shutdown");
				}
			case SSL_ERROR_SYSCALL:
				berr_exit(FMT_INCORRECT_CLOSE);
			default:
				BIO_printf(bio_err, FMT_OUTPUT, "SSL connect error", "");
				ERR_print_errors(bio_err);
				exit(1);
		}
    }
}
