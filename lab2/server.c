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

#define PORT 8765
#define KEYFILE "bob.pem"
#define PASSWORD "password"
#define CIPHER_LIST "SSLv2:SSLv3:TLSv1"

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

int tcp_listen(int port);
void check_cert(SSL *ssl);


int main(int argc, char **argv)
{
	int s, r, sock, port = PORT;
	pid_t pid;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO* sbio;
	
	/*Parse command line arguments*/
	switch (argc)
	{
		case 1:
			break;
		case 2:
			port = atoi(argv[1]);
			if (port < 1 || port > 65535)
			{
				fprintf(stderr, "invalid port number");
				exit(0);
			}
			break;
		default:
			printf("Usage: %s port\n", argv[0]);
			exit(0);
	}

	/* Build the SSL context*/
	ctx = initialize_ctx(KEYFILE, PASSWORD);
	SSL_CTX_set_cipher_list(ctx, CIPHER_LIST);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

	sock = tcp_listen(port);

	while (1)
	{
		if ((s = accept(sock, NULL, 0)) < 0)
		{
			perror("accept");
			close(sock);
			close(s);
			exit(0);
		}

		/*fork a child to handle the connection*/
		if ((pid = fork()))
		{
			close(s);
		}
		else
		{
			/*Child code*/
			char buf[256];
			char *answer = "42";

			ssl = SSL_new(ctx);
			sbio = BIO_new_socket(s, BIO_NOCLOSE);
			SSL_set_bio(ssl, sbio, sbio);

			if ((r = SSL_accept(ssl) <= 0))
				berr_exit(FMT_ACCEPT_ERR);

			check_cert(ssl);

			/* Read bytes from a SSL connection*/
			int r = SSL_read(ssl, buf, 256);
			
			switch (SSL_get_error(ssl, r))
			{
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_ZERO_RETURN:
					r = SSL_shutdown(ssl);
					switch (r)
					{
						case 0:
							r = SSL_shutdown(ssl);
							if (r != 1){
								berr_exit(FMT_INCOMPLETE_CLOSE);
							}
						case 1:
							// Success
							break;
						default:
							berr_exit(FMT_INCOMPLETE_CLOSE);
					}
				case SSL_ERROR_SYSCALL:
					berr_exit(FMT_INCOMPLETE_CLOSE);
				default:
					BIO_printf(bio_err, FMT_OUTPUT, "SSL accept error", "");
					ERR_print_errors(bio_err);
					exit(1);
			}
			buf[r] = '\0';
			printf(FMT_OUTPUT, buf, answer);

			/* Write bytes to a SSL connection.*/
			int w = SSL_write(ssl, answer, strlen(answer));
			switch (SSL_get_error(ssl, w))
			{
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_SYSCALL:
					berr_exit(FMT_INCOMPLETE_CLOSE);
					break;
				default:
					BIO_printf(bio_err, FMT_OUTPUT, "SSL accept error", "");
					ERR_print_errors(bio_err);
					exit(1);
			}
			
			SSL_free(ssl);
			close(sock);
			close(s);
			return 0;
		}
	}
	destroy_ctx(ctx);
	close(sock);
	return 1;
}

int tcp_listen(int port)
{
	int sock;
	struct sockaddr_in sin;
	int val = 1;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket");
		close(sock);
		exit(0);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
		perror("bind");
		close(sock);
		exit(0);
	}

	if (listen(sock, 5) < 0)
	{
		perror("listen");
		close(sock);
		exit(0);
	}

	return sock;
}

void check_cert(SSL *ssl)
{
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];

    if (SSL_get_verify_result(ssl) != X509_V_OK)
        berr_exit(FMT_ACCEPT_ERR);

    peer = SSL_get_peer_certificate(ssl);
	
    /*Get client common name*/
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    
	/*Cet client email*/
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);
    
    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
}