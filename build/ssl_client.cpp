#include "server.h"

void usage(){
	printf("Usage : ssl_client <host> <port>\n");
	printf("Example : ssl_client 127.0.0.1 31337\n");
}

SSL_CTX* init_CTX(void){
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void show_certs(SSL* ssl){
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

void do_recv(SSL *ssl){
	char buf[MSG_SZ];
	int len;
	memset(buf, 0, sizeof(buf));

	while (true) {
		len = SSL_read(ssl, buf, sizeof(buf) - 1);
		write(1, buf, len);
	}
}

void do_send(SSL *ssl){
	char buf[MSG_SZ];
	int len;
	memset(buf, 0, sizeof(buf));

	while (true) {
		len = read(0, buf, sizeof(buf) - 1);

		ssize_t sent = SSL_write(ssl, buf, len);
		if (sent == 0) {
			perror("send failed");
			break;
		}
	}
}

int main(int argc, char *argv[]) {
	SSL_CTX *ctx;
	SSL *ssl;

	if(argc != 3){
		usage();
		return -1;
	}

	SSL_library_init();
	ctx = init_CTX();

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2]));
	inet_pton(AF_INET, argv[1], &addr.sin_addr.s_addr);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int res = connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);

	if(SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	else{
		puts("connected");
		show_certs(ssl);
		std::thread rcvr(do_recv, ssl);
		std::thread sndr(do_send, ssl);

		rcvr.join();
		sndr.join();
	}

	close(sockfd);
}
