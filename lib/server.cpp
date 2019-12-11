#include "server.h"

using namespace std;

Server::Server(int port, int mode){
    int reuseaddr_on = 1;
    socklen_t addr_len = sizeof(sockaddr);

    m_mode = mode;

    if(m_mode & SSL_MODE){
        activate_ssl();
    }

    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons(port);
    m_addr.sin_addr.s_addr = INADDR_ANY;

    m_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(m_fd < 0)
        error(1, "Failed to Create server socket.");
    if(setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, sizeof(reuseaddr_on)) == -1)
        error(1, "Failed to set server socket reusable.");

    if(set_nonblock_mode() == false){
        error(1, "Failed to set non block mode");
    }

    if(bind(get_fd(), reinterpret_cast<sockaddr *>(&m_addr), addr_len) < 0)
        error(1, "Failed to bind server socket.");
    if(listen(m_fd, 5) < 0) 
        error(1, "Failed to Listen on server socket.");
    
}

void Server::activate_ssl(){
    SSL_library_init();
    m_ssl_ctx = ssl_init_server_ctx();
    ssl_load_certificates(m_ssl_ctx, const_cast<char*>("hhro.pem"), const_cast<char*>("hhro.pem"));
}

SSL_CTX* Server::ssl_init_server_ctx(){
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLSv1_2_server_method();
    ctx = SSL_CTX_new(method);

    if(ctx == NULL){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void Server::ssl_load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


void Server::invoke_cb_accept(int fd, short ev, void *ctx){
    return (static_cast<Server*>(ctx))->cb_accept(fd);
}

void Server::invoke_client_handler(int fd, short ev, void *ctx){
    return (static_cast<Server*>(ctx))->client_handler(fd);
}

void Server::cb_accept(int fd){
    int client_fd;
    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(sockaddr);
    struct event *client_evt = (struct event*)calloc(sizeof(struct event), 1);
    SSL *ssl;
    bool on_ssl;

    if(m_mode & SSL_MODE){
        on_ssl = true;
    }

    client_fd = accept(fd, reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
    if(client_fd == -1){
        warn("[!]Accept client failed");
        return;
    }

    if(on_ssl){
        ssl = SSL_new(m_ssl_ctx);
        SSL_set_fd(ssl, client_fd);
        if(SSL_accept(ssl) == SSL_ACCEPT_FAIL)
            ERR_print_errors_fp(stderr);
    }

    Client *client = new Client(client_fd, client_addr);
    if(client->set_nonblock_mode() == false){
        error(1, "Failed to set client socket as non block mode.");
    }

    m_client_mtx.lock();
    m_clients[client_fd] = client;
    m_client_evts[client_fd] = client_evt;

    if(on_ssl)
        m_client_sslds[client_fd] = ssl;

    m_client_mtx.unlock();

    event_set(client_evt, client_fd, EV_READ|EV_PERSIST, invoke_client_handler, this);
    event_add(client_evt, NULL);

    inet_ntop(AF_INET, &client_addr.sin_addr, ip, INET_ADDRSTRLEN);

    std::cout << "Client from " << ip << "connected" << endl;
}

void Server::client_handler(int fd){
	char buf[MSG_SZ];
	int len, wlen;
    Message *msg = nullptr;
    SSL *ssld = nullptr;

    memset(buf, 0, MSG_SZ);

    if(m_mode & SSL_MODE){
        ssld = m_client_sslds[fd];
        len = SSL_read(ssld, buf, sizeof(buf));
    }
    else{
        len = read(fd, buf, sizeof(buf));
    }

    if (len == 0) {
        /* Connection disconnected */
        cout << "Client disconnected." << endl;
        goto close_conn;
    }
    else if (len < 0) {
        /* Unexpected socket error */
        warn("Unexpected socket error, shutdown connection");
        goto close_conn;
    }

    if(m_mode & BROADCAST_MODE)
        msg = new Message(fd, BROADCAST_FD, len, buf);
    else
        msg = new Message(fd, fd, len, buf);
    
    if(msg == nullptr){
        error(1, "Failed to create message instance.");
    }
    else{
        m_msg_mtx.lock();
        m_msg_queue.push(msg);
        m_msg_mtx.unlock();
    }
    m_msg_cv.notify_one();
    return;

close_conn:
    m_client_mtx.lock();
    m_ssld_mtx.lock();
    close(fd);
    event_del(m_client_evts[fd]);
    delete(m_clients[fd]);

    m_clients.erase(fd);
    m_client_evts.erase(fd);
    m_client_mtx.unlock();
    m_ssld_mtx.unlock();

    if(m_mode & SSL_MODE)
        SSL_free(ssld);
        m_client_sslds.erase(fd);

    return;
}

void Server::msg_handler(){
    const char *content;
    int to_fd;
    int len;
    SSL *ssld = nullptr;

    while(true){
        std::unique_lock<std::mutex> lk(m_msg_mtx);
        m_msg_cv.wait(lk, [&] { return !m_msg_queue.empty(); });
        Message *msg = m_msg_queue.front();
        m_msg_queue.pop();
        lk.unlock();

        to_fd = msg->get_to_fd();
        len = msg->get_len();
        content = msg->get_content();

        m_client_mtx.lock();
        m_ssld_mtx.lock();
        if(to_fd == BROADCAST_FD){
            for(auto fd_client : m_clients){
                if(m_mode & BROADCAST_MODE){
                    ssld = m_client_sslds[fd_client.first];
                    SSL_write(ssld, content, len);
                }
                else{
                    write(fd_client.first, content, len);
                }
            }
        }
        else{
            if(m_mode & BROADCAST_MODE){
                ssld = m_client_sslds[to_fd];
                SSL_write(ssld, content, len);
            }
            else{
                write(to_fd, content, len);
            }
        }
        m_client_mtx.unlock();
        m_ssld_mtx.unlock();

        delete(msg);
    }
}

void Server::run_server(){
    for(int i=0;i<MSGWORKERN;i++){
        m_msg_worker.push_back(std::thread(&Server::msg_handler, this));
    }

    event_set(&m_ev_accept, m_fd, EV_READ|EV_PERSIST, invoke_cb_accept, this);
    event_add(&m_ev_accept, NULL);
    event_dispatch();

    for(int i=0;i<MSGWORKERN;i++){
        m_msg_worker[i].join();
    }
}