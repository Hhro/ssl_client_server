#pragma once

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class Socket{
    protected:
        int m_fd;
        struct sockaddr_in m_addr = {};
    
    public:
        Socket() {}
        const int get_fd() const { return m_fd; }
        const struct sockaddr_in & get_addr() const { return m_addr; }
        void set_fd(int fd);
        void set_addr(struct sockaddr_in & addr);
        bool set_nonblock_mode();
};
