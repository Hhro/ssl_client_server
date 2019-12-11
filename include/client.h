#pragma once

#include "socket.h"

class Client: public Socket{
    public:
        explicit Client(int fd, struct sockaddr_in & addr){
            m_fd = fd;
            m_addr = addr;
        }
};
