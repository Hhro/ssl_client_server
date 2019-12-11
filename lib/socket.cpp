#include "socket.h"

void Socket::set_addr(struct sockaddr_in & addr){
    m_addr.sin_family = addr.sin_family;
    m_addr.sin_port = addr.sin_port;
    m_addr.sin_addr.s_addr = addr.sin_addr.s_addr;
}

bool Socket::set_nonblock_mode(){
    int flags;

    flags = fcntl(m_fd, F_GETFL);
    if(flags<0)
        return false;

    flags |= O_NONBLOCK;

    if(fcntl(m_fd, F_SETFL, flags) < 0)
        return false;
    
    return true;
}