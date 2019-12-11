#pragma once 

#include <cstring>

#define MSG_SZ  16384

class Message{
    private:
        int m_from_fd;
        int m_to_fd;
        int m_len;
        char m_content[MSG_SZ];
    public:
        Message(int from_fd, int to_fd, int len, char *content):
            m_from_fd(from_fd), m_to_fd(to_fd), m_len(len){
                memcpy(m_content, content, m_len);
             }
        const int get_to_fd() const { return m_to_fd; }
        const int get_from_fd() const { return m_from_fd; }
        const int get_len() const { return m_len; }
        const char* get_content() const { return m_content; }
};
