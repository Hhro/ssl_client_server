#include "server.h"

using namespace std;

void usage(){
    cout << "Usage: ./ssl_server <port> [-b]" << endl;
    cout << "Example: ./ssl_server 31337 -b" << endl;
}

int main(int argc, char *argv[]){
    int mode;

    if(argc < 2){
        usage();
        exit(1);
    }

    if(argc == 3 && string(argv[2]) == string("-b"))
        mode = BROADCAST_MODE | SSL_MODE;
    else
        mode = ECHO_MODE | SSL_MODE;

    event_init();
    Server *srv= new Server(atoi(argv[1]), mode);

    srv->run_server();
    
    delete(srv);
    return 0;
}