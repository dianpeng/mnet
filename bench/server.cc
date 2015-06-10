#include "../mnet.h"
using namespace mnet;

#define LEN 1024

class Server {
public:
    Server();


    void OnAccept( Socket* new_socket , const NetState& state ) {
        if( !state ) {
            delete new_socket;
        } else {
            // Start the accept the request 
            new_socket->AsyncRead( this );
        }

        server_.AsyncAccept( new Socket( &io_manager_ ) , this );
    }


    void OnRead( Socket* socket , std::size_t len , const NetState& state ) {
        if( !state ) {
            socket->Close();
            delete socket;
        } else {
            if( len == 0 ) {
                socket->Close();
                delete socket;
            } else {
                if( socket->read_buffer().readable_size() == LEN ) {
                    std::size_t sz = LEN;
                    void* mem = socket->read_buffer().Read( &sz );
                    socket->write_buffer().Write( mem , sz );
                    socket->AsyncWrite(this);
                } else {
                    socket->AsyncRead(this);
                }
            }
        }
    }

    void OnWrite( Socket* socket , std::size_t len , const NetState& state ) {
        socket->Close();
        delete socket;
    }

private:
    IOManager io_manager_;
    ServerSocket server_;
};

Server::Server():
    io_manager_(),
    server_()
{
    server_.Bind( Endpoint("127.0.0.1:12345") );
    server_.SetIOManager( &io_manager_ );
    server_.AsyncAccept( new Socket( &io_manager_ ) , this );
    io_manager_.RunMainLoop();
}


int main() {
    Server s;
    return 0;
}
                

