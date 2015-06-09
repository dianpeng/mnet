#include "../../mnet.h"
#include <signal.h>
using namespace mnet;

class Server {
public:
    Server();

    void OnAccept( Socket* new_socket , const NetState& ok );
    void OnRead( Socket* socket , std::size_t size , const NetState& ok );
    void OnWrite( Socket* socket , std::size_t size , const NetState& ok );
    void Run() {
        io_manager_.RunMainLoop();
    }
    void WakeUp() {
        io_manager_.Interrupt();
    }

private:
    int times_; // Times for each echo request
    int fd_fail_; 
    ServerSocket server_; // ServerSocket 
    IOManager io_manager_; // IOManager
    Socket* socket_; 
};


Server::Server():
    times_(0),
    fd_fail_(0),
    server_(),
    io_manager_(),
    socket_( NULL )
{
    server_.Bind( Endpoint( "127.0.0.1:12345" ) );
    server_.SetIOManager(&io_manager_);
    socket_ = new Socket( &io_manager_ );
    server_.AsyncAccept( socket_ , this );
}

void Server::OnAccept( Socket* new_socket , const NetState& ok ) {
    if(ok) {
        // Start to read
        new_socket->AsyncRead( this );
        ++times_;
        server_.AsyncAccept( new Socket( &io_manager_ ) , this );
    } else {
        delete new_socket;
        if( ok.error_code() != EMFILE && 
            ok.error_code() != ENFILE ) {
        } else {
            std::cout<<"Run out FD!Force to shutdown!"<<std::endl;
            ++fd_fail_;
            std::cout<<fd_fail_<<std::endl;
        }
        server_.AsyncAccept( new Socket( &io_manager_ ) , this );
    }
}

void Server::OnRead( Socket* socket , std::size_t size , const NetState& ok ) {
    if( ok ) {
        if( size == 0 ) {
            socket->Close();
            delete socket;
        } else {
            // Dump whatever we have here
            std::size_t read_sz = socket->read_buffer().readable_size();
            void* buf = socket->read_buffer().Read(&read_sz);
            socket->write_buffer().Write( buf , read_sz );
            socket->AsyncWrite( this );
            socket->AsyncRead( this );
        }
    } else {
        socket->Close();
        delete socket;
    }
}

void Server::OnWrite( Socket* socket , std::size_t size , const NetState& ok ) {
}

Server* GServer;

void onsignal( int val ) {
    GServer->WakeUp();
}

int main() {
    Server s;
    signal(SIGTERM,onsignal);
    signal(SIGINT,onsignal);
    signal(SIGTSTP,onsignal);
    signal(SIGPIPE,SIG_IGN);
    GServer = &s;
    s.Run();
    std::cout<<"Done!"<<std::endl;
    return 0;
}
