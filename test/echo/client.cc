#include "../../mnet.h"
#include <iostream>
#include <string>
#include <vector>
#include <iterator>
#include <fstream>

using namespace mnet;

class Client {
public:
    Client( const char* str , int num ) :
        io_manager_(),
        info_(str),
        client_socket_array_()
    {
        client_socket_array_.reserve( num );
        for( int i = 0 ; i <num ; ++i ) {
            ClientSocket* s = new ClientSocket( &io_manager_ ) ;
            s->AsyncConnect( Endpoint("127.0.0.1:12345"),this );
            client_socket_array_.push_back(s);
        }
    }


    void Run() {
        io_manager_.RunMainLoop();
    }

    void OnConnect( Socket* socket , const NetState& state );
    void OnWrite( Socket* socket , size_t size , const NetState& state );
    void OnRead( Socket* socket , size_t size , const NetState& state );

private:
    IOManager io_manager_;
    std::string info_;
    std::vector< ClientSocket* > client_socket_array_;
};


void Client::OnConnect( Socket* socket , const NetState& ok ) {
    if(!ok) {
        std::cerr<<"Cannot connect:"<<std::strerror(ok.error_code())<<std::endl;
        io_manager_.Interrupt();
        return;
    } else {
        char end = 0;
        socket->write_buffer().Write( info_.c_str() , info_.size() );
        socket->write_buffer().Write(&end,1);
        socket->AsyncWrite(this);
    }
}

void Client::OnWrite( Socket* socket, size_t size , const NetState& ok ) {
    if(!ok) {
        std::cerr<<"Cannot write:"<<std::strerror(ok.error_code())<<std::endl;
        io_manager_.Interrupt();
        return;
    } else {
        socket->AsyncRead(this);
    }
}

void Client::OnRead( Socket* socket, size_t size , const NetState& ok ) {
    if(!ok) {
        std::cerr<<"Cannot read:"<<std::strerror(ok.error_code())<<std::endl;
        io_manager_.Interrupt();
        return;
    } else {
        if( size == 0 ) {
            io_manager_.Interrupt();
            return;
        }
        size_t read_sz = socket->read_buffer().readable_size();
        void* mem = socket->read_buffer().Read(&read_sz);
        std::cout<<(char*)(mem)<<std::endl;
        socket->AsyncRead(this);
        return;
    }
}


int main( int argc , char* argv[] ) {
    if( argc != 3 && argc != 4 ) {
        std::cerr<<"Usage: string/file"<<std::endl;
        return -1;
    }
    if( argc == 3 ) {
        Client c(argv[1],atoi(argv[2]));
        c.Run();
    } else {
        // Read the file into the memory and dump it
        std::fstream file(argv[2]);
        if( !file ) {
            std::cerr<<"File:"<<argv[2]<<" is not existed!"<<std::endl;
            return -1;
        }
        std::istream_iterator<char> ibeg(file) , iend;
        file>>std::noskipws;
        std::string buf;

        while( ibeg != iend ) {
            buf.push_back( *ibeg );
            ++ibeg;
        }

        Client c(buf.c_str(),atoi(argv[3]));
        c.Run();
    }
    return 0;
}
