#include "../mnet.h"
#include <sys/types.h>
#include <sys/time.h>
#include <inttypes.h>

using namespace mnet;

uint64_t GetTimeInMS() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec * 1000 + tv.tv_usec/1000;
}

#define LEN 1024
char CONTENT[LEN];

class Client {
public:
    Client( int times ):
        io_manager_(),
        start_(0),
        end_(0),
        times_(times)
    {
        for( int i = 0 ; i < times ; ++i ) {
            ClientSocket* cl = new ClientSocket( &io_manager_ );
            cl->AsyncConnect( Endpoint("127.0.0.1:12345") , this );
        }

        start_ = GetTimeInMS();
        io_manager_.RunMainLoop();
    }


    void OnConnect( Socket* new_socket , const NetState& ok ) {
        if(!ok) {
            std::cerr<<"FAILED!:"<<std::strerror(ok.error_code())<<std::endl;
            return;
        } else {
            new_socket->write_buffer().Write( CONTENT, LEN );
            new_socket->AsyncWrite(this);
        }
    }

    void OnWrite( Socket* new_socket , std::size_t len , const NetState& ok ) {
        if(!ok) {
            std::cerr<<"FAILED!:"<<std::strerror(ok.error_code())<<std::endl;
            return;
        } else {
            new_socket->AsyncRead(this);
        }
    }

    void OnRead( Socket* new_socket , std::size_t len , const NetState& ok ) {
        if(!ok) {
            std::cerr<<"FAILED!:"<<std::strerror(ok.error_code())<<std::endl;
            return;
        } else {
            if( new_socket->read_buffer().readable_size() == LEN ) {
                new_socket->Close();
                delete new_socket;
                --times_;
                if( times_ == 0 ) {
                    end_ = GetTimeInMS();
                    std::cout<<"Diff:"<<end_-start_<<std::endl;
                    io_manager_.Interrupt();
                }
            } else {
                new_socket->AsyncRead(this);
            }
        }
    }

private:
    IOManager io_manager_;
    uint64_t start_;
    uint64_t end_;
    int times_;
};

int main() {
    Client c(1000);
    return 0;
}







