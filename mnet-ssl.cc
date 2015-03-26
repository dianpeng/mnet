#include "mnet-ssl.h"
#include <errno.h>
#include <stdlib.h>
#include <algorithm>

#ifndef NDEBUG
#define VERIFY assert
#else
#define(X) \
    do { \
        if( !(X) ) { \
            fprintf(stderr,"Assertion:%s failed!"); \
            abort(); \
        } \
    } while(0)
#endif // NDEBUG

#ifndef NDEBUG
#define UNREACHABLE(X) \
    do { \
        assert(0&&"UNREACHABLE"); \
        X; \
    } while(0)
#else
#define UNREACHABLE(X) \
    do { \
        __builtin_unreachable(); \
    } while(0)
#endif // NDEBUG

namespace mnet {

SSLSocket::SSLStatus SSLSocket::DoRead( NetState* state ) {
    static const int k64K = 1<<16;
    // For SSL, a single maximum packet is 64K, so we just put it on the
    // stack to avoid too much burden for malloction of buffer
    char whole_packet[k64K];
    // When this function gets called, the underlying socket should
    // already have some data available for us to consume.
    Buffer::Accessor input = socket_->read_buffer().GetReadAccessor();
    
    // Since we have a upper bound for BIO buffer, therefore we cannot
    // write as much as we can, instead we will check how much we can
    // write to the underlying BIO buffer
    std::size_t max_write_buffer = BIO_ctrl_get_write_guarantee( out_bio_ );
    std::size_t write_size = std::min( max_write_buffer,input.size());
    int actual_write_size = BIO_write( out_bio_ , input.address(), write_size );

    // We are absolutely sure that we will not fail on this situtaions, otherwise
    // the memory should be fucked up .
    VERIFY( static_cast<std::size_t>( 
                actual_write_size ) == write_size );
    
    // Set committed size for the buffer
    input.set_committed_size( actual_write_size );

    // Now hit the SSL_read to read from the current data.
    // Notes: it is still possible that the SSL doesn't satisfy the length of
    // the content which results in another requesting for read on underlying
    // socket. We should not ignore this situation as well
    do {
        // Using a 64K buffer to read as much as we could from the SSL
        int size = SSL_read( ssl_, whole_packet , k64K );
        if( size <= 0 ) {
            return SSLStatus( size, SSL_get_error(ssl_,size) );
        } else {
            // SSL data has been corrected read out, so just return
            // how much data we have been read and then notify the user
            return SSLStatus(size,0);
        }
    } while( true );

    UNREACHABLE(return SSLStatus());
}


SSLSocket::SSLStatus SSLSocket::DoWrite( NetState* state ) {
    Buffer::Accessor output = write_buffer_.GetReadAccessor();
    int encoded_size = 0;

    // For write, we will enable SSL enable partial write. Therefore
    // SSL should never run out of the memory. We can encode the whole
    // data correct with SSL. 
    
    do {
        int size = SSL_write( ssl_ , output.address() , output.size() );
        if( size <= 0 ) {
            // This is very rare error since we should not run out of the
            // buffer for mode enable partial write.
            return SSLStatus(size,SSL_get_error(ssl_,size));
        } else {
            encoded_size += size;
            // We have write some data into the buffer now, we can read it 
            // from the underlying BIO and inject it into our output buffer
            std::size_t writed_size = BIO_pending(out_bio_);

            if( writed_size != 0 ) {
                // Inject the data into the output buffer 
                socket_->write_buffer().Reserve( writed_size );

                Buffer::Accessor underlying_socket_output = 
                    socket_->write_buffer().GetWriteAccessor();

                int ssl_write_size = BIO_read( out_bio_ ,
                        underlying_socket_output.address(),
                        underlying_socket_output.size() );

                VERIFY( static_cast<std::size_t>(ssl_write_size) == writed_size );
            }

            if( static_cast<std::size_t>(encoded_size) == output.size() )
                break; // We are done here
        } 
    } while( true );

    // We have already written all the user space data into underlying SSL
    // however we need to schedule the write intention to the underlying 
    // socket. Until we get a successful notification from underlying socket
    // we will hit user's callback function then.
    output.set_committed_size( output.size() );

    // Now, all the data has been encoded so we just issue we want to
    // write output the data. Once the callback calls, inside of it 
    // we will call our user's registered callback function there
    socket_->AsyncWrite( this );

    return SSLStatus();
}

}// namespace mnet
