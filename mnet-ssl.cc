#include "mnet-ssl.h"
#include <errno.h>

namespace mnet {

SSLSocket::SSLStatus SSLSocket::DoRead( NetState* state ) {
    static const int k64K = 1<<16;
    // For SSL, a single maximum packet is 64K, so we just put it on the
    // stack to avoid too much burden for malloction of buffer
    char whole_packet[k64K];
    // When this function gets called, the underlying socket should
    // already have some data available for us to consume.
    Buffer::Accessor input = socket_->read_buffer().GetReadAccessor();
    // Inject these input into the mem_bio using bio method here
    int size = BIO_write( read_bio_ , input.address(), input.size() ); 
    // Checking the return value from BIO_write
    if( size < 0 ) {
        // This should not be so, but if we meet BIO failed, typically
        // we have something error that we could not handle here
        *state = NetState( ENOBUFS );
        return SSLStatus();
    } else {
        input.set_committed_size( size );
    }

    // Now try to read from SSL file descriptors
    size = SSL_read( ssl_, whole_packet , k64K );
    if( size <= 0 ) {
        return SSLStatus( size , SSL_get_error(ssl_,size) );
    } else {
        if( !read_buffer_.Inject( whole_packet , size ) ) {
            *state = NetState( ENOBUFS );
            return SSLStatus();
        } 
        return SSLStatus(size,0);
    }
}


SSLSocket::SSLStatus SSLSocket::DoWrite( NetState* state ) {
    Buffer::Accessor output = write_buffer_.GetReadAccessor();

    // We don't enable partial write (for us it doesn't make much
    // senses). If we cannot write, the only reason for this is that
    // we want read, otherwise we will treat it as inrecoverable 
    // error.
     
    int size = SSL_write(ssl_,output.address(),output.size());
    if( size <= 0 ) {
        // In most cases, this means that the SSL want to read (rehandshake).
        // We enable memory BIO , it is not possible to run out of memory
        return SSLStatus(size,SSL_get_error(ssl_,size));
    } else {
        VERIFY( size == output.size() );
        // Drain the buffer from underlying BIO into the 
        // socket write buffer here
        socket_->write_buffer().Reserve(BIO_pending( write_bio_ ));

        Buffer::Accessor write_accessor = 
            socket_->write_buffer().WriteAccessor();

        // Writing the data from SSL internal BIO into the output
        // buffer in our underlying socket
        int sz = BIO_write( write_bio_ ,
                write_acessor.address() , write_acessor.size() );

        VERIFY( sz == write_acessor.size() );
        write_acessor.set_committed_size(sz);
    }

    output.set_committed_size( output.size() );

    // Now, all the data has been encoded so we just issue we want to
    // write output the data. Once the callback calls, inside of it 
    // we will call our user's registered callback function there
    socket_->AsyncWrite( this );
    return SSLStatus();
}

}// namespace mnet
