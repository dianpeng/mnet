#ifndef MNET_SSL_H_
#define MNET_SSL_H_
#include "mnet.h"
#include <openssl/ssl.h>

namespace mnet {
// =================================================================
// MNet ssl supports. The SSL support here will use 
// wrapper like method to support.
// One thing to note: SSL socket doesn't support full
// duplex since it can't do so in following reason :
// 1) OpenSSL has bug with full duplex
// 2) SSL read can map to read or write on underlying socket, same
// as SSL write, however underlying socket only support only one 
// read and write outstanding. To support it I need to queue the 
// read/write operation for underlying socket which is essentially
// not full duplex !
// =================================================================

class SSLSocket {
public:
    SSLSocket( Socket* client_socket );

    template< typename T >
    void AsyncRead( T* notifier );
    
    template< typename T >
    void AsyncWrite( T* notifier );

    template< typename T >
    void AsyncClose( T* notifier );

    Socket* socket() const {
        return socket_;
    }

public:
    Buffer& write_buffer() {
        return write_buffer_;
    }

    Buffer& read_buffer() {
        return read_buffer_;
    }

    const Buffer& write_buffer() const {
        return write_buffer_;
    }

    const Buffer& read_buffer() const {
        return read_buffer_;
    }

public:
    void OnRead( Socket* socket , std::size_t size , const NetState& ok );
    void OnWrite( Socket* socket, std::size_t size , const NetState& ok );

private:

    // For OpenSSL, every single IO status is represented by previous IO
    // operation's return code and its current ssl error code 
    struct SSLStatus {
        int io_return_code;
        int ssl_error_code;
        SSLStatus() : 
            io_return_code(0),
            ssl_error_code(0)
        {}
        SSLStatus( int ic , int sc ):
            io_return_code(ic),
            ssl_error_code(sc)
        {}
    };

    // The following function will call SSL_read / SSL_write also based on
    // its return status, the caller will perform corresponding operation 
    // based on that .
    SSLStatus DoRead( NetState* state );
    SSLStatus DoWrite( NetState* state );
    bool PerformSSL( void (SSLSocket::*caller)() );
private:
    Buffer read_buffer_, write_buffer_;

    detail::ScopePtr<detail::ReadCallback> read_callback_;
    detail::ScopePtr<detail::WriteCallback> write_callback_;
    detail::ScopePtr<detail::CloseCallback> close_callback_;

    Socket* socket_;
    SSL* ssl_;
    BIO* ssl_bio_ , *out_bio_;

    bool eof_;
};


} // namespace ment
#endif // MNET_SSL_H_

