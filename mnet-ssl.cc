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

#define UNUSED_ARG(X) (void)(X)

#define DO_INVOKE(X,T,...) \
    do { \
        assert(!(X).IsNull()); \
        T cb((X).Release()); \
        cb->Invoke(__VA_ARGS__); \
    } while(false)

namespace mnet {
namespace {
 
// Current version of SSL only supports a 64kb packet (originally designed for
// IPv4). Therefore using a temporary buffer that is large as this will help to
// reduce call into the SSL_read in order to drain the SSL internal buffer. 
// Since we have no way to get how much encoded pending + unencoded pending 
// buffer we can get from SSL, SSL doesn't know either without really parsing.
static const int kSSLPacketLength = 1<<16; // 64 KB
} // namespace 

bool SSLSocket::DoReadLoop( NetState* state ) {
    // Internally we may meet the situation that we need to write
    // data out, therefore we need this flag to fix our pending io
    // operation queue.

    std::size_t writted_size = 0;
    bool write = false;
    char buffer[ kSSLPacketLength ];
    Buffer::Accessor accessor = socket_->read_buffer().GetReadAccessor();

    do {
        if( UNLIKELY( accessor.size() > 0 ) ) {
            // We got some data inside of the user space buffer, just inject
            // these data into the SSL's underlying BIO layer
            int bio_buf_size = BIO_ctrl_get_write_guarantee( out_bio_ );
            int write_size = std::min( 
                    static_cast<int>( accessor.size() ),
                    bio_buf_size );
            int actual_write = BIO_write( out_bio_ , 
                    static_cast<char*>(accessor.address()) + writted_size ,
                    write_size );
            VERIFY( actual_write == write_size );
        }

        int ssl_return = SSL_read( ssl_ , buffer , kSSLPacketLength );
        if( ssl_return < 0 ) {
            int err = SSL_get_error(ssl_,ssl_return);
            if( err == SSL_ERROR_WANT_READ ) {
                // This problem we may be able to solve it by putting more
                // data into the BIO to satisfy the read operation. We just
                // check whether we really have some data that is pending in
                // the user TCP socket buffer or not.
                if( accessor.size() == writted_size ) {
                    return MapPendingIOStatus( state , err , write );
                }
            } else if( err == SSL_ERROR_WANT_WRITE ) {
                // This means the write attempts of SSL has been blocked by
                // not enough memory. Just move data inside of the BIO into
                // the underlying socket layer and try again here.
                write = true;
                if(!DoBufferSend(state)) 
                    return false;
                // Try SSL operation again 
            } else {
                return MapPendingIOStatus( state , err, write );
            }

        } else {
            if( ssl_return == 0 ) {
                // We have a pending EOF operation that is done here
                // No matter it is a unclean close or a clean close
                // we just tell user that we are done here .
                ssl_read_size_ += ssl_return;
                return MapPendingIOStatus( state, SSL_ERROR_ZERO_RETURN , write );
            } else {
                ssl_read_size_ += ssl_return;
                if( !read_buffer_.Inject( buffer , ssl_return ) ) {
                    *state = NetState( state_category::kSystem , ENOBUFS );
                    return false;
                }
                return MapPendingIOStatus( state, SSL_ERROR_NONE , write );
            }
        }
    } while(true); 
    UNREACHABLE( return false );
}

bool SSLSocket::DoWriteLoop( NetState* state ){
    UNUSED_ARG(state);
    Buffer::Accessor accessor = write_buffer_.GetReadAccessor();
    int writted_size = 0;
    bool write = false;

    do {
        // Try to _encode_ the data to the BIO layer and then try our best to
        // move all the BIO layered data outband to the underlying TCP socket.
        // We enable partial write so SSL will try to write as much as possible.
        int ssl_return = SSL_write( ssl_, 
                static_cast<char*>( accessor.address() ) + writted_size ,
                accessor.size() - writted_size );

        if( BIO_pending( out_bio_ ) != 0 ) {
            write = true;
            // Try to send the underlying BIO buffer to the TCP socket buffer
            if(!DoBufferSend(state))
                return false;
        }
        
        // Handle ssl return value here
        if( ssl_return < 0 ) {
            if( ssl_return != SSL_ERROR_WANT_WRITE ) {
                ssl_write_size_ += writted_size;
                return MapPendingIOStatus( state , ssl_return , write );
            }
            // For SSL_ERROR_WANT_WRITE we can try again since it is most
            // likely that the underlying BIO is fulled .

        } else {
            if( ssl_return == 0 ) {
                ssl_write_size_ += writted_size;
                // Meet EOF, again, we don't try to distinguish a clean close
                // or an unexpected close here.
                return MapPendingIOStatus( state , SSL_ERROR_ZERO_RETURN , write );
            } else {
                ssl_write_size_ += writted_size;
                accessor.set_committed_size( writted_size );
                // Check whether we have finished the entire buffer or not
                if( static_cast<std::size_t>(writted_size) == accessor.size() ) {
                    ssl_write_size_ += ssl_return;
                    return MapPendingIOStatus( state , SSL_ERROR_NONE  , write );
                }
            }
        }
    } while( true );
    UNREACHABLE( return false );
}

bool SSLSocket::DoBufferSend( NetState* state ) {
    int pending_size = BIO_pending( out_bio_ );
    if( !socket_->write_buffer().Reserve( 
                pending_size )) {
        *state = NetState( 
                state_category::kSystem,
                ENOBUFS);
        return false;
    } else {
        Buffer::Accessor accessor = socket_->write_buffer().GetWriteAccessor();
        int write_size = BIO_read( out_bio_ , 
                accessor.address(),
                accessor.size());
        VERIFY( write_size == pending_size );
        return true;
    }
}

bool SSLSocket::MapPendingIOStatus( NetState* state , int ssl_return , bool write ) {
    bool ret; 

    if( BIO_pending( out_bio_ ) != 0 ) {
        write = true;
        if(!DoBufferSend(state))
            return false;
    }

    if( ssl_return == SSL_ERROR_WANT_WRITE ) {
        write = true;
    }

    if( write ) {
        pending_io_queue_.Enqueue( WRITE_PENDING );
    }

    switch( ssl_return ) {
        case SSL_ERROR_NONE:
            if( write ) {
                ret = false;
            } else {
                return true;
            }
            break;
        case SSL_ERROR_WANT_READ:
            if( write ) {
                pending_io_queue_.Enqueue( WRITE_PENDING );
            }
            pending_io_queue_.Enqueue( READ_PENDING );
            ret = false;
            break;
        case SSL_ERROR_WANT_WRITE:
            ret = false;
            break;
        case SSL_ERROR_ZERO_RETURN:
            eof_ = true;
            ret = true;
            break;
        default:
            // Handle other error stuffs
            return MapSSLError( state , ssl_return );
    }

    // Setup the Socket watch flag here
    if( pending_io_queue_.Front() == READ_PENDING ) {
        socket_->AsyncRead(this);
        return ret;
    } else {
        VERIFY( pending_io_queue_.Front() == WRITE_PENDING );
        socket_->AsyncWrite(this);
        return ret;
    }
}

bool SSLSocket::MapSSLError( NetState* state , int ssl_return ) {
    switch( ssl_return ) {
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            *state = NetState( state_category::kSSL , ssl_return );
            return false;
        default:
            UNREACHABLE();
            return false;
    }
}

bool SSLSocket::ContinueSSL( NetState* state ) {
    assert( pending_io_queue_.Front() == READ_PENDING ||
            pending_io_queue_.Front() == WRITE_PENDING );
    if( pending_io_queue_.Front() == READ_PENDING ) {
        pending_io_queue_.Dequeue();
        switch( state_ ) {
            case SOCKET_READING:
                if(!DoReadLoop(state))
                    return false;
                break;
            case SOCKET_WRITING:
                if(!DoWriteLoop(state))
                    return false;
                break;
        }
    } else {
        pending_io_queue_.Dequeue();
    }

    if( pending_io_queue_.empty() ) {
        return true;
    }

    UNREACHABLE( return false );
}

void SSLSocket::HandleUnderlyIONotify( const NetState& state ) {
    if( UNLIKELY( state_ == SOCKET_ERROR || state_ == SOCKET_NORMAL ) )        
        return;

    if( UNLIKELY(!state) ) {
        // We have an underlying IO status. This may leads to confliction here,
        // suppose that there're some other pending io that is outstanding , however
        // our callback gets called and we are failed , which means this SSL layer
        // IO can never succeeded .Either we delay our callback function invoking until
        // last IO is not pending _or_ we tell user now . We choose invoke user's cb
        // function now and mark that this socket needs to be cancled for all the other
        // stuff.
        state_ = SOCKET_ERROR;
        pending_io_queue_.Clear();
        CallCallback(state);
    } else {
        // Try to feed SSL state machine again
        NetState ok;
        if( ContinueSSL( &ok ) ) {
            CallCallback( ok );
        } else {
            if( ok ) {
                CallCallback( ok );
            }
        }
    }
}

void SSLSocket::OnRead( Socket* socket , std::size_t size , const NetState& ok ) {
    UNUSED_ARG(socket);
    UNUSED_ARG(size);
    HandleUnderlyIONotify(ok);
}

void SSLSocket::OnWrite( Socket* socket , std::size_t size , const NetState& ok ) {
    UNUSED_ARG(socket);
    UNUSED_ARG(size);
    HandleUnderlyIONotify(ok);
}



}// namespace mnet






























