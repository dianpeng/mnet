#ifndef MNET_SSs_H_
#define MNET_SSL_H_
#include "mnet.h"
#include <openssl/ssl.h>

// Why AsyncSSL is _very_ hard to implement ?
// SSL was designed as a state machine this should make working with SSL
// pretty straitforward and simple. However, the truth is it is extreamly
// hard to work with SSL , it is much more difficult to work out a reliable
// SSL async implementation. 
// 
// 1. SSL is a state machine ? Well, not really !
// A state machine is very good theoriatic model, and also it is very good
// for practical implementation. However, there shouold a way to look up the
// current state without modifying the state of the system. For SSL, it is 
// impossible. SSL is esentially an IO layer, therefore SSL's state is external
// dependency. If you cannot read something or write something, you cannot 
// probing the SSL state. But SSL IO is coupled with BIO, BIO is another 
// abstraction. Therefore, we should tell SSL status by combining BIO behaivor
// and SSL return status code. 
// Suppose you are using memory BIO, which is the common method to implement
// asyncl SSL layer. You should _never_ assume SSL IO operation is finished,
// when SSL returns you SSL_ERROR_DONE ! Because memory based BIO can make
// SSL's every internal write succeded without telling you exact SSL behavior.
// Therefore, you should check whether there're new data inside of the BIO
// and then decide what you gonna do. And if there're new data there, the
// SSL's status, although it says done, should be delayed to the underlying 
// IO finishes its operation. 
//
// 2. SSL's states is not decided by what SSL says, but underlying IO system.
// When to invoke user's callback function is yet another problem, SSL is a
// user space layer not inside of the kernel. We cannot say we are OK when
// SSL say it is done. Instead , we should delay all the invocation of callback
// function until the underlying kernel layer finished. Also, we need to 
// replay the underlying kernel IO as well. The order is important, you cannot
// break the read and write order since this may lead to potential block !
// The peer side is waiting for your packet and you are waiting for the peer's
// packet at the same time, because we assume the incorrect order. 
// SLL is essentially a state machine that is designed to have a blocked IO
// transimission layer. Altough we want to use it in non block version , it
// is not designed so. No protocol will be designed around blocking or non
// blocking issue because this is all stuff engineer cares not the protocol
// designer. Try to keep everything in the correct order makes our life easier.
//
// 3. SSL can , up to now, _not_ be full duplex. Don't waste your time to 
// implement a full duplex SSL layer. It just can't, even if you write it,
// it cannot work 100% ( A open ticket that hasn't been resolved ). Also,
// don't waste time on sharing SSL file descriptors among different threads.
// It just dosesn't help to scale and instead increase complexity.
//
//
// How we tackle all these stuff together ?
// 1. We only allow a half duplex pipe by setting up the context stats.
// 2. We will use memory based BIO plus a paired one. Just for save memory.
// 3. Each SSL IO operation will be decomposed into 3 phases : (1) Invoke
// SSL IO operation (2) Checking SSL status + BIO status (3) Replay the IO
// operation if we need to. 
//
// 4. For read, the correct order is as follow, once the user issue the call,
// we should at first check whether we have memory left inside of the buffer
// in case we are dead locked. If the underlying buffer can feed the SSL, we
// are done. If not, we go to the SSL IO flow described above. Note, for read
// it is definitly sure that we may end up with SSL_ERROR_WANT_READ, however
// we will _NEVER_ end up with SSL_ERROR_WANT_WRITE since our BIO is enough 
// for SSL to issue single atomic rehandshake packet (210 bytes). Therefore 
// we will end up with BIO has some data but SSL says it is done or reports
// it SSL_ERROR_WANT_READ ( normally ). At this point, we should replay the
// IO operation in correct order ,even we allow read/write outstanding at
// same time on TCP. Just issue the write at first and then read at second.
// Note, it is _impossible_ to have read at first and write at second in
// this case !
//
// 5. For write, in most cases, we are fine since we will enable partial
// write. In case user send extreamly large buffer, we should put this 
// SSL operation inside of the loop until we encoded all the data and transfer
// them into the underlying TCP IO or we failed with the transfer for underlying
// TCP IO. However, regarding the rehandshake, it means we may end up with
// SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE. Same as read , when you get the
// SSL_ERROR_WANT_READ don't forget to check the BIO buffer to see whether we
// have pending data to write at first.

namespace mnet {
// SSL error category
namespace state_category {
static const int kSSL = 3;
}

namespace ssl {

class SSLSocket;
class SSLClientSocket;
class SSLListener;

// The callback stuff. We need a different set of callback since our SSLSocket
// doesn't really inherit from Socket class. Therefore to make user use same
// way to do their job, we need a new set of callback trick here.
namespace detail {

// Callback code to make our framework compatible with other type of socket
class SSLReadCallback {
public:
    virtual Invoke( SSLSocket* , std::size_t , const NetState& ) = 0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~SSLReadCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

class SSLWriteCallback {
public:
    virtual Invoke( SSLSocket* , std::size_t , const NetState& ) = 0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~SSLWriteCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR
};

class SSLConnectCallback {
public:
    virtual void Invoke( SSLClientSocket* socket , const NetState& ok ) =0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~SSLConnectCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

class SSLAcceptCallback {
public:
    virtual void Invoke( SSLSocket* socket , const NetState& ok ) =0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~SSLAcceptCallback(){}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

class SSLCloseCallback {
public:
    virtual void Invoke( const NetState& ok ) = 0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~SSLCloseCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

namespace {

template< typename N > struct SSLReadNotifier : public SSLReadCallback {
    virtual void Invoke( SSLSocket* socket , std::size_t size , const NetState& ok ) {
        notifier->OnRead( socket , size , ok );
    }
    N* notifier;
    SSLReadNotifier( N* n ) : notifier(n) {}
};

template< typename N > struct SSLWriteNotifier : public SSLWriteCallback {
    virtual void Invoke( SSLSocket* socket , std::size_t size , const NetState& ok ) {
        notifier->OnWrite( socket , size , ok );
    }
    N* notifier;
    SSLWriteNotifier( N* n ) : notifier(n) {}
};

template< typename N > struct SSLAcceptNotifier : public SSLAcceptCallback {
    virtual void Invoke( SSLSocket* socket , const NetState& ok ) {
        notifier->OnAccept(socket,ok);
    }
    N* notifier;
    SSLAcceptNotifier( N* n ) : notifier(n) {}
};

template< typename N > struct SSLConnectNotifier : public SSLConnectCallback {
    virtual void Invoke( SSLClientSocket* socket , const NetState& ok ) {
        notifier->OnConnect( socket , ok );
    }
    N* notifier;
    SSLConnectNotifier( N* n ) :notifier(n) {}
};

template< typename N > struct SSLCloseNotifier : public SSLCloseCallback {
    virtual void Invoke( const NetState& ok ) {
        notifier->OnClose( ok );
    }
    N* notifier;
    SSLCloseNotifier( N* n ) : notifier(n) {}
};
} // namespace

// Helper funtion to bind a any type T to a specific class and then we are able to
// call its internal callback function inside of the WriteCallback function.

template< typename T >
SSLReadCallback* MakeSSLReadCallback( T* n ) {
    return new SSLReadNotifier<T>(n);
}

template< typename T >
SSLWriteCallback* MakeSSLWriteCallback( T* n ) {
    return new SSLWriteNotifier<T>(n);
}

template< typename T >
SSLAcceptCallback* MakeSSLAcceptCallback( T* n ) {
    return new SSLAcceptNotifier<T>(n);
}

template< typename T >
SSLConnectCallback* MakeSSLConnectCallback( T* n ) {
    return new SSLConnectNotifier<T>(n);
}

template< typename T >
SSLTimeoutCallback* MakeSSLTimeoutCallback( T* n ) {
    return new SSLTimeoutNotifier<T>(n);
}

template< typename T >
SSLCloseCallback* MakeSSLCloseCallback( T* n ) {
    return new CloseNotifier<T>(n);
}

// This queue will utilize the size hint on stack and once the
// member overflows the value on the stack it moves all the stuff
// into the heap allocation.

template< std::size_t S , typename T > 
class EmbeddedQueue {
public:
    EmbeddedQueue():
        queue_(stack_buffer_),
        cap_( S ),
        tail_(0),
        head_(0)
    {}

    ~EmbeddedQueue();
public:
    void Enqueue( const T& value );
    const T& Front() const;
    T& Front();
    void Dequeue();
    std::size_t size() const {
        return tail_-head_;
    }
    void Clear() {
        tail_ = head_ = 0;
    }
    bool empty() const {
        return tail_ == head_;
    }

private:
    void Grow();

private:
    uint8_t stack_buffer_[sizeof(T)*S];
    T* queue_;
    std::size_t cap_;
    std::size_t tail_;
    std::size_t head_;
};

}// namespace detail


bool InitializeSSLLibrary();

// 
// A possible SSL implementation on top of the async SSL layer.
//
class SSLSocket {
public:
    virtual ~SSLSocket();

    template< typename T >
    void AsyncRead( T* notifier );
    
    template< typename T >
    void AsyncWrite( T* notifier );

    template< typename T >
    void AsyncClose( T* notifier );

    template< typename T >
    void AsyncSSLShutdown( T* notifier );

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

    void OnRead( Socket* socket , std::size_t size , const NetState& ok );
    void OnWrite( Socket* socket, std::size_t size , const NetState& ok );

    // For Async Closing
    void OnData( std::size_t );
    void OnClose( const NetState& state );

protected:
    // Please make sure to pass a valid socket here. Either a TCP socket that
    // has already been connected _or_ a socket that has been accepted .
    SSLSocket( Socket* socket );

    enum {
        SOCKET_READING = 0,
        SOCKET_WRITING = 1,
        SOCKET_CLOSING = 2,
        SOCKET_SSL_SHUTDOWN = 3,
        SOCKET_NORMAL = 4,
        SOCKET_ERROR_OR_CLOSE= 5,
        MAXIMUM_SSLSOCKET_STATES 
    };

    enum {
        DONE = 0 , // This operation means invoke user's callback we are done here
        READ_PENDING , // This operation means the SSL wants to read from underlying layer
        WRITE_PENDING  // This operation means the SSL wants to write from underlying layer
    };

    // readonly attributes for inherited classes
    int ssl_io_state() const {
        return ssl_io_state_;
    }

    bool DoBufferSend( NetState* state );
    bool MapPendingIOStatus( NetState* state , int ssl_return , bool write , bool eof );
    bool MapSSLError( NetState* state , int ssl_return );
    void HandleUnderlyIONotify( const NetState& state , std::size_t size );

    virtual void CallCallback( const NetState& state );
    // This function will execute the pending io operation that is in the queue. Also
    virtual bool ContinueSSL( NetState* state );

    // For inheritanace usage here
    Socket* socket_;
    SSL* ssl_;
    BIO* out_bio_;
    int state_;

    // The general cases for each IO operation is invoke corresponding internal
    // buffer transmittion routine which will assign the pending io operation
    // in the pending io queue.
    static const int kLocalPendingIO = 4;

    detail::EmbeddedQueue<kLocalPendingIO,int> pending_io_queue_;

private:
    // These 2 functions will try their best to move the data from SSL to or from TCP layer.
    // If nothing needs to be pending, then it returns true , otherwise it returns false 
    // which means user needs to issue the PENDING IO operations on underlying transport layer.
    bool DoReadLoop( NetState* state );
    bool DoWriteLoop( NetState* state );
    bool DoCloseLoop( NetState* state );

    Buffer read_buffer_, write_buffer_;
    int ssl_read_size_;
    int ssl_write_size_;

    detail::ScopePtr<detail::SSLReadCallback> read_callback_;
    detail::ScopePtr<detail::SSLWriteCallback> write_callback_;
    detail::ScopePtr<detail::SSLCloseCallback> close_callback_;

    int ssl_io_state_; // Internal state for tracking SSL state
};

template< typename T >
void SSLSocket::AsyncRead<T>( T* notifier ) {
    assert( state_ == SOCKET_NORMAL );
    NetState state;

    if( DoReadLoop(&state) ) {
        std::size_t io_size = ssl_read_size_;
        ssl_read_size_ = 0;
        assert( pending_io_queue_.empty() );
        // Invoke the user's callback function here 
        notifier->OnRead( this , io_size , state );
        return;
    } else {
        if( !state ) {
            ssl_read_size_ = 0;
            notifier->OnRead( this , 0 , state );
        } else {
            // Need to register every callback function in the member and
            // wait for the IO operation finished asynchronously
            read_callback_.Reset( detail::MakeSSLReadCallback( notifier ) );
        }
    }
}

template< typename T >
void SSLSocket::AsyncWrite<T>( T* notifier ) {
    assert( state_ == SOCKET_NORMAL );
    NetState state;

    if( DoWriteLoop(&state) ) {
        std::size_t io_size = ssl_write_size_;
        ssl_write_size_ = 0;
        assert( pending_io_queue_.empty() );
        notifier->OnWrite( this, io_size , state );
        return;
    } else {
        if(!state) {
            ssl_read_size_ = 0;
            notifier->OnRead(this,0,state);
        } else {
            write_callback_.Reset( detail::MakeSSLWriteCallback( notifier ) );
        }
    }
}

template< typename T >
void SSLSocket::AsyncClose( T* notifier ) {
    assert( state_ == SOCKET_NORMAL );
    NetState state;

    if( DoCloseLoop(&state) ) {
        assert( pending_io_queue_.empty() );
        socket_->AsyncClose( this );
        return;
    } else {
        if(!state) {
            notifier->OnClose(this,0,state);
        } else {
            close_callback_.Reset( detail::MakeSSLCloseCallback( notifier ) );
        }
    }
}

template< typename T >
void SSLSocket::AsyncSSLShutdown( T* notifier ) {
    assert( state_ == SOCKET_NORMAL );
    NetState state;

    if( DoCloseLoop(&state) ) {
        assert( pending_io_queue_.empty() );
        // Call the user callback directly here
        state_ = SOCKET_ERROR_OR_CLOSE;
        notifier->OnClose(state);
        return;
    } else {
        if(!state) {
            state_ = SOCKET_ERROR_OR_CLOSE;
            notifier->OnClose(state);
        } else {
            close_callback_.Reset( detail::MakeSSLCloseCallback( notifier ) );
        }
    }
}

// SSLClientSocket just allow async connection operation here
class SSLClientSocket : public SSLSocket {
public:
    // Please make sure to give a socket that has already connected to the
    // server. Otherwise the behavior is undefined here.
    SSLClientSocket( ClientSocket* socket );
    virtual ~SSLClientSocket();

    template< typename T > 
    void AsyncConnect( T* notifier );
    

private:
    bool DoConnect( NetState* state );

    virtual void CallCallback( const NetState& state );
    virtual bool ContinueSSL(  NetState* state );

private:
    enum {
        SOCKET_DISCONNECTED = SSLSocket::MAXIMUM_SSLSOCKET_STATES + 1,
        SOCKET_CONNECTING = SSLSocket::MAXIMUM_SSLSOCKET_STATES + 2,
        MAXIMUM_SSLCLIENTSOCKET_STATES
    };

    detail::ScopePtr<detail::SSLConnectCallback> connect_callback_;
};

template< typename T >
void SSLClientSocket::AsyncConnect( T* notifier ) {
    NetState ok;

    if( DoConnect(&ok) ) {
        state_ = SOCKET_NORMAL;
        notifier->OnConnect( this , ok );
    } else {
        if(!ok) {
            state_ = SOCKET_ERROR_OR_CLOSE;
            notifier->OnConnect(this,ok);
        } else {
            state_ = SOCKET_CONNECTING;
        }
    }
}

class SSLAcceptedSocket : public SSLSocket {
public:
    SSLAcceptedSocket( Socket* new_accepted_socket );
    virtual ~SSLAcceptedSocket();

    template< typename T >
    void AsyncAccept( T* notifier );

private:

    virtual void CallCallback( const NetState& state );
    virtual bool ContinueSSL( NetState* state );
    bool DoAccept( NetState* state );

private:
    enum {
        SOCKET_DISCONNECTED = SSLSocket::MAXIMUM_SSLSOCKET_STATES + 1,
        SOCKET_DISCONNECTED = SSLSocket::MAXIMUM_SSLSOCKET_STATES + 2,
        MAXIMUM_SSLACCEPTEDSOCKET_STATES
    };

    detail::ScopePtr<detail::SSLAcceptCallback> accept_callback_;
};

template< typename T > 
void SSLAcceptedSocket::AsyncAccept( T* notifier ) {
    NetState state;
    if( DoAccept(&state) ) {
        state_ = SOCKET_NORMAL;
        notifier->OnAccept( this , state );
    } else {
        if(!state) {
            state_ = SOCKET_ERROR_OR_CLOSE;
            notifier->OnAccept( this, state );
        } 
    }
}

} // namespace ssl
} // namespace ment
#endif // MNET_SSL_H_

