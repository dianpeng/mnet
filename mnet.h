#ifndef MNET_H_
#define MNET_H_

#include <iostream>
#include <sstream>
#include <cstddef>
#include <cassert>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <cstdio>

#include <inttypes.h>

#include <string>
#include <vector>
#include <list>
#include <map>
#include <algorithm>

// System related header
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>

// Macros
#define DISALLOW_COPY_AND_ASSIGN(x) \
    void operator=( const x& ); \
    x( const x& )

#define UNREACHABLE(x) \
    do { \
        assert(0&&"Unreachable!"); \
        x; \
    } while(0)


#define LIKELY(x)       __builtin_expect((x),1)
#define UNLIKELY(x)     __builtin_expect((x),0)

// This directory is used to make gcc options -Weffc++ and -Wnon-virtual-destructor 
// happy. Since those option will force every class that has a virtual function needs
// a non virtual destructor which is not very helpful in our cases. Anyway bearing 
// those rules here. You could define this directory to make our code pass these warnings.
// #define FORCE_VIRTUAL_DESTRUCTOR

// MNet is a small library that is designed to solve massive concurrent
// tcp connection to server. It is a extreamly small C++ library that is
// strictly compatible with C++03 standard. It has only 4 class needs to
// know in order to work with it. It runs sololy on Linux and it is highly
// optimized in the following rules :
// 1. Minimize System Call
// 2. Minimize Buffer Copy
// 3. Minimize OOP overhead

namespace mnet {
class Buffer;
class Endpoint;
class NetState;

class Socket;
class ClientSocket;
class Listener;
class IOManager;

namespace detail {
class Pollable;

class ReadCallback {
public:
    virtual void Invoke( Socket* socket , std::size_t size, const NetState& ok ) = 0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~ReadCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

class WriteCallback {
public:
    virtual void Invoke( Socket* socket , std::size_t size, const NetState& ok ) = 0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~WriteCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR
};

class ConnectCallback {
public:
    virtual void Invoke( ClientSocket* socket , const NetState& ok ) =0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~ConnectCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

class AcceptCallback {
public:
    virtual void Invoke( Socket* socket , const NetState& ok ) =0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~AcceptCallback(){}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

class TimeoutCallback {
public:
    virtual void Invoke( int time ) =0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~TimeoutCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

class CloseCallback {
public:
    virtual void InvokeClose( const NetState& ok ) = 0;
    virtual void InvokeData( std::size_t sz ) = 0;

#ifdef FORCE_VIRTUAL_DESTRUCTOR
    virtual ~CloseCallback() {}
#endif // FORCE_VIRTUAL_DESTRUCTOR

};

namespace {

template< typename N > struct ReadNotifier : public ReadCallback {
    virtual void Invoke( Socket* socket , std::size_t size , const NetState& ok ) {
        notifier->OnRead( socket , size , ok );
    }
    N* notifier;
    ReadNotifier( N* n ) : notifier(n) {}
};

template< typename N > struct WriteNotifier : public WriteCallback {
    virtual void Invoke( Socket* socket , std::size_t size , const NetState& ok ) {
        notifier->OnWrite( socket , size , ok );
    }
    N* notifier;
    WriteNotifier( N* n ) : notifier(n) {}
};

template< typename N > struct AcceptNotifier : public AcceptCallback {
    virtual void Invoke( Socket* socket , const NetState& ok ) {
        notifier->OnAccept(socket,ok);
    }
    N* notifier;
    AcceptNotifier( N* n ) : notifier(n) {}
};

template< typename N > struct ConnectNotifier : public ConnectCallback {
    virtual void Invoke( ClientSocket* socket , const NetState& ok ) {
        notifier->OnConnect( socket , ok );
    }
    N* notifier;
    ConnectNotifier( N* n ) :notifier(n) {}
};

template< typename N > struct TimeoutNotifier : public TimeoutCallback {
    virtual void Invoke( int msec ) {
        notifier->OnTimeout(msec);
    }
    N* notifier;
    TimeoutNotifier( N* n ) :notifier(n) {}
};

template< typename N > struct CloseNotifier : public CloseCallback {
    virtual void InvokeClose( const NetState& ok ) {
        notifier->OnClose( ok );
    }
    virtual void InvokeData( std::size_t sz ) {
        notifier->OnData( sz );
    }
    N* notifier;
    CloseNotifier( N* n ) : notifier(n) {}
};
} // namespace

// Helper funtion to bind a any type T to a specific class and then we are able to
// call its internal callback function inside of the WriteCallback function.

template< typename T >
ReadCallback* MakeReadCallback( T* n ) {
    return new ReadNotifier<T>(n);
}

template< typename T >
WriteCallback* MakeWriteCallback( T* n ) {
    return new WriteNotifier<T>(n);
}

template< typename T >
AcceptCallback* MakeAcceptCallback( T* n ) {
    return new AcceptNotifier<T>(n);
}

template< typename T >
ConnectCallback* MakeConnectCallback( T* n ) {
    return new ConnectNotifier<T>(n);
}

template< typename T >
TimeoutCallback* MakeTimeoutCallback( T* n ) {
    return new TimeoutNotifier<T>(n);
}

template< typename T >
CloseCallback* MakeCloseCallback( T* n ) {
    return new CloseNotifier<T>(n);
}

// A very tiny and simple ScopePtr serves as the replacement of the std::unqiue_ptr
// C++ 03 only has a std::auto_ptr which I don't want to use since it is deperacted
template< typename T >
class ScopePtr {
public:
    ScopePtr() :
        ptr_(NULL)
        {}

    explicit ScopePtr( T* ptr ) :
        ptr_(ptr)
        {}

    ~ScopePtr() {
        delete ptr_;
    }

    // Reset the pointer by ptr typed with T. This function will clear the
    // ScopePtr when ptr == NULL
    void Reset( T* ptr ) {
        delete ptr_ ; // delete handle NULL properly
        ptr_ = ptr;
    }

    bool IsNull() const {
        return ptr_ == NULL;
    }

    bool operator == ( T* ptr ) const {
        return ptr_ == ptr;
    }

    bool operator != ( T* ptr ) const {
        return ptr_ != ptr;
    }

    void Swap( ScopePtr<T>* ptr ) {
        T* p = ptr->Release();
        ptr->ptr_ = ptr_;
        ptr_ = p;
    }

public:

    T* get() const {
        return ptr_;
    }

    T* Release() {
        T* ret = ptr_;
        ptr_ = NULL;
        return ret;
    }

    T* operator->() const {
        assert( ptr_ != NULL );
        return get();
    }

    const T& operator *() const {
        assert( ptr_ != NULL );
        return *get();
    }

    T& operator *() {
        assert( ptr_ != NULL );
        return *get();
    }

private:

    T* ptr_;

    DISALLOW_COPY_AND_ASSIGN(ScopePtr);
};

template< typename T >
bool operator == ( T* l , const ScopePtr<T>& r ) {
    return l == r.get();
}

template< typename T >
bool operator != ( T* l , const ScopePtr<T>& r ) {
    return l != r.get();
}

// Create a tcp file descriptor and set up all its related attributes
int CreateTcpFileDescriptor();

// Create a tcp server file descriptor. This creation will not set up communication
// attributes like NO_DELAY
int CreateTcpListenerFileDescriptor();



}// namespace detail

class Buffer {
private:

    // Rewind buffer if we need to do so. This includes 2 scenerios
    // 1) read_ptr_ hits the write_ptr_ , just rewind back and done
    // 2) write_ptr_ hits the capacity , we need to allocate more
    // spaces since we have no spaces to writing more data.

    void RewindBuffer() {
        if( UNLIKELY(read_ptr_ == write_ptr_) ) {
            read_ptr_ = write_ptr_ = 0;
        }
        // For write_ptr_ is same with capacity, we do nothing since
        // we can delay this operation until we really need more extra
        // spaces. Until then we do the reallocation operation
    }

public:
    // Accessor object. This object enables user to
    // access the internal raw buffer inside of this
    // object without cauzing pain in the copy. This
    // class can be used by user to achieve zero copy
    class Accessor {
    public:
        ~Accessor() {
            if( UNLIKELY(has_committed_) )
                return;
            *ptr_ref_ += committed_size_;
            owned_buffer_->RewindBuffer();
        }

        void* address() const {
            return address_;
        }
        std::size_t size() const {
            return size_;
        }
        std::size_t committed_size() const {
            return committed_size_;
        }

        void set_committed_size( std::size_t committed_size ) {
            assert( !has_committed_ );
            assert( committed_size <= size_ );
            committed_size_ = committed_size;
        }

        void Commit( ) {
            *ptr_ref_ += committed_size_;
            owned_buffer_->RewindBuffer();
            has_committed_ = true;
            committed_size_ = 0;
        }


    private:
        Accessor( std::size_t size ,
                  void* address ,
                  std::size_t* ptr_ref,
                  Buffer* owned_buffer):

            size_(size),
            address_(address),
            ptr_ref_(ptr_ref),
            committed_size_(0),
            owned_buffer_(owned_buffer),
            has_committed_(false)
            {}

    private:
        // Size of this slice inside of the whole buffer
        std::size_t size_;
        // Address for this slice
        void* address_;
        // Pointer ref for updating the size
        std::size_t* ptr_ref_;
        // Committed size
        std::size_t committed_size_;
        // Owned buffer
        Buffer* owned_buffer_;
        // Has committed
        bool has_committed_;
        // For accessing its private constructor
        friend class Buffer;
    };
public:

    explicit Buffer( std::size_t capacity = 0 , bool fixed = false ) :
        read_ptr_(0),
        write_ptr_(0),
        capacity_(capacity),
        is_fixed_( false ),
        mem_(NULL)
        { Grow(capacity); }

    ~Buffer() {
        free(mem_);
    }

    Accessor GetReadAccessor() {
        return Accessor( readable_size() ,
                         static_cast<char*>(mem_)+read_ptr_,
                         &read_ptr_,
                         this);
    }

    Accessor GetWriteAccessor() {
        return Accessor( writable_size() ,
                         static_cast<char*>(mem_)+write_ptr_,
                         &write_ptr_,
                         this);
    }

    void* Read( std::size_t* size ) ;
    bool Write( const void* mem , std::size_t size );
    std::size_t Fill( const void* mem , std::size_t size );

    // Inject will not cause overhead for memory, after injecting, if it
    // requires to malloc new memory, there will not be any extra space
    bool Inject( const void* mem , std::size_t size );

    std::size_t readable_size() const {
        return write_ptr_ - read_ptr_;
    }

    std::size_t writable_size() const {
        return capacity_ - write_ptr_;
    }

    std::size_t capacity() const {
        return capacity_;
    }

    void Clear() {
        write_ptr_ = read_ptr_ = 0;
    }

    bool Reserve( std::size_t capacity ) {
        if( is_fixed_ )
            return false;
        if( writable_size() < capacity ) {
            Grow( capacity - writable_size() );
        }
        return true;
    }

private:

    void Grow( std::size_t capacity );

private:
    // ReadPtr, this pointer points to the first available readable character
    // if ReadPtr == WritePtr , then nothing is avaiable for reading
    std::size_t read_ptr_;

    // WritePtr, this pointer points to the first avaiable space for writing
    // the data. if WritePtr == Capacity, then no extra spaces can be found
    // for writing.
    std::size_t write_ptr_;

    // Capacity
    // Capacity represents how many actual bytes (in total) has been allocated
    // for the buffer object.
    std::size_t capacity_;

    // Fixed buffer. If this buffer is fixed, then no internal memory grow 
    // operation will be used. Once the buffer runs out, it will just fail
    bool is_fixed_;

    // Pointer points to the memory buffer.
    void* mem_;

    friend class Accessor;

    DISALLOW_COPY_AND_ASSIGN(Buffer);
};

// Endpoint is a class that is used to represent a tuple (ipv4,port). It is a convinient
// class for user to 1) get endpoint from the string 2) convert this text representation
// to the real struct inetaddr structure.
class Endpoint {
public:

    Endpoint( const std::string& address , uint16_t port ) {
        ParseFrom(address,port);
    }

    explicit Endpoint( const std::string& endpoint ) {
        ParseFrom(endpoint);
    }

    Endpoint() :
        port_( kEndpointError )
        {}

    Endpoint( uint32_t ipv4 , uint16_t port ) :
        ipv4_(ipv4),
        port_(port)
        {}

    bool ParseFrom( const std::string& address , unsigned short port ) {
        if( StringToIpv4(address.c_str()) < 0 )
            return false;
        port_ = port;
        return true;
    }

    bool ParseFrom( const std::string& address ) {
        int off;
        if( (off = StringToIpv4(address.c_str())) > 0 ) {
            // Checking for that \":\" here
            if( UNLIKELY(off > static_cast<int>(address.size()) || address[off] != ':') ) {
                return false;
            } else {
                // Skip the Ip address part + ':'
                if( UNLIKELY((off = StringToPort(address.c_str()+off+1)) < 0) ) {
                    return false;
                } else {
                    return true;
                }
            }
        }
        return false;
    }

    bool HasError() const {
        return port_ == kEndpointError;
    }

    std::string IpV4ToString() const {
        char buf[1024];
        Ipv4ToString(buf);
        return std::string(buf);
    }

    std::string PortToString() const {
        char buf[32];
        PortToString(buf);
        return std::string(buf);
    }

    uint16_t port() const {
        assert( port_ != kEndpointError );
        return static_cast<uint16_t>(port_);
    }

    void set_port( uint16_t p ) {
        port_ = p;
    }

    uint32_t ipv4() const {
        return ipv4_;
    }

    void set_ipv4( uint32_t ipv4 ) {
        ipv4_ = ipv4;
    }

    std::string ToString() const {
        char addr[1024];
        int length;
        length = Ipv4ToString(addr);
        addr[length]=':';
        PortToString(addr+length+1);
        return std::string(addr);
    }

private:
    // The input user should make sure that buffer has enough size
    int Ipv4ToString( char* buf ) const ;
    int PortToString( char* buf ) const ;

    int StringToIpv4( const char* buf ) ;
    int StringToPort( const char* buf ) ;

    // IPV4 compact representation. For future IPV6 supports,
    // just wrape this representation with a union. Problem is this
    // breaks users binary compatible.
    uint32_t ipv4_;

    // Port, in Linux endian( Big endian )
    uint32_t port_;

    // This value cannot be a valid port , so just use it as a indicator
    // for parsing error.
    static const int kEndpointError = 1 << 24;
};

// NetState
// =====================================================================
// This class represents the error status for the related file descriptors.
// User could use this fd to retrieve information about whether the fd has
// error or not. It also provides function to get a readable text based
// error description.
// =====================================================================

namespace state_category {
static const int kDefault = 0;
static const int kSystem = 1;
}// namespace state_category

class NetState {
public:
    NetState( int cate, int err ) {
        CheckPoint(cate,err);
    }

    NetState() :
        category_(state_category::kDefault),
        error_code_(0) {
    }

    bool CheckPoint( int cate , int err ) {
        category_ = cate;
        error_code_ = err;
        return err != 0;
    }

    int error_code() const {
        return error_code_;
    }

    int category() const {
        return category_;
    }

    bool HasError() const {
        return error_code_ != 0 ;
    }

    operator bool () const {
        return !HasError();
    }

    void Clear() {
        error_code_ = 0;
    }

private:
    // Error category for this one
    int category_;
    // Error code for the NetState class
    int error_code_;
};

namespace detail {

// A pollable is ensentially an entity. The solo goal for this class is
// to represent the states of a pollable device(file descriptor).
class Pollable {
public:
    Pollable() :
        fd_(-1),
        is_epoll_read_( false ),
        is_epoll_write_( false ),
        can_read_( false ),
        can_write_( false )
        {}

    virtual ~Pollable() {
        // When this pollable gets destructed, its internal
        // fd MUST be recalimed. It means the fd_ must be
        // already set to invalid socket handler value
        assert( fd_ < 0 );
    }

    // Accessor(readonly) for internal states of Socket
    bool is_epoll_read() const {
        return is_epoll_read_;
    }

    bool is_epoll_write()const {
        return is_epoll_write_;
    }

    int fd() const {
        return fd_;
    }

    bool Valid() const {
        return fd_ > 0 ;
    }

    operator bool() const {
        return Valid();
    }

public:
    // This function gets called when the IOManager find that a signal attach
    // to this pollable is issued for read. IOManager will do nothing but telling
    // you that you can read without blocking
    virtual void OnReadNotify( ) = 0;
    virtual void OnWriteNotify( ) = 0;
    virtual void OnException( const NetState& ) =0;

protected:

    void set_fd( int fd ) {
        fd_ = fd;
    }

    bool can_write() const {
        return can_write_;
    }

    void set_can_write( bool c ) {
        can_write_ = c;
    }

    bool can_read() const {
        return can_read_;
    }

    void set_can_read( bool c ) {
        can_read_ = c;
    }

private:
    // File descriptors
    int fd_;
    // If this fd has been added to epoll as epoll_read
    bool is_epoll_read_ ;

    // If this fd has been added to epoll as epoll_write
    bool is_epoll_write_;

    // Can read. This flag is used when there're data in
    // the kernel for edge trigger
    bool can_read_;

    // Can write. This flag is must since we will use edge trigger
    bool can_write_;

    friend class ::mnet::IOManager;
    friend class ::mnet::Listener;
};

}// namespace detail

// Socket represents a communication socket. It can be a socket that is accepted
// or a socket that initialized by connect. However, for listening, the user should
// use Listener. This socket will be added into the epoll fd using edge trigger.

class Socket : public detail::Pollable {
public:
    explicit Socket( IOManager* io_manager ) :
        io_manager_(io_manager),
        state_( NORMAL ) ,
        eof_(false) {}
    // This function serves for retrieving the Local address for the underlying
    // file descriptor.
    void GetLocalEndpoint( Endpoint* addr );
    // This function retrieve the peer side end point address for underlying file
    // descriptor
    void GetPeerEndpoint( Endpoint* addr );

    // Operation for user level read and write
    template< typename T >
    void AsyncRead( T* notifier );

    template< typename T >
    void AsyncWrite( T* notifier );

    template< typename T >
    void AsyncClose( T* notifier );

    // Closing this socket at once. This operation is entirely relied on the OS
    // no graceful shutdown is performed on each socket. This is OK in most cases,
    // however, AsyncClose can guarantee the socket been shutdown properly ( with
    // EOF received by local side).
    void Close() {
        assert( state_ == NORMAL );
        // Ignore the close return status
        ::close(fd());
        // Setting the fd to invalid value
        set_fd(-1);
    }

    const Buffer& read_buffer() const {
        return read_buffer_;
    }

    Buffer& read_buffer() {
        return read_buffer_;
    }

    const Buffer& write_buffer() const {
        return write_buffer_;
    }

    Buffer& write_buffer() {
        return write_buffer_;
    }

protected:
    // The following OnRead/OnWrite function is for IOManager private usage.
    // User should not call this function.

    virtual void OnReadNotify();
    virtual void OnWriteNotify();
    virtual void OnException( const NetState& state );

    IOManager* io_manager() const {
        return io_manager_;
    }

private:
    std::size_t DoRead( NetState* state );
    std::size_t DoWrite( NetState* state );

private:
    // Callback function
    detail::ScopePtr<detail::ReadCallback> user_read_callback_;
    detail::ScopePtr<detail::WriteCallback> user_write_callback_;
    detail::ScopePtr<detail::CloseCallback> user_close_callback_;

    std::size_t prev_write_size_;

    // User level buffer management , per socket per buffer.
    Buffer read_buffer_ ;
    Buffer write_buffer_;

    // IO Manager for this socket
    IOManager* io_manager_;

    enum {
        CLOSING,
        CLOSED,
        NORMAL // Initial state for the socket
    };

    int state_;

    // Flag to indicate that whether a EOF has been seen
    bool eof_;

    DISALLOW_COPY_AND_ASSIGN(Socket);
};

// ClientSocket, client socket represents a socket that could be initialize with
// async connection operation.
class ClientSocket : public Socket {
public:
    explicit ClientSocket( IOManager* io_manager ) :
        Socket( io_manager ) ,
        state_( DISCONNECTED )
        {}

    // This function is used to make this socket being connected to the peer.
    template< typename T>
    void AsyncConnect( const Endpoint& address , T* notifier );

private:

    virtual void OnReadNotify();
    virtual void OnWriteNotify();
    virtual void OnException( const NetState& state );
    void DoConnect( NetState* state );
private:
    // Callback function for async connection operations
    detail::ScopePtr<detail::ConnectCallback> user_conn_callback_;

    // States for the ClientSocket
    enum {
        CONNECTING ,
        DISCONNECTED,
        CONNECTED,
    };

    // This state field indicates the status of this ClientSocket. The ClientSocket
    // is initialized with DISCONNECTED, then if the user specify the connect operation
    // it turns into the CONNECTING states, finally either an error happened which
    // makes the state_ be DISCONNECTED again or successfully connected.
    int state_;

    DISALLOW_COPY_AND_ASSIGN(ClientSocket);
};

// Listener class represents the class that is sololy for listening. This one will
// be added into the epoll fd by level trigger. This is specifically needed if we
// want to loop through different epoll set and allow level trigger just make code
// simpler
class Listener : public detail::Pollable {
public:
    Listener();

    ~Listener();

    // Binding the Listener to a speicific end point and start
    // to listen. (This function is equavlent for bind + listen)
    bool Bind( const Endpoint& ep );

    // Accept operations. Indeed this operation will not be held
    // by IOManager since IOManager only notify read/write operations.
    // It is for specific socket that has different states to interpret
    // this event notification.
    template< typename T >
    void AsyncAccept( Socket* socket , T* notifier );

    IOManager* io_manager() const {
        return io_manager_;
    }

private:

    virtual void OnReadNotify( );
    virtual void OnWriteNotify( ) {
        // We will never register write notification for Listener
        UNREACHABLE(return);
    }
    virtual void OnException( const NetState& state );

    void set_io_manager( IOManager* io_manager ) {
        io_manager_ = io_manager;
    }

    int DoAccept( NetState* state );

    void HandleRunOutOfFD( int err );

private:
    // User callback function
    detail::ScopePtr<detail::AcceptCallback> user_accept_callback_;
    Socket* new_accept_socket_;

    // The following fd is used to gracefully shutdown the remote the
    // remote connection when we are run out the FD (EMFILE/ENFILE).
    int dummy_fd_;

    // This field represents the manager that this listener has been added
    // If it sets to zero, it means the listener has no attached IOManager
    IOManager* io_manager_;

    // This flag is used to tell the state of the current listener
    bool is_bind_;

    friend class IOManager;
    DISALLOW_COPY_AND_ASSIGN(Listener);
};

// IOManager class represents the reactor. It performs socket event notification
// and also timeout notification. This IOManager is a truely reactor, it spawn the
// notification when the IO event is ready ( performs the IO without blocking ).
// To achieve notification, the typical way is through callback function. In C++
// 11 we can use std::function or we can use boost::function. However, to make the
// library stay small and simple, we will not use these tools. Additionally, no
// drop in replacement for std::function will be created here. We use a trick to
// make user do not need to inherit any base class. This trick involes the overhead
// for new/delete call , however, we assume that OS take care of it . The overhead
// is as follow, for each event (read/write/accept/connect/timeout) a new/delete will
// be invoked once. Maybe a simple memory pool can solve these overhead

class IOManager {
public:
    IOManager();

    ~IOManager();

    // Schedule a notifier that is to be invoked after msec milliseconds passed
    template< typename T >
    void Schedule( int msec , T* notifier );

    // This one is specifically for listener stuff
    void SetListener( Listener* l ) {
        l->set_io_manager(this);
        WatchRead(l);
    }

    // Calling this function will BLOCK the IOManager into the main loop
    NetState RunMainLoop();

    // This function could be safely called from another thread. It will
    // wake up a blocked IOManager for that thread. Once calling from this
    // one, the RunMainLoop will return with an empty NetState .
    void Interrupt();

private:

    // The following interface is privately used by Socket/Listener/Connector class
    void WatchRead( detail::Pollable* pollable );
    void WatchWrite( detail::Pollable* pollable );

    // This function is used here to avoid potential stack overflow for accepting
    // function
    template< typename T >
    void SetPendingAccept( Socket* new_accept_socket, T* notifier , const NetState& state );

    // This function is used to watch the control fd, the reason why need another one
    // is that for control fd, we use level trigger
    void WatchControlFd();

private:

    void DispatchLoop( const struct epoll_event* evnt , std::size_t sz );
    uint64_t UpdateTimer( std::size_t event_sz , uint64_t prev_timer );

    // This function is actually a hack to avoid potential stack overflow. The situation is
    // as follow, if we invoke user's notifier just when we find that we can get a new fd 
    // from accept inside of function AsyncAccept, then user could call AsyncAccept( which is
    // always the case ). It means user's notifier function can goto AsyncAccept again , then
    // such loop can countinue if the accept can get more new fd. It can potentailly lead to
    // stack overflow if too much concurrent connection is established. Puting such function
    // invocation into the main event loop can break such call graph thus avoiding stack 
    // overflow potentially.
    
    void ExecutePendingAccept();

private:
    // The maximum buffer for epoll_events buffer for epoll_wait on the stack
    static const std::size_t kEpollEventLength = 1024;

    // control file descriptor
    class CtrlFd : public detail::Pollable {
    public:
        CtrlFd() :
            is_wake_up_(false)
            {}

        virtual void OnReadNotify();
        virtual void OnWriteNotify( ) {}
        virtual void OnException( const NetState& state ){
            is_wake_up_ = true;
        }

        // Send only 1 bytes data serve as an notification
        static const std::size_t kDataLen = 1;

        bool is_wake_up() const {
            return is_wake_up_;
        }

        void set_is_wake_up( bool b ) {
            is_wake_up_ = b;
        }

    private:
        bool is_wake_up_;
    };

    CtrlFd ctrl_fd_;

    // Epoll file descriptors.
    int epoll_fd_;

    // Safely transfer ownership of a pointer in STL is kind of like nightmare in C++03.
    // STL is designed for value semantic, for pointer semantic it is very hard to make
    // copy constructor and assignment operator happy without using smart pointer. For
    // simplicity, the TimerStruct will _not_ own the pointer. The deletion will happened
    // explicitly once it gets invoked.

    struct TimerStruct {
        int time;
        detail::TimeoutCallback* callback;
        bool operator < ( const TimerStruct& rhs ) const {
            return time > rhs.time;
        }

        TimerStruct( int tm , detail::TimeoutCallback* cb ) :
            time(tm),
            callback(cb)
        {}
    };

    // A timer heap , maintain the heap validation by using std::heap_pop
    std::vector<TimerStruct> timer_queue_;

    // The pending accept events are listed here. This allows us to avoid potential
    // stack overflow. This field is checked when we enter the loop every time, if
    // a pending accept/error is there, then we just invoke it; otherwise we head to
    // the epoll loop stuff there.

    Socket* new_accept_socket_;
    NetState pending_accept_state_;
    detail::ScopePtr<detail::AcceptCallback> pending_accept_callback_;

    // Friend class, those classes are classes that is inherited
    // from the detail::Pollable class. This class needs to access the private
    // API to watch the event notification.

    friend class Socket;
    friend class Listener;
    friend class ClientSocket;

    DISALLOW_COPY_AND_ASSIGN(IOManager);
};
} // namespace mnet

// ----------------------------------------------------
// Inline function or template function definition
// ----------------------------------------------------
namespace mnet{

template< typename T >
void Socket::AsyncRead( T* notifier ) {
    assert( state_ != CLOSED );
    assert( user_read_callback_.IsNull() );
    if( UNLIKELY(can_read()) ) {
        if( UNLIKELY(eof_) ) {
            // This socket has been shutdown before previous DoRead 
            // operation. We just call user notifier here
            notifier->OnRead( this, 0 , NetState(0) );
            return;
        } else {
            // We can directly read data from the kernel space
            NetState state;
            std::size_t sz = DoRead(&state);
            // Checking if the read process goes smoothly or not
            if( UNLIKELY(state) ) {
                if( sz > 0 ) {
                    // Notify user that we have something for you.
                    notifier->OnRead( this , sz , NetState(0) );
                    return;
                }
            } else {
                notifier->OnRead( this , sz , state );
                return;
            }
        }
    }
    // Setup the watch operation
    io_manager_->WatchRead(this);
    // Set up the read operations
    user_read_callback_.Reset( detail::MakeReadCallback(notifier) );
}

template< typename T >
void Socket::AsyncWrite( T* notifier ) {
    assert( state_ != CLOSED );
    assert( user_write_callback_.IsNull() );
    assert( write_buffer().readable_size() != 0 );
    prev_write_size_ = 0;

    if( UNLIKELY(can_write()) ) {
        NetState state;
        // It means we don't need to let the epoll to watch us
        // since we can do write without blocking here
        prev_write_size_ = DoWrite( &state );
        if( UNLIKELY(!state) ) {
            notifier->OnWrite( this, prev_write_size_ , state );
            return;
        }
        if( write_buffer().readable_size() == 0 ) {
            // We have already written all the data into the kernel
            // without blocking.
            notifier->OnWrite( this, prev_write_size_ , NetState() );
            return;
        }
    }
    // Watch the write operation in the reactor
    io_manager_->WatchWrite(this);
    // Set up the user callback function
    user_write_callback_.Reset( detail::MakeWriteCallback(notifier) );
}

template< typename T >
void Socket::AsyncClose( T* notifier ) {
    assert( state_ == NORMAL );
    // Issue the shutdown on the write pipe operations
    ::shutdown( fd() , SHUT_WR );
    // Set the state to closing here
    state_ = CLOSING;

    // Now we need to stuck on the read handler here
    if( can_read() ) {
        NetState state;
        // Try to read the data from current fd
        std::size_t sz =  DoRead( &state );
        if( LIKELY(sz == 0 || !state) ) {
            Close();
            notifier->OnClose();
            return;
        }
    }
    // After shuting down, we are expecting for read here
    io_manager_->WatchRead(this);
    // Seting up the user close callback function
    user_close_callback_.Reset(
            detail::MakeCloseCallback(notifier));
}

template< typename T >
void ClientSocket::AsyncConnect( const Endpoint& endpoint , T* notifier ) {
    assert( state_ == DISCONNECTED );
    int sock_fd = detail::CreateTcpFileDescriptor();
    if( UNLIKELY(sock_fd < 0) ) {
        notifier->OnConnect( this , NetState(state_category::kSystem,errno) );
        return;
    }

    set_fd( sock_fd );

    struct sockaddr_in ipv4addr;
    bzero(&ipv4addr,sizeof(ipv4addr));

    // Initialize the sockaddr_in structure
    ipv4addr.sin_family = AF_INET; // IpV4
    ipv4addr.sin_port = htons(endpoint.port());
    ipv4addr.sin_addr.s_addr = htonl(endpoint.ipv4());

    int ret = ::connect( fd() ,
            reinterpret_cast<struct sockaddr*>(&ipv4addr),sizeof(ipv4addr));

    if( UNLIKELY(ret == 0) ) {
        // Our connection is done here, this is possible when you
        // connect to a local host then kernel just succeeded at once
        // This typically happenes on FreeBSD.
        // Now just call user's callback function directly
        notifier->OnConnect( this , NetState(0) );
        state_ = CONNECTED;
    } else {
        if ( UNLIKELY(errno != EINPROGRESS) ) {
           // When the errno is not EINPROGRESS, this means that it is
           // not a recoverable error. Just return from where we are
           notifier->OnConnect( this , NetState(state_category::kSystem,errno) );
           return;
        }
    }

    // Now issue the connection on epoll. Epoll interpret this information
    // as could write ( there're potential problem on *NIX system for this).
    io_manager()->WatchWrite(this);

    // Setup the user callback function
    user_conn_callback_.Reset(
            detail::MakeConnectCallback(notifier));

    state_ = CONNECTING;
}

template< typename T >
void Listener::AsyncAccept( Socket* socket , T* notifier ) {
    assert( user_accept_callback_.IsNull() );
    assert( io_manager_ != NULL );

    if( can_read() ) {
        // Try to accept at first since for listen fd we use level trigger
        // This cost you a tiny system call but may help save a epoll_wait
        // wake up which will be much more costy than an accept
        NetState state;
        int nfd = DoAccept(&state);
        if( UNLIKELY(nfd < 0) ) {
            if( !state ) {
                // We meet an error, just notify user about this situation
                io_manager_->SetPendingAccept( socket, notifier,state );
                return;
            }
        } else {
            socket->set_fd( nfd );
            io_manager_->SetPendingAccept( socket,notifier,state );
            return;
        }
    }

    // When we reach here, it means that we have no pending accepted fd
    // in the kernel space. Now just issue the WatchRead on the listen
    // fd until we get hitted.
    io_manager_->WatchRead(this);
    user_accept_callback_.Reset(detail::MakeAcceptCallback(notifier));
    new_accept_socket_ = socket;

    return;
}

template< typename T >
void IOManager::Schedule( int msec , T* notifier ) {
    timer_queue_.push_back( TimerStruct(msec, detail::MakeTimeoutCallback(notifier)) );
    std::push_heap(timer_queue_.begin(),timer_queue_.end());
}

template< typename T >
void IOManager::SetPendingAccept( Socket* new_socket , T* notifier , const NetState& state ) {
    assert( pending_accept_callback_.IsNull() );
    new_accept_socket_ = new_socket;
    pending_accept_callback_.Reset( detail::MakeAcceptCallback(notifier) );
    pending_accept_state_ = state;
}

}// namespace mnet
#endif // MNET_H_

