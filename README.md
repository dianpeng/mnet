An Ultimate Small Proactor Network Library in C++03
==================================================

# Introduction
MNet is a small proactor library that works only on Linux. It uses epoll edge trigger to achieve performance while reserving easy to use by implementing a proactor based library. 

The MNet library is extreamly small , however enough for most of the intranet or IPV4 TCP tasks. It only supports TCP protocol with IPV4. It is a C++ 03 compatible library , however user doesn't need to use inheritance to implement callback function. Actually MNet has a builtin callback library to enable user uses signature based way to implement callback function. 

MNet is also designed to achieve high performance. It utilize epoll function with edge trigger, also it uses scatter read to minimize system call at most. Lastly, since edge trigger has special property, which allows MNet to call epoll_ctl for each file descriptor at most twice . Unlike boost::asio, each time a event happen , 2 system call will have to be called. In MNet, it achieves nearly the same semantic with boost::asio which is regarded to be a easy to use library, however user will not need to pay so much on system call.

Although it has so many features, it is extreamly easy to be used. Since MNet doesn't use inheritance, user will only need to know several objects' function and some function signature, then user are good to go. You can checkout example directory for more examples.



