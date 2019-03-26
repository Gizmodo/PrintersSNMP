#include "icmp_header.hpp"
#include "ipv4_header.hpp"

#include <sys/types.h>
#include <unistd.h>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/log/trivial.hpp>
#include <boost/container/vector.hpp>
#include <iostream>
#include <sstream>


using boost::asio::ip::icmp;
using boost::asio::deadline_timer;
using boost::asio::io_service;
using boost::asio::streambuf;
using boost::system::error_code;
using std::cout;
using std::endl;
namespace posix_time = boost::posix_time;


static const std::string BODY = "ping";
static const auto PROCESS = getpid();

void hello() {
    cout << "Hello" << endl;
}

int main() {
    boost::thread my_thread(&hello);
    my_thread.join();
    BOOST_LOG_TRIVIAL(trace) << "A trace severity message";
    BOOST_LOG_TRIVIAL(debug) << "A debug severity message";
    BOOST_LOG_TRIVIAL(info) << "An informational severity message";
    BOOST_LOG_TRIVIAL(warning) << "A warning severity message";
    BOOST_LOG_TRIVIAL(error) << "An error severity message";
    BOOST_LOG_TRIVIAL(fatal) << "A fatal severity message";
    boost::container::vector<int> v;
    for (int i = 0; i < 20; ++i) {
        v.insert(v.begin(), i);
    }
    return 0;

}