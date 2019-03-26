// Headers from ping example:
// http://www.boost.org/doc/libs/1_51_0/doc/html/boost_asio/example/icmp/
#include "icmp_header.hpp"
#include "ipv4_header.hpp"

#include <sys/types.h>
#include <unistd.h>
#include <boost/asio.hpp>
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

static int gSequence;
static io_service gService;
static icmp::socket gSocket(gService, icmp::v4());
static char gReply[65536];
static icmp::endpoint gReceiver;

void StartReceive1() {
    gSocket.async_receive_from(boost::asio::buffer(gReply), gReceiver, [&](const error_code &error, size_t length) {

        ipv4_header ipv4Hdr;
        icmp_header icmpHdr;
        std::string body(BODY.size(), 0);

        std::istringstream is(std::string(gReply, length));
        is >> ipv4Hdr >> icmpHdr;
        is.read(&body[0], BODY.size());

        auto ip = ipv4Hdr.source_address().to_string();
        auto rc = gReceiver.address().to_string();
        auto id = icmpHdr.identifier();
        auto process = PROCESS;
        auto sn = icmpHdr.sequence_number();
        auto type = icmpHdr.type();
/*
        cout << " Length="              << length <<
             " Error="               << error <<
             " IP checksum="         << ipv4Hdr.header_checksum() <<
             " IP address="          << ip <<
             " Receiver address="    << rc <<
             " ICMP identification=" << id <<
             " ICMP type="           << (int)type <<
             " Process="             << process <<
             " Sequence="            << sn << "\n";
*/
        if (is && icmpHdr.type() == icmp_header::echo_reply && icmpHdr.identifier() == PROCESS &&
            icmpHdr.sequence_number() == gSequence && body == BODY) {
            cout << "    > " << ip << endl;
        }

        cout << endl;

        StartReceive1();
    });
}

int main() {
    icmp::resolver resolver(gService);

    icmp_header echoRequest;
    echoRequest.type(icmp_header::echo_request);
    echoRequest.identifier(PROCESS);

    std::vector<std::string> pool;
    for (auto it = 88; it != 89; ++it) {
        for (auto j = 0; j != 255; ++j) {
            pool.push_back("192.168." + std::to_string(it) + "." + std::to_string(j));
        }
    }

    for (gSequence = 0; gSequence < 1; ++gSequence) {
        cout << "----------------------------------------------------------" << endl;
        cout << "Iteration=" << gSequence << endl;
        cout << "----------------------------------------------------------" << endl;

        echoRequest.sequence_number(gSequence);
        compute_checksum(echoRequest, BODY.begin(), BODY.end());

        streambuf request;
        std::ostream os(&request);
        os << echoRequest << BODY;

        gService.reset();

        StartReceive1();

        for (std::string ip : pool) {
            icmp::resolver::query query(icmp::v4(), ip, "");
            auto dest = *resolver.resolve(query);

            gSocket.send_to(request.data(), dest);
            std::cout << "Sent to " << dest.endpoint() << "\n";
        }

        deadline_timer gTimer(gService);
        gTimer.expires_from_now(posix_time::millisec(500));
        gTimer.async_wait([&](error_code) {
            gService.stop();
        });

        gService.run();
    }
}