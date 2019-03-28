#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "icmp_header.hpp"
#include "ipv4_header.hpp"

#include <boost/asio.hpp>
#include <boost/container/vector.hpp>
#include <boost/log/trivial.hpp>
#include <boost/thread.hpp>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
#include <definitions.h>

using boost::asio::deadline_timer;
using boost::asio::io_service;
using boost::asio::streambuf;
using boost::asio::ip::icmp;
using boost::system::error_code;
using namespace boost::container;
using std::cout;
using std::endl;
namespace posix_time = boost::posix_time;

static const std::string BODY = "ping";
static const auto PROCESS = getpid();

boost::container::vector<std::string> ipList;

static int gSequence;
static io_service gService;
static icmp::socket gSocket(gService, icmp::v4());
static char gReply[65536];
static icmp::endpoint gReceiver;

struct oidStruct {
    const char *Name;
    oid Oid[MAX_OID_LEN];
    int oidLen;
};

oidStruct oids[] = {{".1.3.6.1.2.1.1.1.0"},
                    {".1.3.6.1.2.1.1.6.0"},
                    {"1.3.6.1.2.1.43.10.2.1.4.1.1"},
                    {"1.3.6.1.2.1.43.11.1.1.9.1.1"},
                    {"1.3.6.1.2.1.25.3.2.1.3.1"},
                    {"1.3.6.1.2.1.43.5.1.1.17.1"},
                    {"1.3.6.1.2.1.1.5.0"},
                    {NULL}};

void initSNMP(void) {
    struct oidStruct *os = oids;

    init_snmp("monitor");

    //parse oids
    while (os->Name) {
        os->oidLen = sizeof(os->Oid) / sizeof(os->Oid[0]);
        if (!read_objid(os->Name, os->Oid,
                        reinterpret_cast<size_t *>(&os->oidLen))) {
            snmp_perror("read_objid");
            exit(1);
        }
        os++;
    }
}

void startSNMP();

void hello() { cout << "Hello" << endl; }

static const int NETWORK = 1;

void snmp_print(std::string result, int num) {
    cout << "result " << result << endl;
    cout << "num " << num << endl;
}

void initIPsList() {
    for (int i = 88; i < 89; ++i) {
        for (int j = 0; j < 255; ++j) {
            ipList.push_back("192.168." + std::to_string(i) + "." +
                             std::to_string(j));
        }
    }
}

void printIPList() {
    cout << ipList.size() << "\n";
    for (const std::string ip : ipList) {
        cout << ip << "\n";
    }
}

void StartReceive() {
    gSocket.async_receive_from(
            boost::asio::buffer(gReply), gReceiver,
            [&](const boost::system::error_code &error, size_t length) {
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
                if (is && icmpHdr.type() == icmp_header::echo_reply &&
                    icmpHdr.identifier() == PROCESS &&
                    icmpHdr.sequence_number() == gSequence && body == BODY) {
                    cout << "    > " << ip << endl;
                    startSNMP();
                }

                cout << endl;

                StartReceive();
            });
}

void startSNMP() {

}

int main() {
    initIPsList();
//    printIPList();

    // Ping
    icmp::resolver resolver(gService);

    icmp_header echoRequest;
    echoRequest.type(icmp_header::echo_request);
    echoRequest.identifier(PROCESS);
    echoRequest.sequence_number(0);
    compute_checksum(echoRequest, BODY.begin(), BODY.end());

    boost::asio::streambuf request;
    std::ostream os(&request);
    os << echoRequest << BODY;

    gService.reset();

    StartReceive();
    for (const std::string ip : ipList) {
        icmp::resolver::query query(icmp::v4(), ip, "");
        auto dest = *resolver.resolve(query);

        gSocket.send_to(request.data(), dest);
        std::cout << "Sent to " << dest.endpoint() << "\n";
    }

    deadline_timer gTimer(gService);
    gTimer.expires_from_now(posix_time::millisec(1000));
    gTimer.async_wait([&](boost::system::error_code) { gService.stop(); });

    gService.run();
    /*
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
     */
    return 0;
}