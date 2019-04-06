#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#include "icmp_header.hpp"
#include "ipv4_header.hpp"

#include <boost/asio.hpp>
#include <boost/container/vector.hpp>
#include <boost/log/common.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/thread.hpp>
#include <definitions.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

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
static const int NETWORK = 1;

/*
 * a list of variables to query for
 */
struct oid_struct {
  const char *Name;
  oid Oid[MAX_OID_LEN];
  int OidLen;
  std::string Description;
} oids[] = {
    {.Name = ".1.3.6.1.2.1.43.10.2.1.4.1.1", .Description = {"Pages"}},
    {.Name = ".1.3.6.1.2.1.1.6.0", .Description = {"Location"}},
    {.Name = ".1.3.6.1.2.1.25.3.2.1.3.1", .Description = {"Model"}},
    {.Name = ".1.3.6.1.2.1.1.5.0", .Description = {"Name"}},
    {.Name = ".1.3.6.1.2.1.43.5.1.1.17.1", .Description = {"SerialNumber"}},
    {.Name = ".1.3.6.1.2.1.43.11.1.1.9.1.1", .Description = {"TonerLevel"}},
    {NULL}};

void startPing();
void initOIDs(void) {
  struct oid_struct *op = oids;

  init_snmp("asynchapp");

  /* parse the oids */
  while (op->Name) {
    op->OidLen = sizeof(op->Oid) / sizeof(op->Oid[0]);
    if (!read_objid(op->Name, op->Oid,
                    reinterpret_cast<size_t *>(&op->OidLen))) {
      snmp_perror("read_objid");
      exit(1);
    }
    op++;
  }
}

int print_result(int status, struct snmp_session *sp, struct snmp_pdu *pdu,
                 std::string Name) {
  char buf[1024];
  struct variable_list *vp;
  int ix;
  struct timeval now;
  struct timezone tz;
  struct tm *tm;

  gettimeofday(&now, &tz);
  tm = localtime(&now.tv_sec);
  fprintf(stdout, "%.2d:%.2d:%.2d.%.6ld ", tm->tm_hour, tm->tm_min, tm->tm_sec,
          now.tv_usec);
  switch (status) {
  case STAT_SUCCESS:
    vp = pdu->variables;
    if (pdu->errstat == SNMP_ERR_NOERROR) {
      while (vp) {
        snprint_variable(buf, sizeof(buf), vp->name, vp->name_length, vp);
        fprintf(stdout, "%s - %s: %s\n", Name.c_str(), sp->peername, buf);
        vp = vp->next_variable;
      }
    } else {
      for (ix = 1; vp && ix != pdu->errindex; vp = vp->next_variable, ix++)
        ;
      if (vp)
        snprint_objid(buf, sizeof(buf), vp->name, vp->name_length);
      else
        strcpy(buf, "(none)");
      fprintf(stdout, "%s: %s: %s\n", sp->peername, buf,
              snmp_errstring(pdu->errstat));
    }
    return 1;
  case STAT_TIMEOUT:
    fprintf(stdout, "%s: Timeout\n", sp->peername);
    return 0;
  case STAT_ERROR:
    snmp_perror(sp->peername);
    return 0;
  }
  return 0;
}

void startSNMP(std::string ip) {
  struct snmp_session ss, *sp;
  struct oid_struct *op;
  /*

    // std::string to char * with boost::scoped_array
    boost::scoped_array<char> writeable(new char[ip.size() + 1]);
    std::copy(ip.begin(), ip.end(), writeable.get());
    writeable[ip.size()] = '\0';

    // std::string to char * with std::vector
    std::vector<char> writable1(ip.begin(), ip.end());
    writable1.push_back('\0');
  */

  snmp_sess_init(&ss);
  ss.version = SNMP_VERSION_2c;
  ss.peername = strdup(ip.c_str());
  ss.community = (u_char *)"public";
  ss.community_len = strlen("public");
  if (!(sp = snmp_open(&ss))) {
    snmp_perror("snmp_open");
    // continue;
  }
  for (op = oids; op->Name; op++) {
    struct snmp_pdu *req, *resp;
    int status;
    req = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(req, op->Oid, op->OidLen);
    status = snmp_synch_response(sp, req, &resp);
    if (!print_result(status, sp, resp, op->Description))
      break;
    snmp_free_pdu(resp);
  }
  snmp_close(sp);
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
          startSNMP(ip);
        }

        cout << endl;

        StartReceive();
      });
}

int main() {
  /* initOIDs();
  initIPsList();
  //  printIPList();
  startPing();
*/

//  boost::thread my_thread(&hello);
//  my_thread.join();
  BOOST_LOG_TRIVIAL(trace) << "A trace severity message";
  BOOST_LOG_TRIVIAL(debug) << "A debug severity message";
  BOOST_LOG_TRIVIAL(info) << "An informational severity message";
  BOOST_LOG_TRIVIAL(warning) << "A warning severity message";
  BOOST_LOG_TRIVIAL(error) << "An error severity message";
  BOOST_LOG_TRIVIAL(fatal) << "A fatal severity message";

  return 0;
}
void startPing() { // Ping
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
}
