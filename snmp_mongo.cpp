#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <definitions.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

#include <boost/container/vector.hpp>
#include <boost/format.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/thread.hpp>

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>

using boost::system::error_code;
using namespace boost::container;

using std::cout;
using std::endl;
namespace posix_time = boost::posix_time;
namespace logging = boost::log;
namespace src = boost::log::sources;
namespace expr = boost::log::expressions;
namespace keywords = boost::log::keywords;
static const std::string BODY = "ping";
static const auto PROCESS = getpid();

boost::container::vector<std::string> ipList;

static const int NETWORK = 1;
//[ example_expressions_channel_severity_filter
// We define our own severity levels
enum severity_level { normal, notification, warning, error, critical };

// Define the attribute keywords
BOOST_LOG_ATTRIBUTE_KEYWORD(line_id, "LineID", unsigned int)
BOOST_LOG_ATTRIBUTE_KEYWORD(severity, "Severity", severity_level)
BOOST_LOG_ATTRIBUTE_KEYWORD(channel, "Channel", std::string)

//<-
std::ostream &operator<<(std::ostream &strm, severity_level level) {
  static const char *strings[] = {"normal", "notification", "warning", "error",
                                  "critical"};

  if (static_cast<std::size_t>(level) < sizeof(strings) / sizeof(*strings))
    strm << strings[level];
  else
    strm << static_cast<int>(level);

  return strm;
}
//->

// Define our logger type
typedef src::severity_channel_logger<severity_level, std::string> logger_type;

void test_logging(logger_type &lg, std::string const &channel_name) {
  BOOST_LOG_CHANNEL_SEV(lg, channel_name, normal)
      << "A normal severity level message";
  BOOST_LOG_CHANNEL_SEV(lg, channel_name, notification)
      << "A notification severity level message";
  BOOST_LOG_CHANNEL_SEV(lg, channel_name, warning)
      << "A warning severity level message";
  BOOST_LOG_CHANNEL_SEV(lg, channel_name, error)
      << "An error severity level message";
  BOOST_LOG_CHANNEL_SEV(lg, channel_name, critical)
      << "A critical severity level message";
}
//]

/*
 * a list of variables to query for
 */
struct oid_struct {
  const char *Name;
  oid Oid[MAX_OID_LEN];
  int OidLen;
  std::string Description;
} oids[] = {
    {.Name = ".1.3.6.1.2.1.25.3.2.1.3.1", .Description = {"Model"}},
    {.Name = ".1.3.6.1.2.1.43.10.2.1.4.1.1", .Description = {"Pages"}},
    {.Name = ".1.3.6.1.2.1.1.6.0", .Description = {"Location"}},
    {.Name = ".1.3.6.1.2.1.1.5.0", .Description = {"Name"}},
    {.Name = ".1.3.6.1.2.1.43.5.1.1.17.1", .Description = {"SerialNumber"}},
    {.Name = ".1.3.6.1.2.1.43.11.1.1.9.1.1", .Description = {"TonerLevel"}},
    {NULL}};

void initIP(bool devMode) {
  if (devMode) {
    ipList.push_back("192.168.88.1");
    ipList.push_back("192.168.88.251");
  } else {
    for (int i = 88; i < 89; ++i) {
      for (int j = 0; j < 255; ++j) {
        ipList.push_back("192.168." + std::to_string(i) + "." +
                         std::to_string(j));
      }
    }
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
      int count = 1;
      while (vp) {
        snprint_variable(buf, sizeof(buf), vp->name, vp->name_length, vp);
        fprintf(stdout, "%s - %s: %s\n", Name.c_str(), sp->peername, buf);
        //***********************************************************************************
        if (vp->type == ASN_OCTET_STR) {
          char *stp = static_cast<char *>(malloc(1 + vp->val_len));
          memcpy(stp, vp->val.string, vp->val_len);
          stp[vp->val_len] = '\0';
          printf("value #%d is a string: %s\n", count++, stp);
          free(stp);
        } else {
          printf("value #%d is NOT a string! Ack!\n", count++);
        }
        //***********************************************************************************
        vp = vp->next_variable;
        std::string str;
        str = strdup(buf);
        std::size_t found = str.find("No Such Object");
        if (found != std::string::npos) {
          return 3;
        }
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
int print_result_new(int status, struct snmp_session *sp, struct snmp_pdu *pdu,
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
      int count = 1;
      while (vp) {
        snprint_variable(buf, sizeof(buf), vp->name, vp->name_length, vp);
        fprintf(stdout, "%s - %s: %s\n", Name.c_str(), sp->peername, buf);
        //***********************************************************************************
        if (vp->type == ASN_OCTET_STR) {
          char *stp = static_cast<char *>(malloc(1 + vp->val_len));
          memcpy(stp, vp->val.string, vp->val_len);
          stp[vp->val_len] = '\0';

          BOOST_LOG_TRIVIAL(debug)
              << boost::format("value #%d is a string: %s") % count++ % stp;
          free(stp);
        } else {
          printf("value #%d is NOT a string! Ack!", count++);
          return -1;
        }
        //***********************************************************************************
        vp = vp->next_variable;
        std::string str;
        str = strdup(buf);
        std::size_t found = str.find("No Such Object");
        if (found != std::string::npos) {
          return 3;
        }
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
  ss.timeout = 100000;
  if (!(sp = snmp_open(&ss))) {
    snmp_perror("snmp_open");
    BOOST_LOG_TRIVIAL(debug) << boost::format("Device %s offline") % ip;
    // continue;
  } else {
    BOOST_LOG_TRIVIAL(debug) << boost::format("Device %s online") % ip;

    for (op = oids; op->Name; op++) {
      struct snmp_pdu *req, *resp;
      int status;
      int print_result_status = -1;
      req = snmp_pdu_create(SNMP_MSG_GET);
      snmp_add_null_var(req, op->Oid, op->OidLen);
      status = snmp_synch_response(sp, req, &resp);

      switch (status) {
      case 2:
        cout << "Timeout"
             << "\n";
        break;
      case 1:
        print_result_status =
            print_result_new(status, sp, resp, op->Description);
        break;
      case 0:
        print_result_status =
            print_result_new(status, sp, resp, op->Description);
        break;
      default:
        break;
        // After first model response check for continue other oids
        if (print_result_status == -1) {
          BOOST_LOG_TRIVIAL(debug)
              << boost::format("Device %s is not a printer") % ip;
          break;
        }
      }

      snmp_free_pdu(resp);
      if (status == 2 || print_result_status == 3 || print_result_status == -1)
        break;
    }
  }
  snmp_close(sp);
}

void parseOid(void) {
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

/*****************************************************************************/
void initMongo() {
  mongocxx::instance inst{};
  mongocxx::client conn{mongocxx::uri{}};

  bsoncxx::builder::stream::document document{};

  auto collection = conn["testdb"]["testcollection"];
  document << "hello"
           << "world";

  collection.insert_one(document.view());
  auto cursor = collection.find({});

  for (auto &&doc : cursor) {
    std::cout << bsoncxx::to_json(doc) << std::endl;
  }
}

void scanSNMP() {
  for (const std::string ip : ipList) {
    startSNMP(ip);
  }
}
void initLog() {
  // Create a minimal severity table filter
  typedef expr::channel_severity_filter_actor<std::string, severity_level>
      min_severity_filter;
  min_severity_filter min_severity =
      expr::channel_severity_filter(channel, severity);

  // Set up the minimum severity levels for different channels
  min_severity["general"] = notification;
  min_severity["network"] = warning;
  min_severity["gui"] = error;

  logging::add_console_log(
      std::clog, keywords::filter = min_severity || severity >= critical,
      keywords::format = (expr::stream << line_id << ": <" << severity << "> ["
                                       << channel << "] " << expr::smessage));
}
int main(int argc, char **argv) {
  initLog();
  logging::add_common_attributes();

  logger_type lg;
  test_logging(lg, "general");
  test_logging(lg, "network");
  test_logging(lg, "gui");
  test_logging(lg, "filesystem");

  parseOid();
  initMongo();
  initIP(true);
  scanSNMP();
  return 0;
}
