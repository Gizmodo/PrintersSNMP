#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/decimal128.hpp>
#include <bsoncxx/exception/exception.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/types.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/container/vector.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/format.hpp>
#include <boost/log/attributes/named_scope.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <definitions.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

using boost::system::error_code;
using std::cout;
using std::endl;

boost::container::vector<std::string> IPs;

struct oidStruct {
  const char *Name;
  oid Oid[MAX_OID_LEN];
  int OidLen;
  std::string Description;
} oids[] = {{.Name = ".1.3.6.1.2.1.25.3.2.1.3.1", .Description = {"Model"}},
            {.Name = ".1.3.6.1.2.1.43.5.1.1.17.1", .Description = {"SN"}},
            {.Name = ".1.3.6.1.2.1.43.10.2.1.4.1.1", .Description = {"Pages"}},
            {.Name = ".1.3.6.1.2.1.1.6.0", .Description = {"Location"}},
            {nullptr}};

struct data {
  const char *Model;
  const char *SerialNumber;
  long Pages;
  const char *Location;
  std::string IP;
  unsigned int IPUInt;
  bsoncxx::decimal128 IPDecimal128;
} dataArray[1];

mongocxx::instance instance{}; // This should be done only once.
mongocxx::client conn{mongocxx::uri{"mongodb://192.168.88.254/testdb"}};

void cleanDataArray(void) {
  for (size_t i = 0; i < 1; ++i) {
    dataArray[i].Model = 0;
    dataArray[i].SerialNumber = 0;
    dataArray[i].Pages = 0;
    dataArray[i].Location = 0;
    dataArray[i].IP = "";
    dataArray[i].IPUInt = 0;
    dataArray[i].IPDecimal128 = bsoncxx::decimal128();
  }
}
int ipStringToNumber(const char *pDottedQuad, unsigned int *pIpAddr) {
  unsigned int byte3;
  unsigned int byte2;
  unsigned int byte1;
  unsigned int byte0;
  char dummyString[2];

  /* The dummy string with specifier %1s searches for a non-whitespace char
   * after the last number. If it is found, the result of sscanf will be 5
   * instead of 4, indicating an erroneous format of the ip-address.
   */
  if (sscanf(pDottedQuad, "%u.%u.%u.%u%1s", &byte3, &byte2, &byte1, &byte0,
             dummyString) == 4) {
    if ((byte3 < 256) && (byte2 < 256) && (byte1 < 256) && (byte0 < 256)) {
      *pIpAddr = (byte3 << 24) + (byte2 << 16) + (byte1 << 8) + byte0;

      return 1;
    }
  }

  return 0;
}

void initIP(bool devMode) {
  if (devMode) {
    IPs.push_back("192.168.88.1");
    IPs.push_back("192.168.88.251");
    IPs.push_back("183.108.188.25");
    IPs.push_back("169.237.117.47");
    IPs.push_back("183.108.188.25");
    IPs.push_back("58.137.51.68");
    IPs.push_back("103.210.24.244");
    IPs.push_back("107.211.249.156");
    IPs.push_back("115.160.56.153");
    IPs.push_back("118.128.78.196");
    IPs.push_back("121.137.133.227");
    IPs.push_back("121.143.103.125");
    IPs.push_back("134.255.76.46");
    IPs.push_back("134.255.76.46");
    IPs.push_back("137.26.143.186");
    IPs.push_back("153.19.67.9");
    IPs.push_back("163.19.200.141");
    IPs.push_back("163.27.162.109");
    IPs.push_back("163.27.162.61");
    IPs.push_back("173.19.94.142");
    IPs.push_back("18.127.2.4");
    IPs.push_back("182.31.30.55");
    IPs.push_back("183.98.155.134");
    IPs.push_back("193.198.100.138");
    IPs.push_back("193.198.100.138");
    IPs.push_back("193.198.93.14");
    IPs.push_back("195.96.231.88");
    IPs.push_back("197.50.226.137");
    IPs.push_back("197.50.227.149");
    IPs.push_back("200.6.169.149");
    IPs.push_back("202.172.107.201");
    IPs.push_back("203.253.251.146");
    IPs.push_back("206.126.42.241");
    IPs.push_back("210.179.32.162");
    IPs.push_back("211.40.127.253");
    IPs.push_back("24.213.57.102");
    IPs.push_back("47.144.13.89");
    IPs.push_back("5.148.131.50");
    IPs.push_back("58.181.35.141");
    IPs.push_back("64.185.36.123");
    IPs.push_back("66.210.225.179");
    IPs.push_back("80.11.188.182");
    IPs.push_back("90.152.31.213");
    IPs.push_back("95.97.141.123");
    IPs.push_back("96.91.105.110");
    IPs.push_back("98.155.108.21");
  } else {
    for (int i = 88; i < 89; ++i) {
      for (int j = 0; j < 255; ++j) {
        IPs.push_back("192.168." + std::to_string(i) + "." + std::to_string(j));
      }
    }
  }
}

void strtrim(char *str) {
  int start = 0; // number of leading spaces
  char *buffer = str;
  while (*str && *str++ == ' ')
    ++start;
  while (*str++)
    ; // move to end of string
  int end = str - buffer - 1;
  while (end > 0 && buffer[end - 1] == ' ')
    --end;         // backup over trailing spaces
  buffer[end] = 0; // remove trailing spaces
  if (end <= start || start == 0)
    return; // exit if no leading spaces or string is now empty
  str = buffer + start;
  while ((*buffer++ = *str++))
    ; // remove leading spaces: K&R
}

int print_result_new(int status, struct snmp_session *sp, struct snmp_pdu *pdu,
                     std::string Name) {
  char buf[1024];
  struct variable_list *vp;

  switch (status) {
  case STAT_SUCCESS:
    vp = pdu->variables;
    if (pdu->errstat == SNMP_ERR_NOERROR) {
      snprint_variable(buf, sizeof(buf), vp->name, vp->name_length, vp);
      //   fprintf(stdout, "%s - %s: %s\n", Name.c_str(), sp->peername, buf);

      switch (vp->type) {
      case 129: {
        // No Such ...
        BOOST_LOG_TRIVIAL(warning)
            << boost::format(" No Such ... %s: %d") % Name % vp->type;
        break;
      }
      case ASN_OCTET_STR: {
        char *stp = static_cast<char *>(malloc(1 + vp->val_len));
        memcpy(stp, vp->val.string, vp->val_len);
        stp[vp->val_len] = '\0';

        // Check for null of No OID string
        std::string str =
            strdup(reinterpret_cast<const char *>(vp->val.string));
        boost::trim(str);
        //        boost::algorithm::is_lower(str);
        strtrim(stp);

        size_t found = str.find("No Such");

        if ((found != std::string::npos || vp->val_len == 0) &&
            Name == "Model") {
          BOOST_LOG_TRIVIAL(warning)
              << boost::format(" %s: not a printer") % Name;
          return -1;
        } else {
          BOOST_LOG_TRIVIAL(info) << boost::format(" %s: %s") % Name % stp;
          if (Name == "Model") {
            dataArray[0].Model = strdup(stp);
          }
          if (Name == "Location") {
            dataArray[0].Location = strdup(stp);
          }
          if (Name == "SN") {
            dataArray[0].SerialNumber = strdup(stp);
          }
        }
        free(stp);
        break;
      }
      case ASN_INTEGER:
      case ASN_COUNTER: {
        long intval;
        intval = *((long *)vp->val.integer);
        BOOST_LOG_TRIVIAL(info) << boost::format(" %s: %d") % Name % intval;
        if (Name == "Pages") {
          dataArray[0].Pages = intval;
        }
        break;
      }
      default:
        BOOST_LOG_TRIVIAL(warning)
            << boost::format(" default ... %s: %d") % Name % vp->type;
        break;
      }
    } else {
      BOOST_LOG_TRIVIAL(error) << boost::format("SNMP_ERR_NOERROR");
      int ix;
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
    BOOST_LOG_TRIVIAL(debug)
        << boost::format("STAT_TIMEOUT: %s") % sp->peername;
    return -1;
  case STAT_ERROR:
    BOOST_LOG_TRIVIAL(error) << boost::format("STAT_ERROR: %s") % sp->peername;
    snmp_perror(sp->peername);
    return -1;
  default:
    return -1;
  }
}

void getSNMPbyIP(std::string ip) {
  struct snmp_session ss, *sp;
  struct oidStruct *op;
  bool doSave = false;
  /*

    // std::string to char * with boost::scoped_array
    boost::scoped_array<char> writeable(new char[ip.size() + 1]);
    std::copy(ip.begin(), ip.end(), writeable.get());
    writeable[ip.size()] = '\0';

    // std::string to char * with std::vector
    std::vector<char> writable1(ip.begin(), ip.end());
    writable1.push_back('\0');
  */
  cleanDataArray();
  snmp_sess_init(&ss);
  ss.version = SNMP_VERSION_2c;
  ss.peername = strdup(ip.c_str());
  ss.community = (u_char *)"public";
  ss.community_len = strlen("public");
  ss.timeout = 100000;
  BOOST_LOG_TRIVIAL(warning)
      << boost::format("<---------------------------------->");
  if (!(sp = snmp_open(&ss))) {
    snmp_perror("snmp_open");
    BOOST_LOG_TRIVIAL(debug) << boost::format("%s offline") % ip;
  } else {
    BOOST_LOG_TRIVIAL(debug) << boost::format("%s online") % ip;

    for (op = oids; op->Name; op++) {
      struct snmp_pdu *req, *resp;
      int status;
      int print_result_status = -1;
      req = snmp_pdu_create(SNMP_MSG_GET);
      snmp_add_null_var(req, op->Oid, op->OidLen);
      status = snmp_synch_response(sp, req, &resp);

      switch (status) {
      case 2:
        BOOST_LOG_TRIVIAL(debug) << boost::format("%s timeout") % ip;
        print_result_status = -1;
        break;
      case 0:
      case 1:
        print_result_status =
            print_result_new(status, sp, resp, op->Description);
        break;
      default:
        print_result_status = -1;
        break;
      }

      snmp_free_pdu(resp);

      if (print_result_status == -1) {
        doSave = false;
        break;
      } else {
        doSave = true;
      }
    }
    if (doSave) {
      dataArray[0].IP = ip;

      unsigned int ipAddr;
      bsoncxx::decimal128 d128;

      if (ipStringToNumber(ip.c_str(), &ipAddr) == 1) {
        dataArray[0].IPUInt = ipAddr;
        try {
          d128 = bsoncxx::decimal128(std::to_string(ipAddr));
        } catch (const bsoncxx::exception &e) {
          BOOST_LOG_TRIVIAL(error)
              << boost::format(" Cast error to bsoncxx::decimal128 %s") % e.what();
        }

        dataArray[0].IPDecimal128 = d128;
      } else {
        dataArray[0].IPDecimal128 = bsoncxx::decimal128();
        dataArray[0].IPUInt = 0;
      }
      // todo ip to integer

      auto collection = conn["testdb"]["testcollection"];
      auto builder = bsoncxx::builder::stream::document{};
      bsoncxx::document::value doc_value =
          builder << "model" << dataArray[0].Model << "serial"
                  << dataArray[0].SerialNumber << "date"
                  << bsoncxx::types::b_date(std::chrono::system_clock::now())
                  << "pages" << dataArray[0].Pages << "location"
                  << dataArray[0].Location << "ip" << dataArray[0].IP
                  << "ip_int" << dataArray[0].IPDecimal128

                  << bsoncxx::builder::stream::finalize;

      collection.insert_one(doc_value.view());
    }
  }
  snmp_close(sp);
}

void parseOid(void) {
  struct oidStruct *op = oids;
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

void initMongo() {
  mongocxx::client conn{mongocxx::uri{"mongodb://192.168.88.254/testdb"}};

  bsoncxx::builder::stream::document document{};

  /*auto cursor = collection.find({});

  for (auto &&doc : cursor) {
    std::cout << bsoncxx::to_json(doc) << std::endl;
  }*/
}

void scanSNMP() {
  for (const std::string ip : IPs) {
    getSNMPbyIP(ip);
  }
}

static void initLog(void) {
  boost::log::add_common_attributes();
  boost::log::core::get()->add_global_attribute(
      "Scope", boost::log::attributes::named_scope());
  boost::log::core::get()->set_filter(boost::log::trivial::severity >=
                                      boost::log::trivial::trace);

  auto fmtTimeStamp =
      boost::log::expressions::format_date_time<boost::posix_time::ptime>(
          "TimeStamp", "%d.%m.%Y %H:%M:%S");
  auto fmtThreadId = boost::log::expressions::attr<
      boost::log::attributes::current_thread_id::value_type>("ThreadID");
  auto fmtSeverity =
      boost::log::expressions::attr<boost::log::trivial::severity_level>(
          "Severity");
  auto fmtScope = boost::log::expressions::format_named_scope(
      "Scope", boost::log::keywords::format = "%n(%f:%l)",
      boost::log::keywords::iteration = boost::log::expressions::reverse,
      boost::log::keywords::depth = 2);
  boost::log::formatter logFmt =
      boost::log::expressions::format("[%1%] [%2%] %3%") % fmtTimeStamp %
      fmtSeverity % boost::log::expressions::smessage;

  /* console sink */
  auto consoleSink = boost::log::add_console_log(std::clog);
  consoleSink->set_formatter(logFmt);
}

int main(int argc, char **argv) {
  initMongo();
  initLog();
  parseOid();
  //  initMongo();
  initIP(true);
  scanSNMP();
  return 0;
}
