/*
 * NET-SNMP demo
 *
 * This program demonstrates different ways to query a list of hosts
 * for a list of variables.
 *
 * It would of course be faster just to send one query for all variables,
 * but the intention is to demonstrate the difference between synchronous
 * and asynchronous operation.
 *
 * Niels Baggesen (Niels.Baggesen@uni-c.dk), 1999.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include <definitions.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

#include <boost/container/vector.hpp>
using namespace boost::container;
using std::cout;
using std::endl;
boost::container::vector<std::string> ipList;

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
void initIPsList() {
  for (int i = 88; i < 89; ++i) {
    for (int j = 0; j < 255; ++j) {
      ipList.push_back("192.168." + std::to_string(i) + "." +
                       std::to_string(j));
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
  ss.timeout = 100000;
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

void initialize(void) {
  struct oid_struct *op = oids;

  /* Win32: init winsock */
  SOCK_STARTUP;

  /* initialize library */
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

int main(int argc, char **argv) {
  initialize();
  initIPsList();

  for (const std::string ip : ipList) {
    startSNMP(ip);
  }
  printf("---------- synchronous -----------\n");

  return 0;
}
