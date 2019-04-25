#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/container/vector.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/format.hpp>
#include <boost/log/attributes/named_scope.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
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
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
using boost::system::error_code;
using std::cout;
using std::endl;
using namespace std::chrono;
boost::container::vector<std::string> IPs;
typedef high_resolution_clock Clock;
typedef Clock::time_point ClockTime;

std::string printExecutionTime(ClockTime start_time, ClockTime end_time) {
  //  auto execution_time_ns = duration_cast<nanoseconds>(end_time -
  //  start_time).count(); auto execution_time_ms =
  //  duration_cast<microseconds>(end_time - start_time).count();
  auto execution_time_sec =
      duration_cast<seconds>(end_time - start_time).count();
  auto execution_time_min =
      duration_cast<minutes>(end_time - start_time).count();
  auto execution_time_hour =
      duration_cast<hours>(end_time - start_time).count();
  std::string res = "";

  if (execution_time_hour > 0)
    res = std::to_string(execution_time_hour) + " h, ";
  if (execution_time_min > 0)
    res = res + std::to_string(execution_time_min % 60) + " m, ";
  if (execution_time_sec > 0)
    res = res + std::to_string(execution_time_sec % 60) + " s";
  /*
   * if(execution_time_ms > 0)
    cout << "" << execution_time_ms % long(1E+3) << " MicroSeconds, ";
  if(execution_time_ns > 0)
    cout << "" << execution_time_ns % long(1E+6) << " NanoSeconds, ";
    */
  return res;
}
void print(const boost::system::error_code & /*e*/,
           boost::asio::deadline_timer *t, int *count) {

  BOOST_LOG_TRIVIAL(info) << boost::format("Start at: %s") % (t->expires_at() + boost::posix_time::hours(3));
  auto dt = t->expires_at() + boost::posix_time::hours(8);
  t->expires_at(dt);
  BOOST_LOG_TRIVIAL(info) << boost::format("Next  at: %s") % (dt + boost::posix_time::hours(3));
  cout << dt;
  t->async_wait(boost::bind(print, boost::asio::placeholders::error, t, count));
}

static void initLog() {
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
int main() {
  initLog();
  boost::asio::io_service io;

  int count = 0;
  boost::asio::deadline_timer t(io, boost::posix_time::seconds(1));
  t.async_wait(
      boost::bind(print, boost::asio::placeholders::error, &t, &count));

  io.run();

  std::cout << "Final count is " << count << std::endl;

  return 0;
}