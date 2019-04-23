#include <boost/algorithm/string.hpp>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
using std::cout;
using std::endl;
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>
#include <iostream>
#include <vector>

using namespace std;
using namespace boost;

void formatModel(std::string str) {
  boost::trim(str);
  size_t found;

  found = str.find("Xerox WorkCentre 5330");
  if (found != std::string::npos) {
    str = "Xerox WorkCentre 5330";
  }

  found = str.find("Xerox VersaLink C600");
  if (found != std::string::npos) {
    str = "Xerox VersaLink C600";
  }
  found = str.find("Xerox WorkCentre 5330");
  if (found != std::string::npos) {
    str = "Xerox WorkCentre 5330";
  }
  found = str.find("Xerox Phaser 5550DN");
  if (found != std::string::npos) {
    str = "Xerox Phaser 5550DN";
  }
  found = str.find("Xerox Phaser 3610");
  if (found != std::string::npos) {
    str = "Xerox Phaser 3610";
  }
  found = str.find("Xerox Phaser 6360DN");
  if (found != std::string::npos) {
    str = "Xerox Phaser 6360DN";
  }
  found = str.find("Xerox WorkCentre 6505DN");
  if (found != std::string::npos) {
    str = "Xerox WorkCentre 6505DN";
  }
  found = str.find("Xerox WorkCentre 5945");
  if (found != std::string::npos) {
    str = "Xerox WorkCentre 5945";
  }

  found = str.find("Lexmark");
  if (found != std::string::npos) {
    std::vector<std::string> details;
    boost::split(details, str, boost::is_any_of(" "));
    // If I iterate through the vector there is only one element "John" and not
    // all ?
    /*
     * for (std::vector<std::string>::iterator pos = details.begin();
           pos != details.end(); ++pos) {
        cout << *pos << endl;
      }
  */
    try {
      str = details.at(0) + " " + details.at(1);
    } catch (std::out_of_range o) {
      std::cout << o.what() << std::endl;
    }
  }

  cout << str << "\n";
}

int main() {
  char *s = "Hello, World!";
  formatModel(strdup(s));
  formatModel("Lexmark E450dn 6215V65 LM.SZ.P113");
  return 0;
}