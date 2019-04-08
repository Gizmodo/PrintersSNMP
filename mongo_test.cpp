#include <iostream>

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
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
int main(int, char **) {
  int res;
  const char *ipString = "255.255.255.255";
  unsigned int ipAddr;

  res = ipStringToNumber(ipString, &ipAddr);
  std::cout << ipAddr;
  return 1;
}
int main1(int, char **) {
  mongocxx::instance inst{};
  mongocxx::client conn{mongocxx::uri{"mongodb://192.168.88.254/testdb"}};

  bsoncxx::builder::stream::document document{};

  auto collection = conn["testdb"]["testcollection"];
  document << "hello"
           << "world"
           << "1"
           << "2";

  auto builder = bsoncxx::builder::stream::document{};
  bsoncxx::document::value doc_value =
      builder << "name"
              << "MongoDB"
              << "type"
              << "database"
              << "count" << 1 << "versions"
              << bsoncxx::builder::stream::open_array << "v3.2"
              << "v3.0"
              << "v2.6" << bsoncxx::builder::stream::close_array << "info"
              << bsoncxx::builder::stream::open_document << "x" << 203 << "y"
              << 102 << "Date"
              << bsoncxx::types::b_date(std::chrono::system_clock::now())
              << bsoncxx::builder::stream::close_document
              << bsoncxx::builder::stream::finalize;

  collection.insert_one(doc_value.view());
  auto cursor = collection.find({});

  for (auto &&doc : cursor) {
    std::cout << bsoncxx::to_json(doc) << std::endl;
  }
}