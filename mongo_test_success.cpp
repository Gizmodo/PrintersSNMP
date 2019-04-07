#include <iostream>

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>

int main(int, char **) {
    mongocxx::instance inst{};
    mongocxx::client conn{mongocxx::uri{"mongodb://192.168.88.254/testdb"}};

    bsoncxx::builder::stream::document document{};

    auto collection = conn["testdb"]["testcollection"];
    document << "hello" << "world" << "1" << "2" ;

  auto builder = bsoncxx::builder::stream::document{};
  bsoncxx::document::value doc_value = builder
      << "name" << "MongoDB"
      << "type" << "database"
      << "count" << 1
      << "versions" << bsoncxx::builder::stream::open_array
      << "v3.2" << "v3.0" << "v2.6"
      << bsoncxx::builder::stream::close_array
      << "info" << bsoncxx::builder::stream::open_document
      << "x" << 203
      << "y" << 102
      <<"Date" <<bsoncxx::types::b_date(std::chrono::system_clock::now())
      << bsoncxx::builder::stream::close_document
      << bsoncxx::builder::stream::finalize;


    collection.insert_one(doc_value.view());
    auto cursor = collection.find({});

    for (auto &&doc : cursor) {
        std::cout << bsoncxx::to_json(doc) << std::endl;
    }
}