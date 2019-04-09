cmake_minimum_required(VERSION 3.10)
project(snmp)
set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_CXX_STANDARD 11)
set(BOOST_ROOT /home/user/boost_1_69_0)
set(BOOST_INCLUDEDIR /home/user/boost_1_69_0)
set(BOOST_LIBRARYDIR /home/user/boost_1_69_0/stage/lib)
include_directories(
        /usr/local/include/mongocxx/v_noabi
        /usr/local/include/bsoncxx/v_noabi
        /home/user/boost_1_69_0
        /usr/local/include/net-snmp
)
set(Boost_USE_STATIC OFF)
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED OFF)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost COMPONENTS thread log log_setup system  date_time  chrono REQUIRED)
if (Boost_FOUND)

    message(STATUS "Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
    message(STATUS "Boost_LIBRARIES: ${Boost_LIBRARIES}")
    message(STATUS "Boost_VERSION: ${Boost_VERSION}")

    #    include_directories(${Boost_INCLUDE_DIRS})

endif ()

project(mongo_test)
add_executable(mongo_test mongo_test.cpp)
set_target_properties(mongo_test PROPERTIES OUTPUT_NAME "mongo_test")
target_link_libraries(mongo_test
        /usr/local/lib/libbsoncxx.so.3.4.0
        #/usr/local/lib/libbsoncxx.so._noabi
        /usr/local/lib/libmongocxx.so._noabi
        /home/user/boost_1_69_0/stage/lib/libboost_system.a
        /home/user/boost_1_69_0/stage/lib/libboost_thread.a
        /home/user/boost_1_69_0/stage/lib/libboost_regex.a
        /usr/local/lib/libnetsnmp.so
        )

project(snmp_mongo)
add_executable(snmp_mongo snmp_mongo.cpp)
set_target_properties(snmp_mongo PROPERTIES OUTPUT_NAME "snmp_mongo")
target_link_libraries(snmp_mongo
        /usr/local/lib/libbsoncxx.so.3.4.0
        #/usr/local/lib/libbsoncxx.so._noabi
        /usr/local/lib/libmongocxx.so._noabi
        /home/user/boost_1_69_0/stage/lib/libboost_system.a
        /home/user/boost_1_69_0/stage/lib/libboost_thread.a
        /home/user/boost_1_69_0/stage/lib/libboost_log.a
        /usr/local/lib/libnetsnmp.so
        )