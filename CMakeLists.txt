cmake_minimum_required(VERSION 3.13)
project(snmp)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
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
find_package(Boost COMPONENTS system filesystem regex thread REQUIRED)
if (Boost_FOUND)

    message(STATUS "Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
    message(STATUS "Boost_LIBRARIES: ${Boost_LIBRARIES}")
    message(STATUS "Boost_VERSION: ${Boost_VERSION}")

    #    include_directories(${Boost_INCLUDE_DIRS})

endif ()
add_executable(snmp snmp_test_success.cpp)
set_target_properties(snmp PROPERTIES OUTPUT_NAME "SNMP_")
target_link_libraries(snmp
        /usr/local/lib/libbsoncxx.so.3.4.0
        #/usr/local/lib/libbsoncxx.so._noabi
        /usr/local/lib/libmongocxx.so._noabi
        /home/user/boost_1_69_0/stage/lib/libboost_system.a
        /home/user/boost_1_69_0/stage/lib/libboost_thread.a
        /home/user/boost_1_69_0/stage/lib/libboost_regex.a
        /usr/local/lib/libnetsnmp.so
        #        /usr/lib/x86_64-linux-gnu/libboost_system.so
        #        /usr/lib/x86_64-linux-gnu/libboost_filesystem.so
        #        ${Boost_LIBRARIES}
        )

project(mongo)
add_executable(mongo mongo_test_success.cpp)
set_target_properties(mongo PROPERTIES OUTPUT_NAME "MONGO_")
target_link_libraries(mongo
        /usr/local/lib/libbsoncxx.so.3.4.0
        #/usr/local/lib/libbsoncxx.so._noabi
        /usr/local/lib/libmongocxx.so._noabi
        /home/user/boost_1_69_0/stage/lib/libboost_system.a
        /home/user/boost_1_69_0/stage/lib/libboost_thread.a
        /home/user/boost_1_69_0/stage/lib/libboost_regex.a
        /usr/local/lib/libnetsnmp.so
        #        /usr/lib/x86_64-linux-gnu/libboost_system.so
        #        /usr/lib/x86_64-linux-gnu/libboost_filesystem.so
        #        ${Boost_LIBRARIES}
        )
project(ping)
add_executable(ping ping_test_success.cpp)
set_target_properties(ping PROPERTIES OUTPUT_NAME "PING_")
target_link_libraries(ping
        /usr/local/lib/libbsoncxx.so.3.4.0
        #/usr/local/lib/libbsoncxx.so._noabi
        /usr/local/lib/libmongocxx.so._noabi
        /home/user/boost_1_69_0/stage/lib/libboost_system.a
        /home/user/boost_1_69_0/stage/lib/libboost_thread.a
        /home/user/boost_1_69_0/stage/lib/libboost_regex.a
        /usr/local/lib/libnetsnmp.so
        #        /usr/lib/x86_64-linux-gnu/libboost_system.so
        #        /usr/lib/x86_64-linux-gnu/libboost_filesystem.so
        #        ${Boost_LIBRARIES}
        )