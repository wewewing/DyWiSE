cmake_minimum_required(VERSION 3.27)
project(DFCT)
FIND_PACKAGE(OpenSSL REQUIRED)
set(CMAKE_CXX_STANDARD 17)
link_libraries(-lrelic -lcrypto -lgmp -lpthread pqxx  OpenSSL::Crypto )
link_directories(/usr/local/lib)
add_executable(DFCT
        primitive.h
        primitive.cpp
        Util/CommonUtil.h
        Util/CommonUtil.cpp
        GGM/GGMTree.h
        GGM/GGMTree.cpp
        GGM/GGMNode.h
        main.cpp)
