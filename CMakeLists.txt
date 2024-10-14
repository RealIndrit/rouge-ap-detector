cmake_minimum_required(VERSION 3.29)
project(WifiHelper C)

set(CMAKE_C_STANDARD 11)

add_library(wlanapi IMPORTED STATIC)
set_target_properties(wlanapi PROPERTIES IMPORTED_LOCATION "C:/WINDOWS/System32/wlanapi.dll")

add_executable(WifiHelper main.c)
target_link_libraries(WifiHelper wlanapi)