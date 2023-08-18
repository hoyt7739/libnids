project(nids)

add_compile_definitions(NIDS_EXPORTS)

file(TOUCH ${CMAKE_CURRENT_BINARY_DIR}/config.h)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(WPCAP_DIR ${CMAKE_SOURCE_DIR}/third_party/wpcap)
set(PLATFORM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${PLATFORM})

if(WIN32)
    set(INCLUDE_DIRS ${WPCAP_DIR}/include ${PLATFORM_DIR})
    set(LINK_DIRS ${WPCAP_DIR}/lib/x64)
    set(LIBRARIES wpcap ws2_32)
elseif(UNIX)
    set(INCLUDE_DIRS /usr/include/glib-2.0 /usr/lib64/glib-2.0/include)
    set(LIBRARIES pcap net gthread-2.0 glib-2.0)
endif()

aux_source_directory(${PLATFORM_DIR} PLATFORM_SOURCES)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SOURCES)
add_library(${PROJECT_NAME} SHARED ${PLATFORM_SOURCES} ${SOURCES})

target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_SOURCE_DIR}/include PRIVATE ${INCLUDE_DIRS})
target_link_directories(${PROJECT_NAME} PRIVATE ${LINK_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBRARIES})
