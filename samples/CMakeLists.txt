project(samples)

set(LIBRARIES nids)
if(WIN32)
    set(LIBRARIES ${LIBRARIES} ws2_32)
endif()

foreach(SAMPLE overflows printall sniff)
    add_executable(${SAMPLE} ${SAMPLE}.c)
    target_link_libraries(${SAMPLE} ${LIBRARIES})
endforeach()
