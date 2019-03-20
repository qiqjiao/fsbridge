cmake_minimum_required (VERSION 3.0)

project (fsbridge)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE REQUIRED fuse)

find_package(Threads)

file(GLOB SRC "*.cpp")
add_executable(fsbridge ${SRC})
target_link_libraries(fsbridge ${FUSE_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(fsbridge PUBLIC ${FUSE_INCLUDE_DIRS})
target_compile_options(fsbridge PUBLIC ${FUSE_CFLAGS_OTHER})

# message(${FUSE_LIBRARIES} ${FUSE_INCLUDE_DIRS} ${FUSE_CFLAGS_OTHER})
