cmake_minimum_required (VERSION 3.0.0)

set(EXE_NAME "demo_zkg")
set(LIB_NAME "zkg")

set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -g -Wall")

set(ZKG_CLIENT_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${ZKG_CLIENT_CMAKE_DIR})


# 项目信息
project(libzkg)
set(VERSION 1.0.0)

#编译环境
find_package(Boost)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIR})
    add_definitions( "-DHAS_BOOST" )
endif()

find_package(OpenMP)
if(OPENMP_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

add_compile_options(-DMULTICORE)
#add_compile_options(-DBINARY_OUTPUT=OFF)
add_subdirectory(libsnark)

add_compile_options(-std=c++11)
add_compile_options(-DCURVE_ALT_BN128)
add_compile_options(-DNO_PROCPS)
add_compile_options(-DBINARY_OUTPUT=OFF)
add_subdirectory(circuit)

# 并将名称保存到 DIR_SRCS 变量
aux_source_directory(. DIR_SRCS)

# 指定生成目标
#add_executable(${EXE_NAME} ${DIR_SRCS})
# 添加链接库
#target_link_libraries (${EXE_NAME} ${Boost_LIBRARIES})
#target_link_libraries(${EXE_NAME} snark)
#target_link_libraries(${EXE_NAME} ff)
#target_link_libraries(${EXE_NAME} circuit)

add_library (${LIB_NAME} ${DIR_SRCS})
target_link_libraries (${LIB_NAME} ${Boost_LIBRARIES})
target_link_libraries(${LIB_NAME} snark)
target_link_libraries(${LIB_NAME} ff)
target_link_libraries(${LIB_NAME} circuit)





