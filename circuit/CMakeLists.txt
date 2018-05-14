add_compile_options(-std=c++11)
add_compile_options(-DCURVE_ALT_BN128)
add_compile_options(-DNO_PROCPS)
add_compile_options(-DMULTICORE)

set(LIB_NAME "circuit")

# 查找当前目录下的所有源文件
# 并将名称保存到 DIR_LIB_SRCS 变量
aux_source_directory(. DIR_LIB_SRCS)
aux_source_directory(./util DIR_LIB_SRCS)
aux_source_directory(./gadget SUB_DIR_LIB_SRCS)
include_directories(../libsnark)
#include_directories(../libsnark/libsnark)
include_directories(../libsnark/depends)
include_directories(../libsnark/depends/libff)
#include_directories(../libsnark/depends/libff/libff)
#include_directories(../libsnark/depends/libfqfft)
include_directories(../)
include_directories(./)
# 生成链接库
add_library (${LIB_NAME} STATIC ${DIR_LIB_SRCS} ${SUB_DIR_LIB_SRCS})

target_link_libraries(${LIB_NAME} snark)
target_link_libraries(${LIB_NAME} ff)
target_link_libraries(${LIB_NAME} zm)
target_link_libraries(${LIB_NAME} gmp)
target_link_libraries(${LIB_NAME} stdc++)
target_link_libraries(${LIB_NAME} procps)
target_link_libraries(${LIB_NAME} gmpxx)
target_link_libraries(${LIB_NAME} gomp)
