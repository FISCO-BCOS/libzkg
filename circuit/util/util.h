/*
 * @file: util.h
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#ifndef ZKG_UTIL_H_
#define ZKG_UTIL_H_

#include <vector>
#include <cstdint>
#include <fstream>
#include <string>

std::vector<unsigned char> convertIntToVectorLE(const uint64_t val_int);
std::vector<unsigned char> convertBoolVectorToBytesVector(const std::vector<bool>& bool_vec);
std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes);
uint64_t convertVectorToInt(const std::vector<bool>& v);

#endif // ZKG_UTIL_H_
