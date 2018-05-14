/*
 * @file: util.cpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "util.h"
#include <algorithm>
#include <stdexcept>

std::vector<unsigned char> convertIntToVectorLE(const uint64_t val_int) {
    std::vector<unsigned char> bytes;

    for(size_t i = 0; i < 8; i++) {
        bytes.push_back(val_int >> (i * 8));
    }

    return bytes;
}

std::vector<unsigned char> convertBoolVectorToBytesVector(const std::vector<bool>& bool_vec) {
    std::vector<unsigned char> ret;
    ret.resize((bool_vec.size() + 7) / 8 ); //不够的补0

    for (size_t i = 0; i < ret.size(); i++) {
        unsigned char c = 0;
        for(size_t j = 0; j < 8; j++) {
            c <<= 1;
            c += bool_vec[i * 8 + j];
        }
        ret[i] = c;
    }
    return ret;
}

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes) {
    std::vector<bool> ret;
    ret.resize(bytes.size() * 8);

    unsigned char c;
    for (size_t i = 0; i < bytes.size(); i++) {
        c = bytes.at(i);
        for (size_t j = 0; j < 8; j++) {
            ret.at((i*8)+j) = (c >> (7-j)) & 1;
        }
    }

    return ret;
}

// Convert boolean vector (big endian) to integer
uint64_t convertVectorToInt(const std::vector<bool>& v) {
    if (v.size() > 64) {
        throw std::length_error ("boolean vector can't be larger than 64 bits");
    }

    uint64_t result = 0;
    for (size_t i=0; i<v.size();i++) {
        if (v.at(i)) {
            result |= (uint64_t)1 << ((v.size() - 1) - i);
        }
    }

    return result;
}
