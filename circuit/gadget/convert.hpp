/*
 * @file: convert.hpp
 * @author: Andrew G. Ma, jimmyshi
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#ifndef GADGET_UTIL
#define GADGET_UTIL

#include "util/uint256.h"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/relations/variable.hpp"
#include "libff/common/default_types/ec_pp.hpp"
#include "libff/common/profiling.hpp"
#include "libff/common/utils.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

#include <fstream>
#include <string>

#include "field.h"

using namespace std;
using namespace libsnark;
using namespace libff;

template <typename T>
std::vector<bool> to_bool_vector(T input)
{
    std::vector<unsigned char> input_v(input.begin(), input.end());

    return convertBytesVectorToVector(input_v);
}

std::vector<bool> uint256_to_bool_vector(uint256 input)
{
    return to_bool_vector(input);
}

std::vector<bool> uint64_to_bool_vector(uint64_t input)
{
    auto num_bv = convertIntToVectorLE(input);

    return convertBytesVectorToVector(num_bv);
}

void insert_uint256(std::vector<bool> &into, uint256 from)
{
    std::vector<bool> blob = uint256_to_bool_vector(from);
    into.insert(into.end(), blob.begin(), blob.end());
}

void insert_uint64(std::vector<bool> &into, uint64_t from)
{
    std::vector<bool> num = uint64_to_bool_vector(from);
    into.insert(into.end(), num.begin(), num.end());
}

template <typename T>
T swap_endianness_u64(T v)
{
    if (v.size() != 64)
    {
        throw std::length_error("invalid bit length for 64-bit unsigned integer");
    }

    for (size_t i = 0; i < 4; i++)
    {
        for (size_t j = 0; j < 8; j++)
        {
            std::swap(v[i * 8 + j], v[((7 - i) * 8) + j]);
        }
    }

    return v;
}

template <typename T>
T swap_endianness(T c)
{
    T r = 0;
    for (size_t i = 0; i < sizeof(T) * 8; i++)
    {
        r <<= 1;
        r |= (c & 0x1);
        c >>= 1;
    }
    return r;
}

template <typename FieldT>
linear_combination<FieldT> packed_addition(pb_variable_array<FieldT> input)
{
    auto input_swapped = swap_endianness_u64(input);

    return pb_packing_sum<FieldT>(pb_variable_array<FieldT>(
        input_swapped.rbegin(), input_swapped.rend()));
}

typedef bigint<alt_bn128_r_limbs> bigint_r;
#define bigint_len 32

void set_bit(bigint_r &num, const std::size_t bitno, bool b)
{
    assert(bitno < 256 * GMP_NUMB_BITS);

    const std::size_t part = bitno / GMP_NUMB_BITS;
    const std::size_t bit = bitno - (GMP_NUMB_BITS * part);
    const mp_limb_t one = 1;
    mp_limb_t pend = one << bit;

    if (b)
        num.data[part] |= pend;
    else
        num.data[part] &= ~pend;
}

template <typename FieldT>
FieldT uint256_to_fp(uint256 x_256)
{
    vector<bool> bits = uint256_to_bool_vector(x_256);
    bigint_r r;
    for (size_t i = 0; i < 256; i++)
        set_bit(r, i, bits[i]);
    return r;
}

template <typename FieldT>
uint256 fp_to_uint256(const FieldT &fp)
{
    bigint_r num = fp.as_bigint();
    vector<unsigned char> bytes;
    for (size_t i = 0; i < 256 / 8; i++)
    {
        char c = 0;
        for (size_t j = 0; j < 8; j++)
        {
            bool bit = num.test_bit(i * 8 + j);
            c <<= 1;
            c |= bit;
        }
        bytes.push_back(c);
    }

    return uint256(bytes);
}

//二进制字节数组转换为Fp
template <typename FieldT>
FieldT byte_to_fp(unsigned char *bytebuf)
{
    bigint_r b;
    memcpy(&b.data[0], bytebuf, bigint_len);
    //FieldT fp=b;
    return b;
}

//fp转换为16进制字符串
template <typename FieldT>
void fp_to_byte(FieldT &b, unsigned char *bytebuf)
{
    memcpy((char *)bytebuf, (char *)&b.as_bigint().data[0], bigint_len);
}

#endif