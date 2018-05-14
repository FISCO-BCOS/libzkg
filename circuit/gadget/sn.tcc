/*
 * @file: sn.tcc
 * @author: Andrew G. Ma
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "util/uint256.h"
//--------------SN序列号-----------------------------
//序列号由用户私钥和随机数哈希而成
template <typename FieldT>
class sn_gadget : gadget<FieldT>
{
  private:
    std::shared_ptr<block_variable<FieldT>> block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher;

  public:
    sn_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &a_sk,
        pb_variable_array<FieldT> &r,
        std::shared_ptr<digest_variable<FieldT>> result) : gadget<FieldT>(pb)
    {

        //H(a_sk,r)
        block.reset(new block_variable<FieldT>(pb, {a_sk, r}, ""));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block->bits,
            *result,
            ""));
    }

    void generate_r1cs_constraints()
    {
        hasher->generate_r1cs_constraints();
    }

    void generate_r1cs_witness()
    {
        hasher->generate_r1cs_witness();
    }

    static uint256 calculate_sn(uint256 a_sk, uint256 r)
    {
        CSHA256 hasher;

        uint256 result;

        //H(a_sk r)
        hasher.Write(a_sk.begin(), 32);
        hasher.Write(r.begin(), 32);
        hasher.FinalizeNoPadding(result.begin());

        return result;
    }
};

class sn_caculator
{
  public:
    static uint256 sn(uint256 a_sk, uint256 r)
    {
        CSHA256 hasher;

        uint256 result;

        //H(a_sk r)
        hasher.Write(a_sk.begin(), 32);
        hasher.Write(r.begin(), 32);
        hasher.FinalizeNoPadding(result.begin());

        return result;
    }
};