/*
 * @file: prf.tcc
 * @author: Andrew G. Ma
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


//------------公私匙部分-----------------------------
//用户公钥由私钥哈希而来
template <typename FieldT>
class prf_gadget : gadget<FieldT>
{
  private:
    std::shared_ptr<block_variable<FieldT>> block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher;

  public:
    prf_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &a_sk,
        std::shared_ptr<digest_variable<FieldT>> result) : gadget<FieldT>(pb)
    {

        //H(a_sk,a_sk)
        block.reset(new block_variable<FieldT>(pb, {a_sk, a_sk}, ""));

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
};

class prf_caculator
{
  public:
    static uint256 prf(uint256 a_sk)
    {
        CSHA256 hasher;

        uint256 result;

        //H(a_sk a_sk)
        hasher.Write(a_sk.begin(), 32);
        hasher.Write(a_sk.begin(), 32);
        hasher.FinalizeNoPadding(result.begin());

        return result;
    }
};