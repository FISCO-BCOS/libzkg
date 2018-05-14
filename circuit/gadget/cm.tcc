/*
 * @file: cm.tcc
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include <ctime>
#include <cstdlib>
#include "merkle.tcc"
#include "prf.tcc"
#include "cm_pool.hpp"

//-----------------------承诺部分------------------------
template <typename FieldT>
class cm_gadget : gadget<FieldT>
{
    /*
     *  cm = hash(tmp, r)
     *             |
     *            tmp = hash(apk, v, v, v, v)
    */

  private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;
    std::shared_ptr<digest_variable<FieldT>> result;

  public:
    cm_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &apk,
        pb_variable_array<FieldT> &v,
        pb_variable_array<FieldT> &r,
        std::shared_ptr<digest_variable<FieldT>> result) : gadget<FieldT>(pb), result(result)
    {
        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));
        //H(apk,v)
        block1.reset(new block_variable<FieldT>(pb, {apk, v, v, v, v}, ""));
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
            ""));
        pb_variable_array<FieldT> intermediate_block;
        intermediate_block.insert(intermediate_block.end(), (*intermediate_hash).bits.begin(), (*intermediate_hash).bits.end());
        //H(H(apk,v),r)
        block2.reset(new block_variable<FieldT>(pb, {intermediate_block, r}, ""));
        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block2->bits,
            *result,
            ""));
    }

    void generate_r1cs_constraints()
    {
        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(uint256 apk, int64_t v, uint256 r)
    {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();

        uint256 cm_256 = calculate_cm(apk, v, r);
        result->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(cm_256));
    }

    static uint256 calculate_cm(uint256 apk, int64_t v, uint256 r)
    {
        CSHA256 hasher1;
        CSHA256 hasher2;

        uint256 imt;
        uint256 result;

        //H(apk )
        hasher1.Write(apk.begin(), 32);

        //H(apk,v,v,v,v)
        auto value_vec = convertIntToVectorLE(v);
        hasher1.Write(&value_vec[0], value_vec.size());
        hasher1.Write(&value_vec[0], value_vec.size());
        hasher1.Write(&value_vec[0], value_vec.size());
        hasher1.Write(&value_vec[0], value_vec.size());
        hasher1.FinalizeNoPadding(imt.begin());

        //H( H(apk,v,v,v,v),r)
        hasher2.Write(imt.begin(), 32);
        hasher2.Write(r.begin(), 32);
        hasher2.FinalizeNoPadding(result.begin());

        return result;
    }
};

class cm_caculator
{
  public:
    static uint256 cm(uint256 apk, int64_t v, uint256 r)
    {
        CSHA256 hasher1;
        CSHA256 hasher2;

        uint256 imt;
        uint256 result;

        //H(apk )
        hasher1.Write(apk.begin(), 32);

        //H(apk,v,v,v,v)
        auto value_vec = convertIntToVectorLE(v);
        hasher1.Write(&value_vec[0], value_vec.size());
        hasher1.Write(&value_vec[0], value_vec.size());
        hasher1.Write(&value_vec[0], value_vec.size());
        hasher1.Write(&value_vec[0], value_vec.size());
        hasher1.FinalizeNoPadding(imt.begin());

        //H( H(apk,v,v,v,v),r)
        hasher2.Write(imt.begin(), 32);
        hasher2.Write(r.begin(), 32);
        hasher2.FinalizeNoPadding(result.begin());

        return result;
    }
};

//-------------匿名交易，被消费的cm------------
template <typename FieldT>
class cm_in_gadget : public gadget<FieldT>
{
    /*
     *  rt = hash(tree_path...., cm)
     *                            |
     *                           cm = hash(hash(apk, v, v, v, v), r)
     *                                           |
     *                                          apk = prf(ask)
    */

  private:

    std::shared_ptr<digest_variable<FieldT>> 
        //ai shared
        p_ask, p_r, //r random number, rt root
        //pi    
        p_rt;

    //ai local
    pb_variable<FieldT> value_enforce;
    std::shared_ptr<digest_variable<FieldT>> p_apk, p_commitment;
    // and value below

    //dependency gadget
    std::shared_ptr<prf_gadget<FieldT>> prf_gad;
    std::shared_ptr<cm_gadget<FieldT>> cm_gad;
    std::shared_ptr<libzcash::merkle_tree_gadget<FieldT>> cm_tree_gad;

  public:
    pb_variable_array<FieldT> value; // ai local

    cm_in_gadget(
        protoboard<FieldT> &pb,
        std::shared_ptr<digest_variable<FieldT>> p_ask,
        std::shared_ptr<digest_variable<FieldT>> p_r,
        std::shared_ptr<digest_variable<FieldT>> p_rt) : gadget<FieldT>(pb), p_ask(p_ask), p_r(p_r), p_rt(p_rt)
    {
        value.allocate(pb, 64);
        p_apk.reset(new digest_variable<FieldT>(pb, 256, ""));
        p_commitment.reset(new digest_variable<FieldT>(pb, 256, ""));

        prf_gad.reset(new prf_gadget<FieldT>(
            pb,
            p_ask->bits,
            p_apk));

        cm_gad.reset(new cm_gadget<FieldT>(
            pb,
            p_apk->bits,
            value,
            p_r->bits,
            p_commitment));

        value_enforce.allocate(pb);
        cm_tree_gad.reset(new libzcash::merkle_tree_gadget<FieldT>(
            pb,
            *p_commitment,
            *p_rt,
            value_enforce));
    }

    void generate_r1cs_constraints()
    {
        for (size_t i = 0; i < 64; i++)
        {
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                value[i],
                "boolean_value");
        }

        p_apk->generate_r1cs_constraints();
        p_commitment->generate_r1cs_constraints();
        prf_gad->generate_r1cs_constraints();
        cm_gad->generate_r1cs_constraints();

        // value * (1 - enforce) = 0
        // Given `enforce` is boolean constrained:
        // If `value` is zero, `enforce` _can_ be zero.
        // If `value` is nonzero, `enforce` _must_ be one.
        generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce, "");

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                                         packed_addition(this->value),
                                         (1 - value_enforce),
                                         0),
                                        "");

        cm_tree_gad->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        uint256 &r_rt, //返回计算得到的根root
        uint64_t v_64, uint256 ask_256, uint256 r_256, std::shared_ptr<CMPool> cm_pool)
    {
        value.fill_with_bits(this->pb, uint64_to_bool_vector(v_64));
        p_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(r_256));

        p_ask->bits.fill_with_bits(this->pb, uint256_to_bool_vector(ask_256));
        prf_gad->generate_r1cs_witness(); //此步骤会自动计算 p_apk

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        uint256 apk_256 = prf_caculator::prf(ask_256);
        cm_gad->generate_r1cs_witness(apk_256, v_64, r_256); //此步骤自动计算cm

        //计算cm_256
        uint256 cm_256 = cm_caculator::cm(apk_256, v_64, r_256);
        //根据承诺池，构造merkle路径
        ZCIncrementalMerkleTree tree;
        CMPool::index_t cm_i = cm_pool->get_index(cm_256.GetHex());

        if (cm_i < 0)
        {
            LOG(WARNING) << "Witness generate error: CM is illegal!" << endl;
            throw CMNotFoundException();
        }

        //To smaller cm_tree. We generate a random around range [from, to] which to - from < tree_cap && from <= cm_i <= to
        CMPool::index_t from, to;
        getRandAroundCmPoolRange(from, to, cm_i, cm_pool->size());

        //用构造cm以及之前的所有cm构造的merkle树。注意：cm一定是此tree最后一个append的元素
        cm_pool->for_each_cm_range(from, cm_i,
                                   [&](std::string cm) {
                                       tree.append(libzcash::SHA256Compress(uint256S(cm)));
                                   });

        //再用cm之后所有的cm来构造当前的merkle树，目的是为了计算当前root下的merkle路径
        ZCIncrementalWitness tree_wit(tree);
        if (cm_i + 1 <= to) //如果cm不是最后一个承诺
            cm_pool->for_each_cm_range(cm_i + 1, to,
                                       [&](std::string cm) {
                                           tree_wit.append(libzcash::SHA256Compress(uint256S(cm)));
                                       });
        LOG(TRACE) << "CM Root: " << tree_wit.root().GetHex() << endl;
        r_rt = uint256S(tree_wit.root().GetHex()); //hashToUint256(tree_wit.root());

        // Set enforce flag for nonzero input value
        this->pb.val(value_enforce) = (v_64 != 0) ? FieldT::one() : FieldT::zero();

        p_rt->bits.fill_with_bits(this->pb, uint256_to_bool_vector(r_rt));

        // Witness merkle tree authentication path
        cm_tree_gad->generate_r1cs_witness(tree_wit.path()); //此步骤自动计算rt
    }

    pb_variable_array<FieldT> &get_apk_pb_variable()
    {
        return p_apk->bits;
    }

    pb_variable_array<FieldT> &get_value_pb_variable()
    {
        return value;
    }

    void check_witness(uint64_t v_64, uint256 ask_256, uint256 r_256, uint256 rt_256)
    {
        //check generated apk witness
        uint256 apk_256 = prf_caculator::prf(ask_256);
        p_apk->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_256));
        LOG(DEBUG) << "apk: " << apk_256.GetHex() << endl;
        LOG(DEBUG) << "Check apk witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;

        //check generated cm witness
        uint256 cm_256 = cm_caculator::cm(apk_256, v_64, r_256);
        LOG(DEBUG) << "cm_in: " << cm_256.GetHex() << endl;
        p_commitment->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cm_256));
        LOG(DEBUG) << "Check cm_in witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;

        //check generated rt witness
        LOG(DEBUG) << "rt: " << rt_256.GetHex() << endl;
        p_rt->bits.fill_with_bits(this->pb, uint256_to_bool_vector(rt_256));
        LOG(DEBUG) << "Check merkle_root witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;
    }

  private:
    //Get a random around range of cm_pool according to cm_idx and tree capacity
    void getRandAroundCmPoolRange(
        CMPool::index_t &r_from, CMPool::index_t &r_to, //return [from, to]
        CMPool::index_t idx,                            //around according to
        size_t cm_pool_size)
    {
        //Tree capacity
        CMPool::index_t cap = (CMPool::index_t)treeCapacity();

        //rand [to_lower_bound, to_upper_bound) -> to
        CMPool::index_t to_upper_bound = min(idx + cap, (CMPool::index_t)cm_pool_size),
                        to_lower_bound = idx;

        // [from, to]
        r_to = randomRange(to_lower_bound, to_upper_bound);
        r_from = max(CMPool::index_t(0), r_to - cap + 1);
    }

    static size_t treeCapacity()
    {
        return size_t(1 << INCREMENTAL_MERKLE_TREE_DEPTH);
    }

    template <typename T>
    T randomRange(T lower_bound, T upper_bound)
    { //random [lower_bound, upper_bound)
        std::srand(std::time(nullptr));
        return (std::rand() % (upper_bound - lower_bound) + lower_bound);
    }
};

//-------------匿名交易，新生成的cm------------
template <typename FieldT>
class cm_out_gadget : public gadget<FieldT>
{
  private:
    //pi
    std::shared_ptr<digest_variable<FieldT>> p_commitment;

    //ai local
    std::shared_ptr<digest_variable<FieldT>> p_apk, p_r;

    //dependency gadget
    std::shared_ptr<cm_gadget<FieldT>> cm_gad;

  public:
    pb_variable_array<FieldT> value;

    cm_out_gadget(
        protoboard<FieldT> &pb,
        std::shared_ptr<digest_variable<FieldT>> p_commitment) : gadget<FieldT>(pb), p_commitment(p_commitment)
    {
        value.allocate(pb, 64);
        p_apk.reset(new digest_variable<FieldT>(pb, 256, ""));
        p_r.reset(new digest_variable<FieldT>(pb, 256, ""));

        cm_gad.reset(new cm_gadget<FieldT>(
            pb,
            p_apk->bits,
            value,
            p_r->bits,
            p_commitment));
    }

    void generate_r1cs_constraints()
    {
        for (size_t i = 0; i < 64; i++)
        {
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                value[i],
                "boolean_value");
        }

        p_apk->generate_r1cs_constraints();
        p_r->generate_r1cs_constraints();

        cm_gad->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(uint256 &r_cm, uint256 &r_r, //r_cm，r_r生成的承诺和随机数在此处返回
                               uint64_t v_64, uint256 apk_256)
    {
        //生成随机数
        r_r = random_uint256();
        r_cm = cm_gadget<FieldT>::calculate_cm(apk_256, v_64, r_r);

        value.fill_with_bits(this->pb, uint64_to_bool_vector(v_64));
        p_apk->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_256));
        p_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(r_r));

        cm_gad->generate_r1cs_witness(apk_256, v_64, r_r); //此步骤自动计算cm
    }

    pb_variable_array<FieldT> &get_value()
    {
        return value;
    };

    void check_witness(uint256 cm_256, uint256 r_256)
    {
        LOG(DEBUG) << "r_out: " << cm_256.GetHex() << endl;
        p_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(r_256));
        LOG(DEBUG) << "Check r_out witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;

        //check generated rt witness
        LOG(DEBUG) << "cm_out: " << cm_256.GetHex() << endl;
        p_commitment->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cm_256));
        LOG(DEBUG) << "Check cm_out witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;
    }

    pb_variable_array<FieldT> &get_apk_pb_variable()
    {
        return p_apk->bits;
    }

    pb_variable_array<FieldT> &get_value_pb_variable()
    {
        return value;
    }
};
