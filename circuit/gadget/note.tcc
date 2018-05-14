/*
 * @file: note.tcc
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "cm.tcc"
#include "sn.tcc"
#include "field.h"
#include "convert.hpp"
#include "cm_pool.hpp"

//--------------Note：cm, sn的封装
template <typename FieldT>
class note_in_gadget : public gadget<FieldT>
{
  private:
    //shared var
    std::shared_ptr<digest_variable<FieldT>> p_rt, p_sn;

    //internal var
    std::shared_ptr<digest_variable<FieldT>> p_ask, p_r;

    //dependency gadget
    std::shared_ptr<cm_in_gadget<FieldT>> cm_in_gad;
    std::shared_ptr<sn_gadget<FieldT>> sn_gad;

    //other
    //ZCIncrementalWitness tree_wit;
  public:
    note_in_gadget(
        protoboard<FieldT> &pb,
        std::shared_ptr<digest_variable<FieldT>> p_rt,
        std::shared_ptr<digest_variable<FieldT>> p_sn) : gadget<FieldT>(pb), p_rt(p_rt), p_sn(p_sn)
    {
        p_ask.reset(new digest_variable<FieldT>(pb, 256, ""));
        p_r.reset(new digest_variable<FieldT>(pb, 256, ""));

        //Init CM gadget
        cm_in_gad.reset(new cm_in_gadget<FieldT>(
            pb,
            p_ask,
            p_r,
            p_rt));

        //Init SN gadget
        sn_gad.reset(new sn_gadget<FieldT>(
            pb,
            p_ask->bits,
            p_r->bits,
            p_sn));
    }

    void generate_r1cs_constraints()
    {
        p_ask->generate_r1cs_constraints();
        p_r->generate_r1cs_constraints();

        cm_in_gad->generate_r1cs_constraints();
        sn_gad->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        uint256 &r_rt, uint256 &r_sn, //计算得到的cm_root和sn，从此处返回
        uint256 ask_256, uint64_t v_64, uint256 r_256,
        std::shared_ptr<CMPool> cm_pool)
    {

        p_ask->bits.fill_with_bits(this->pb, uint256_to_bool_vector(ask_256));
        p_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(r_256));

        cm_in_gad->generate_r1cs_witness(r_rt, v_64, ask_256, r_256, cm_pool);

        r_sn = sn_caculator::sn(ask_256, r_256);
        sn_gad->generate_r1cs_witness();
    }

    pb_variable_array<FieldT> &get_apk_pb_variable()
    {
        return cm_in_gad->get_apk_pb_variable();
    };

    pb_variable_array<FieldT> &get_value_pb_variable()
    {
        return cm_in_gad->get_value_pb_variable();
    };

    void check_witness(uint256 rt_256, uint256 sn_256, uint256 ask_256, uint64_t v_64, uint256 r_256)
    {
        cm_in_gad->check_witness(v_64, ask_256, r_256, rt_256);

        LOG(DEBUG) << "sn: " << sn_256.GetHex() << endl;
        p_sn->bits.fill_with_bits(this->pb, uint256_to_bool_vector(sn_256));
        LOG(DEBUG) << "Check sn witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;
    }
};

//note_out里头只有cm_out，所以直接传递名字
#define note_out_gadget cm_out_gadget