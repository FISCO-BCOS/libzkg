/*
 * @file: exp.tcc
 * @author: Andrew G. Ma, jimmyshi
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "field.h"
#include "convert.hpp"
#include "binary.tcc"

template <typename FieldT>
class exp_gadget : public gadget<FieldT>
{
    // caculate a ^ x = y
  private:
    const size_t EXP_SIZE = alt_bn128_r_bitcount; //254
    //ai shared
    pb_variable<FieldT> a, x, y;
    //ai local
    pb_variable_array<FieldT> 
        x_bins, 
        x_inv_bins,
        a_exps,
        tmps1, // = x_bins * a_exps
        //tmps2,    // = tmps1 + x_inv_bins
        tmps3; // tmps3[0] = one * tmps2[0], tmps3[1] = tmps3[0] * tmps2[1], y = tmps3.back()
    //gadgets
    std::shared_ptr<binary_gadget<FieldT>> x_binary_gad; //x --bin--> x_bin
  public:
    exp_gadget(
        protoboard<FieldT> &pb,
        pb_variable<FieldT> &a,
        pb_variable<FieldT> &x,
        pb_variable<FieldT> &y) : gadget<FieldT>(pb), a(a), x(x), y(y)
    {
        x_bins.allocate(pb, EXP_SIZE);
        x_inv_bins.allocate(pb, EXP_SIZE);
        a_exps.allocate(pb, EXP_SIZE);
        tmps1.allocate(pb, EXP_SIZE);
        tmps3.allocate(pb, EXP_SIZE);

        x_binary_gad = std::make_shared<binary_gadget<FieldT>>(
            pb,
            x_bins,
            x);
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template <typename FieldT>
void exp_gadget<FieldT>::generate_r1cs_constraints()
{
    //x_bins
    x_binary_gad->generate_r1cs_constraints();

    //a_exps
    for (size_t i = 0; i < EXP_SIZE; i++)
    {
        if (i == 0) //a[0001] = a
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                                             FieldT::one(),
                                             a,
                                             a_exps[0]),
                                         FMT(this->annotation_prefix, " S_%zu", i));
        else //a[0010] = a[0001] * a[0001], a[0100] = a[0010] * a[0010]...
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                                             a_exps[i - 1],
                                             a_exps[i - 1],
                                             a_exps[i]),
                                         FMT(this->annotation_prefix, " S_%zu", i));
    }

    //x_inv_bins
    for (size_t i = 0; i < EXP_SIZE; i++)
    {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                                         FieldT::one() - x_bins[i],
                                         FieldT::one(),
                                         x_inv_bins[i]),
                                     FMT(this->annotation_prefix, " S_%zu", i));
    }

    //tmps1 = = x_bins * a_exps
    for (size_t i = 0; i < EXP_SIZE; i++)
    {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                                         x_bins[i],
                                         a_exps[i],
                                         tmps1[i]),
                                     FMT(this->annotation_prefix, " S_%zu", i));
    }

    //tmps2 & tmps3
    //tmps2 = tmps1 + x_inv_bins
    //tmps3 = tmps3[0] = one * tmps2[0], tmps3[1] = tmps3[0] * tmps2[1], y = tmps3.back()
    for (size_t i = 0; i < EXP_SIZE; i++)
    {
        if (i == 0) //tmps3 = tmps3[0] = one * tmps2[0]
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                                             tmps1[0] + x_inv_bins[0],
                                             FieldT::one(),
                                             tmps3[0]),
                                         FMT(this->annotation_prefix, " S_%zu", i));
        else //tmps3[1] = tmps3[0] * tmps2[1]...
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                                             tmps1[i] + x_inv_bins[i],
                                             tmps3[i - 1],
                                             tmps3[i]),
                                         FMT(this->annotation_prefix, " S_%zu", i));
    }

    //y = tmps3.back()
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                                     tmps3[EXP_SIZE - 1],
                                     FieldT::one(),
                                     y),
                                 FMT(this->annotation_prefix, " S_%zu"));
}

template <typename FieldT>
void exp_gadget<FieldT>::generate_r1cs_witness()
{
    //x_bins
    x_binary_gad->generate_r1cs_witness(false); //置为false，表示已知x倒推x_bins

    //a_exps
    for (size_t i = 0; i < EXP_SIZE; i++)
    {
        if (i == 0) //a[0001] = a
            this->pb.val(a_exps[0]) = this->pb.lc_val(a);
        else //a[0010] = a[0001] * a[0001], a[0100] = a[0010] * a[0010]...
            this->pb.val(a_exps[i]) = this->pb.lc_val(a_exps[i - 1]) * this->pb.lc_val(a_exps[i - 1]);
    }

    //x_inv_bins
    for (size_t i = 0; i < EXP_SIZE; i++)
    {
        this->pb.val(x_inv_bins[i]) = FieldT::one() - this->pb.lc_val(x_bins[i]);
    }

    //tmps1 = = x_bins * a_exps
    for (size_t i = 0; i < EXP_SIZE; i++)
    {
        this->pb.val(tmps1[i]) = this->pb.lc_val(a_exps[i]) * this->pb.lc_val(x_bins[i]);
    }

    //tmps2 & tmps3
    //tmps2 = tmps1 + x_inv_bins
    //tmps3 = tmps3[0] = one * tmps2[0], tmps3[1] = tmps3[0] * tmps2[1], y = tmps3.back()
    for (size_t i = 0; i < EXP_SIZE; i++)
    {
        if (i == 0) //tmps3 = tmps3[0] = one * tmps2[0]
            this->pb.val(tmps3[0]) = this->pb.lc_val(tmps1[0]) + this->pb.lc_val(x_inv_bins[0]);
        else //tmps3[1] = tmps3[0] * tmps2[1]...
            this->pb.val(tmps3[i]) = (this->pb.lc_val(tmps1[i]) + this->pb.lc_val(x_inv_bins[i])) * this->pb.lc_val(tmps3[i - 1]);
    }

    //y = tmps3.back()
    this->pb.val(y) = this->pb.lc_val(tmps3[EXP_SIZE - 1]);
}

