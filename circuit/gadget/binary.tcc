/*
 * @file: binary.tcc
 * @author: Andrew G. Ma, jimmyshi
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "field.h"
#include "convert.hpp"

template <typename FieldT>
class binary_gadget : public packing_gadget<FieldT>
{
  private:
    pb_variable_array<FieldT> temp1;
    pb_variable_array<FieldT> temp2;
    FieldT g;

  public:
    const pb_linear_combination_array<FieldT> A;
    const pb_variable<FieldT> result;

    binary_gadget(protoboard<FieldT> &pb,
                  const pb_linear_combination_array<FieldT> &A, //y
                  const pb_variable<FieldT> &result,
                  const std::string &annotation_prefix = "") : packing_gadget<FieldT>(pb, A, result, annotation_prefix){};

    void generate_r1cs_constraints()
    {
        packing_gadget<FieldT>::generate_r1cs_constraints(true); //That's why binary gadget
    }

    void generate_r1cs_witness(bool is_binary_to_packed = true)
    {
        //若为false，可支持已知result反推A二进制数组
        if (!is_binary_to_packed)
            packing_gadget<FieldT>::generate_r1cs_witness_from_packed();
        else
            packing_gadget<FieldT>::generate_r1cs_witness_from_bits();
    }
};