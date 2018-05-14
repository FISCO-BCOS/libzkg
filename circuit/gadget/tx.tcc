/*
 * @file: tx.tcc
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "note.tcc"

template <size_t NumInputs, size_t NumOutputs>
class TxGovInfo
{
  public:
    uint64_t vpub_old, vpub_new;
    boost::array<uint256, NumInputs> in_apks;
    boost::array<uint64_t, NumInputs> in_values;
    boost::array<uint256, NumOutputs> out_apks;
    boost::array<uint64_t, NumOutputs> out_values;
};

template <typename FieldT, size_t NumInputs, size_t NumOutputs>
class tx_gadget : public gadget<FieldT>
{
  private:
    //pi
    pb_variable_array<FieldT> zk_packed_inputs;

    //ai
    pb_variable_array<FieldT> zk_unpacked_inputs;
    boost::array<std::shared_ptr<digest_variable<FieldT>>, NumInputs> input_roots, input_sns;
    boost::array<std::shared_ptr<digest_variable<FieldT>>, NumOutputs> output_cms;
    pb_variable_array<FieldT> vpub_old, vpub_new;
    std::shared_ptr<digest_variable<FieldT>> g, //生成元
        Gpk,                                    //监管公钥
        G_data;                                 //监管密文

    pb_variable_array<FieldT> total_uint64;
    //gadget
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
    boost::array<std::shared_ptr<note_in_gadget<FieldT>>, NumInputs> input_note_gads;
    boost::array<std::shared_ptr<note_out_gadget<FieldT>>, NumOutputs> output_note_gads;
    std::shared_ptr<gov_gadget<FieldT>> gov_gad;

  public:
    tx_gadget(
        protoboard<FieldT> &pb) : gadget<FieldT>(pb)
    {
        //参考Zcash的压缩方法
        // The verification inputs are all bit-strings of various
        // lengths (256-bit digests and 64-bit integers) and so we
        // pack them into as few field elements as possible. (The
        // more verification inputs you have, the more expensive
        // verification is.)
        zk_packed_inputs.allocate(pb, verifying_field_element_size());
        pb.set_input_sizes(verifying_field_element_size());

        for (size_t i = 0; i < NumInputs; i++)
        {
            alloc_uint256(zk_unpacked_inputs, input_roots[i]);
            alloc_uint256(zk_unpacked_inputs, input_sns[i]);
        }

        for (size_t i = 0; i < NumOutputs; i++)
        {
            alloc_uint256(zk_unpacked_inputs, output_cms[i]);
        }

        alloc_uint64(zk_unpacked_inputs, vpub_old);
        alloc_uint64(zk_unpacked_inputs, vpub_new);

        alloc_uint256(zk_unpacked_inputs, g);
        alloc_uint256(zk_unpacked_inputs, Gpk);
        alloc_bits(zk_unpacked_inputs, G_data, gov_data_bit_size());

        assert(zk_unpacked_inputs.size() == verifying_input_bit_size());

        // This gadget will ensure that all of the inputs we provide are
        // boolean constrained.
        unpacker.reset(new multipacking_gadget<FieldT>(
            pb,
            zk_unpacked_inputs,
            zk_packed_inputs,
            FieldT::capacity(),
            "unpacker"));

        total_uint64.allocate(pb, 64);

        for (size_t i = 0; i < NumInputs; i++)
        {
            input_note_gads[i].reset(new note_in_gadget<FieldT>(
                pb,
                input_roots[i],
                input_sns[i]));
        }

        for (size_t i = 0; i < NumOutputs; i++)
        {
            output_note_gads[i].reset(new note_out_gadget<FieldT>(
                pb,
                output_cms[i]));
        }

        //gov_gadget的初始化一定要放在最后
        gov_gad.reset(new gov_gadget<FieldT>(
            pb,
            g,
            Gpk,
            G_data,
            get_gov_pb_variable()));
    }

    void generate_r1cs_constraints()
    {
        //TODO: 是否需要此初始化步骤
        for (size_t i = 0; i < NumInputs; i++)
        {
            input_roots[i]->generate_r1cs_constraints();
            input_sns[i]->generate_r1cs_constraints();
        }
        ///*
        for (size_t i = 0; i < NumOutputs; i++)
        {
            output_cms[i]->generate_r1cs_constraints();
        }

        //unpacker->generate_r1cs_constraints(true);
        ///*
        for (size_t i = 0; i < NumInputs; i++)
        {
            input_note_gads[i]->generate_r1cs_constraints();
            //input_sns[i]->generate_r1cs_constraints();
        }

        for (size_t i = 0; i < NumOutputs; i++)
        {
            output_note_gads[i]->generate_r1cs_constraints();
        }

        //value balance
        {
            linear_combination<FieldT> left_side = packed_addition(vpub_old);
            for (size_t i = 0; i < NumInputs; i++)
            {
                left_side = left_side + packed_addition(input_note_gads[i]->get_value_pb_variable());
            }

            linear_combination<FieldT> right_side = packed_addition(vpub_new);
            for (size_t i = 0; i < NumOutputs; i++)
            {
                right_side = right_side + packed_addition(output_note_gads[i]->get_value_pb_variable());
            }

            // Ensure that both sides are equal
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                1,
                left_side,
                right_side));

            // #854: Ensure that left_side is a 64-bit integer.
            for (size_t i = 0; i < 64; i++)
            {
                generate_boolean_r1cs_constraint<FieldT>(
                    this->pb,
                    total_uint64[i],
                    "");
            }

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                1,
                left_side,
                packed_addition(total_uint64)));
        }
        gov_gad->generate_r1cs_constraints();
        //*/
    }

    void generate_r1cs_witness(
        //计算得到的结果
        boost::array<uint256, NumInputs> &r_input_rts,
        boost::array<uint256, NumInputs> &r_input_sns,
        boost::array<uint256, NumOutputs> &r_output_cms,
        boost::array<uint256, NumOutputs> &r_output_rs,
        std::vector<bool> &r_G_data_v,
        //入参
        uint64_t vpub_old_64, //TODO: 考虑负数攻击
        uint64_t vpub_new_64,
        boost::array<std::shared_ptr<CMPool>, NumInputs> cm_pools,
        boost::array<uint256, NumInputs> input_asks_256,
        boost::array<uint256, NumInputs> input_rs_256,
        boost::array<uint64_t, NumInputs> input_vs_64,
        boost::array<uint256, NumOutputs> output_apks_256,
        boost::array<uint64_t, NumOutputs> output_vs_64,
        uint256 g_256,
        uint256 Gpk_256)
    {
        vpub_old.fill_with_bits(this->pb, uint64_to_bool_vector(vpub_old_64));
        vpub_new.fill_with_bits(this->pb, uint64_to_bool_vector(vpub_new_64));

        // Witness total_uint64 bits
        uint64_t left_side_acc = vpub_old_64;
        for (size_t i = 0; i < NumInputs; i++)
        {
            left_side_acc += input_vs_64[i];
        }

        total_uint64.fill_with_bits(this->pb, uint64_to_bool_vector(left_side_acc));

        for (size_t i = 0; i < NumInputs; i++)
        {
            input_note_gads[i]->generate_r1cs_witness(
                r_input_rts[i], r_input_sns[i],
                input_asks_256[i], input_vs_64[i], input_rs_256[i],
                cm_pools[i]);
        } //此步自动计算rt和sn并填入witness数组中

        for (size_t i = 0; i < NumOutputs; i++)
        {
            output_note_gads[i]->generate_r1cs_witness(
                r_output_cms[i], r_output_rs[i],
                output_vs_64[i], output_apks_256[i]);
        } //此步自动计算cm和r并填入witness数组中

        g->bits.fill_with_bits(this->pb, uint256_to_bool_vector(g_256));
        Gpk->bits.fill_with_bits(this->pb, uint256_to_bool_vector(Gpk_256));

        //计算监管密文
        gov_gad->generate_r1cs_witness(r_G_data_v);

        // This happens last, because only by now are all the
        // verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    static r1cs_primary_input<FieldT> witness_map(
        const boost::array<uint256, NumInputs> &input_rts,
        const boost::array<uint256, NumInputs> &input_sns,
        const boost::array<uint256, NumOutputs> &output_cms,
        uint64_t vpub_old_64,
        uint64_t vpub_new_64,
        uint256 g_256,
        uint256 Gpk_256,
        std::vector<bool> G_data_v)
    {
        std::vector<bool> verify_inputs;

        for (size_t i = 0; i < NumInputs; i++)
        {
            insert_uint256(verify_inputs, input_rts[i]);
            insert_uint256(verify_inputs, input_sns[i]);
        }

        for (size_t i = 0; i < NumOutputs; i++)
        {
            insert_uint256(verify_inputs, output_cms[i]);
        }

        insert_uint64(verify_inputs, vpub_old_64);
        insert_uint64(verify_inputs, vpub_new_64);

        insert_uint256(verify_inputs, g_256);
        insert_uint256(verify_inputs, Gpk_256);

        if (G_data_v.size() != gov_data_bit_size())
            throw ProveParamsLengthException();

        verify_inputs.insert(verify_inputs.end(), G_data_v.begin(), G_data_v.end());

        if (verify_inputs.size() != verifying_input_bit_size())
            throw ProveParamsLengthException();

        auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        if (verify_field_elements.size() != verifying_field_element_size())
            throw ProveParamsLengthException();

        return verify_field_elements;
    }

    static size_t verifying_input_bit_size()
    {
        size_t acc = 0;

        for (size_t i = 0; i < NumInputs; i++)
        {
            acc += 256; // the merkle root (anchor)
            acc += 256; // sn
        }
        for (size_t i = 0; i < NumOutputs; i++)
        {
            acc += 256; // new commitment
        }
        acc += 64; // vpub_old
        acc += 64; // vpub_new

        acc += 256; // g
        acc += 256; // Gpk
        acc += gov_data_bit_size();

        return acc;
    }

    static size_t verifying_field_element_size()
    {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    static size_t gov_data_bit_size()
    {
        size_t acc = 0; //明文大小
        //left side
        acc += 64; //vpub_old
        for (size_t i = 0; i < NumInputs; i++)
        {
            acc += 256; //in apk
            acc += 64;  //in value
        }
        //right side
        acc += 64; //vpub_new
        for (size_t i = 0; i < NumOutputs; i++)
        {
            acc += 256; //out apk
            acc += 64;  //out value
        }

        return gov_gadget<FieldT>::caculate_ciphertext_size(acc); //计算，返回密文大小
    }

    void alloc_uint256(
        pb_variable_array<FieldT> &packed_into,
        std::shared_ptr<digest_variable<FieldT>> &var)
    {
        var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }

    void alloc_uint64(
        pb_variable_array<FieldT> &packed_into,
        pb_variable_array<FieldT> &integer)
    {
        integer.allocate(this->pb, 64, "");
        packed_into.insert(packed_into.end(), integer.begin(), integer.end());
    }

    void alloc_bits(
        pb_variable_array<FieldT> &packed_into,
        std::shared_ptr<digest_variable<FieldT>> &bits,
        size_t size)
    {
        bits.reset(new digest_variable<FieldT>(this->pb, size, ""));
        packed_into.insert(packed_into.end(), bits->bits.begin(), bits->bits.end());
    }

    void check_witness(
        //计算得到的结果
        boost::array<uint256, NumInputs> r_input_rts,
        boost::array<uint256, NumInputs> r_input_sns,
        boost::array<uint256, NumOutputs> r_output_cms,
        boost::array<uint256, NumOutputs> r_output_rs,
        std::vector<bool> &r_G_data_v,
        //入参
        uint64_t vpub_old_64,
        uint64_t vpub_new_64,
        boost::array<std::shared_ptr<CMPool>, NumInputs> cm_pools,
        boost::array<uint256, NumInputs> input_asks_256,
        boost::array<uint256, NumInputs> input_rs_256,
        boost::array<uint64_t, NumInputs> input_vs_64,
        boost::array<uint256, NumOutputs> output_apks_256,
        boost::array<uint64_t, NumOutputs> output_vs_64,
        uint256 g_256,
        uint256 Gpk_256)
    {
        LOG(DEBUG) << "Check prepared: " << (this->pb.is_satisfied() ? "True" : "False!") << endl;

        LOG(DEBUG) << "---------- Check transaction value ----------" << endl;
        uint64_t left_side_acc = vpub_old_64;
        for (size_t i = 0; i < NumInputs; i++)
        {
            left_side_acc += input_vs_64[i];
        }
        LOG(DEBUG) << "left_side_value: " << left_side_acc << endl;

        uint64_t right_side_acc = vpub_new_64;
        for (size_t i = 0; i < NumOutputs; i++)
        {
            right_side_acc += output_vs_64[i];
        }
        LOG(DEBUG) << "right_side_value: " << right_side_acc << endl;
        LOG(DEBUG) << "Check value balance: " << ((left_side_acc == right_side_acc) ? "Verified" : "Failed!") << endl;
        //LOG(DEBUG) << "Check value balance witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;

        total_uint64.fill_with_bits(this->pb, uint64_to_bool_vector(left_side_acc));
        LOG(DEBUG) << "Check left_side is a 64-bit integer witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;

        for (size_t i = 0; i < NumInputs; i++)
        {
            LOG(DEBUG) << "---------- Check input[" << i << "] ----------" << endl;
            input_note_gads[i]->check_witness(
                r_input_rts[i], r_input_sns[i],
                input_asks_256[i], input_vs_64[i], input_rs_256[i]);
        }

        for (size_t i = 0; i < NumOutputs; i++)
        {
            LOG(DEBUG) << "---------- Check output[" << i << "] ----------" << endl;
            output_note_gads[i]->check_witness(
                r_output_cms[i], r_output_rs[i]);
        }

        gov_gad->check_witness(g_256, Gpk_256, r_G_data_v);
    }

    std::vector<pb_variable_array<FieldT>> get_gov_pb_variable()
    {
        std::vector<pb_variable_array<FieldT>> datas;
        //left side
        datas.push_back(vpub_old);
        for (size_t i = 0; i < NumInputs; i++)
        {
            datas.push_back(input_note_gads[i]->get_apk_pb_variable());
            datas.push_back(input_note_gads[i]->get_value_pb_variable());
        }
        //right side
        datas.push_back(vpub_new);
        for (size_t i = 0; i < NumOutputs; i++)
        {
            datas.push_back(output_note_gads[i]->get_apk_pb_variable());
            datas.push_back(output_note_gads[i]->get_value_pb_variable());
        }
        return datas;
    }

    static TxGovInfo<NumInputs, NumOutputs> decrypt_tx_gov_info(uint256 Gsk_256, vector<bool> G_data_v)
    {
        //Gsk_256->FieldT Gsk
        FieldT Gsk = uint256_to_fp<FieldT>(Gsk_256);
        vector<bool> plaintext = ELGamal<FieldT>::decrypt(G_data_v, Gsk);

        TxGovInfo<NumInputs, NumOutputs> info;
        size_t offset = 0;
        info.vpub_old = ELGamal<FieldT>::decode_uint64(plaintext, offset);
        offset += 64;

        for (size_t i = 0; i < NumInputs; i++)
        {
            info.in_apks[i] = ELGamal<FieldT>::decode_uint256(plaintext, offset);
            offset += 256;

            info.in_values[i] = ELGamal<FieldT>::decode_uint64(plaintext, offset);
            offset += 64;
        }

        info.vpub_new = ELGamal<FieldT>::decode_uint64(plaintext, offset);
        offset += 64;

        for (size_t i = 0; i < NumOutputs; i++)
        {
            info.out_apks[i] = ELGamal<FieldT>::decode_uint256(plaintext, offset);
            offset += 256;

            info.out_values[i] = ELGamal<FieldT>::decode_uint64(plaintext, offset);
            offset += 64;
        }

        return info;
    }
};