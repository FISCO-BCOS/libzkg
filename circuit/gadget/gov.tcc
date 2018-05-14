/*
 * @file: gov.tcc
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include "elgamal.tcc"

template <typename FieldT>
class gov_gadget : public gadget<FieldT>
{
  private:
    //pi
    std::shared_ptr<digest_variable<FieldT>> p_g, p_Gpk, p_ciphertext;

    //ai shared
    //datas_in_bits

    //ai local
    std::shared_ptr<digest_variable<FieldT>> p_plaintext;

    //gadget
    std::shared_ptr<elgamal_plaintext_gadget<FieldT>> m_gad;
    std::shared_ptr<elgamal_gadget<FieldT>> elg_gad;

    //other data
    vector<bool> ciphertex, plaintext;

  public:
    gov_gadget(
        protoboard<FieldT> &pb,
        std::shared_ptr<digest_variable<FieldT>> p_g,
        std::shared_ptr<digest_variable<FieldT>> p_Gpk,
        std::shared_ptr<digest_variable<FieldT>> p_ciphertext,
        std::vector<pb_variable_array<FieldT>> datas_in_bits) : gadget<FieldT>(pb), p_g(p_g), p_Gpk(p_Gpk)
    {
        p_plaintext.reset(new digest_variable<FieldT>(pb, 0, "")); // 在elgamal_plaintext_gadget中映射
        m_gad.reset(new elgamal_plaintext_gadget<FieldT>(
            pb,
            p_plaintext));

        for (auto data_in_bits : datas_in_bits)
            m_gad->plaintext_append(data_in_bits);

        m_gad->fill_back();

        elg_gad.reset(new elgamal_gadget<FieldT>(
            pb,
            p_g,
            p_Gpk,
            p_ciphertext,
            p_plaintext));
    }

    void generate_r1cs_constraints()
    {
        m_gad->generate_r1cs_constraints();
        elg_gad->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        vector<bool> &r_G_data //计算得到的监管密文
    )
    {
        m_gad->generate_r1cs_witness();
        this->plaintext = p_plaintext->get_digest();

        elg_gad->generate_r1cs_witness(r_G_data);
        this->ciphertex = r_G_data;
    }

    void check_witness()
    {
        LOG(DEBUG) << "Check gov witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;
    }

    static size_t caculate_ciphertext_size(const size_t plaintext_size)
    {
        return elgamal_gadget<FieldT>::caculate_ciphertext_size(plaintext_size);
    }

    void check_witness(uint256 g_256, uint256 Gpk_256, vector<bool> _ciphertext)
    {
        elg_gad->check_witness(_ciphertext, g_256, Gpk_256, plaintext);
    }
};