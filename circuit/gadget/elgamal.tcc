/*
 * @file: elgamal.tcc
 * @author: Andrew G. Ma, jimmyshi
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include <string>
#include <vector>
#include "exp.tcc"
#include "util/uint256.h"
#include "field.h"
#include "convert.hpp"

//-----------Elgamal加密解密及其证明部分-----------------------------

//ELGamal calulator
template <typename FieldT>
class ELGamal
{
    /*
    ELGamal 算法 
    （1）定义
        生成元 g
        公钥  Gpk
        私钥  Gsk
        随机数 y
        明文  m
        密文  c = (c1, c2)
    （2）公私钥生成
        Gpk = g ^ Gsk
    （3）加密
        c1 = g ^ y
        c2 = m * (Gpk ^ y)
    （4）解密
        m = c2 / (c1 ^ Gsk)
*/

    /*
    zkg中ELGamal的加解密协议
        明文格式：将明文m以248bit分割进行加密,加密bit长度不能超过253，这是FieldT决定的
            m = [m0, m1, m2 ...] 不足的后面补0
            bit  248 248 248 ...        248 bit = 31 bytes

        密文格式：c1是唯一的，在开头，c2有多个，依次排列在后
            c = [c1, c21, c22, c32 ... ]
            bit  256 256  256  256  bits = 32 bytes

        明文密文对应关系：
            m = [    m0,  m1,  m2 ...]
                     |    |    |
            c = [c1, c21, c22, c32 ... ]
*/
  public:
//生成元
#define DEFAULT_G_STR "39061f1c854fae629b599d29cefe1f12bc4809aa681809bfaaeb1b7087be6fed"

    static const size_t M_BOX_BYTE_SIZE = 31; //248 = 31 * 8
    static const size_t C1_BOX_BYTE_SIZE = 32;
    static const size_t C2_BOX_BYTE_SIZE = 32;
    static const size_t C_BOX_BYTE_SIZE = C1_BOX_BYTE_SIZE + C2_BOX_BYTE_SIZE;

    static const size_t M_BOX_BIT_SIZE = M_BOX_BYTE_SIZE * 8; //248 = 31 * 8
    static const size_t C1_BOX_BIT_SIZE = C1_BOX_BYTE_SIZE * 8;
    static const size_t C2_BOX_BIT_SIZE = C2_BOX_BYTE_SIZE * 8;
    static const size_t C_BOX_BIT_SIZE = C1_BOX_BIT_SIZE + C2_BOX_BIT_SIZE;

  public:
    static FieldT g_generator(string g_str = string(DEFAULT_G_STR))
    {
        FieldT g = hex_str_to_fr(g_str);
        return g;
    }

    static FieldT pk_generator(FieldT sk, FieldT g)
    {
        FieldT pk = g ^ sk.as_bigint();
        return pk;
    }

    static string pk_generator(string sk_str, string g_str = string(DEFAULT_G_STR))
    {
        FieldT g = hex_str_to_fr(g_str);
        FieldT sk = hex_str_to_fr(sk_str);
        FieldT pk = pk_generator(sk, g);

        return fr_to_hex_string(pk);
    }

    static vector<bool> encrypt(
        vector<bool> m_bits, string Gpk_hex_str, FieldT y = FieldT::random_element(), string g_str = string(DEFAULT_G_STR))
    {
        //TODO assert Gpk y 是否合法，长度不能超过253bit
        FieldT Gpk, g;
        g = hex_str_to_fr(g_str);
        Gpk = hex_str_to_fr(Gpk_hex_str);
        return encrypt(m_bits, Gpk, y, g);
    }

    static vector<bool> encrypt(
        vector<bool> m_bits, FieldT Gpk, FieldT y, FieldT g)
    {

        vector<uint8_t> result;

        //生成随机数r和c1
        FieldT c1 = g ^ y.as_bigint();

        //c1写入开头
        unsigned char c1_char[C1_BOX_BYTE_SIZE];
        fp_to_byte<FieldT>(c1, c1_char);
        for (int i = 0; i < C1_BOX_BYTE_SIZE; i++)
            result.emplace_back(swap_endianness<unsigned char>(c1_char[i])); //为了与gadget一致，密文需要改变endianness来存

        size_t m_size = m_bits.size();
        for (size_t m_pos = 0; m_pos < m_size; m_pos += M_BOX_BIT_SIZE)
        {
            //建一个tmp数组存放31字节数据
            unsigned char m_char[M_BOX_BYTE_SIZE + 1];
            for (int i = 0; i < M_BOX_BYTE_SIZE; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    m_char[i] <<= 1;
                    m_char[i] |= (m_pos + i * 8 + j < m_size ? m_bits[m_pos + i * 8 + j] : 0); //不足补0
                }
                m_char[i] = swap_endianness<unsigned char>(m_char[i]);
            }
            m_char[31] = 0;

            FieldT m = byte_to_fp<FieldT>(m_char);

            //加密
            FieldT c2 = m * (Gpk ^ y.as_bigint());

            //写到结果中
            unsigned char c2_char[C2_BOX_BYTE_SIZE];
            fp_to_byte<FieldT>(c2, c2_char);

            for (int i = 0; i < C2_BOX_BYTE_SIZE; i++)
                result.emplace_back(swap_endianness<unsigned char>(c2_char[i])); //为了与gadget一致，密文需要改变endianness来存
            LOG(DEBUG) << "t result size:" << result.size() << endl;
        }

        return convertBytesVectorToVector(result);
    }

    static vector<bool> decrypt(vector<bool> c_str_bool, string Gsk_hex_str)
    {
        //TODO assert Gsk 是否合法，长度不能超过253bit
        FieldT g, Gsk;
        Gsk = hex_str_to_fr(Gsk_hex_str);
        return decrypt(c_str_bool, Gsk);
    }

    static vector<bool> decrypt(vector<bool> c_str_bool, FieldT Gsk)
    {
        vector<uint8_t> c_str = convertBoolVectorToBytesVector(c_str_bool);

        //检查密文是否合法（除掉C1 Box之后，长度满足为C2 Box整数倍）
        assert(c_str.size() > C1_BOX_BYTE_SIZE);
        assert((c_str.size() - C1_BOX_BYTE_SIZE) % C2_BOX_BYTE_SIZE == 0);

        vector<bool> result;

        unsigned char c1_char[C1_BOX_BYTE_SIZE];
        for (int i = 0; i < C1_BOX_BYTE_SIZE; i++)
            c1_char[i] = swap_endianness<unsigned char>(c_str[i]);
        FieldT c1 = byte_to_fp<FieldT>(c1_char);

        size_t c_size = c_str.size();
        for (size_t c_pos = C1_BOX_BYTE_SIZE; c_pos < c_size; c_pos += C2_BOX_BYTE_SIZE)
        {
            //建temp存放c1 c2
            unsigned char c2_char[C2_BOX_BYTE_SIZE];
            for (int i = 0; i < C2_BOX_BYTE_SIZE; i++)
                c2_char[i] = swap_endianness<unsigned char>(c_str[c_pos + i]);

            FieldT c2 = byte_to_fp<FieldT>(c2_char);

            //解密
            FieldT s = c1 ^ Gsk.as_bigint(),
                   m = c2 * s.inverse();

            unsigned char m_char[32];
            fp_to_byte(m, m_char);

            //转换成M_BOX大小写回
            for (int i = 0; i < M_BOX_BYTE_SIZE; i++)
                for (int j = 0; j < 8; j++)
                {
                    result.push_back((m_char[i] >> j) & 0x1);
                }
        }
        return result;
    }

  private:
    static string fr_to_hex_string(FieldT x)
    {
        uint256 x_256 = fp_to_uint256<FieldT>(x);
        return x_256.GetHex();
    }

    static FieldT hex_str_to_fr(const string &str)
    {
        return uint256_to_fp<FieldT>(uint256S(str));
    }

  public:
    static vector<bool> encode_uint256(vector<bool> &m_bits, uint256 x_256)
    {
        vector<bool> vec = uint256_to_bool_vector(x_256);
        m_bits.insert(m_bits.end(), vec.begin(), vec.end());
        return m_bits;
    }

    static vector<bool> encode_uint64(vector<bool> &m_bits, uint64_t x_64)
    {
        vector<bool> vec = uint64_to_bool_vector(x_64);
        m_bits.insert(m_bits.end(), vec.begin(), vec.end());
        return m_bits;
    }

    static uint256 decode_uint256(vector<bool> m_bits, int offset)
    {
        assert(m_bits.size() >= (offset + 256));
        vector<bool> sub(m_bits.begin() + offset, m_bits.begin() + offset + 256);
        return uint256(convertBoolVectorToBytesVector(sub));
    }

    static uint64_t decode_uint64(vector<bool> m_bits, int offset)
    {
        assert(m_bits.size() >= (offset + 64));
        vector<bool> sub(m_bits.begin() + offset, m_bits.begin() + offset + 64);

        uint64_t ret = 0;
        for (int i = 7; i >= 0; i--)
            for (int j = 0; j < 8; j++)
            {
                ret <<= 1;
                ret |= sub[i * 8 + j];
            }
        return ret;
    }

    static vector<bool> fill_back(vector<bool> m_bits)
    { //在明文后面补0，保证是248的倍数
        size_t back_num = M_BOX_BIT_SIZE - (m_bits.size() % M_BOX_BIT_SIZE);
        for (size_t i = 0; i < back_num; i++)
            m_bits.push_back(false);
        return m_bits;
    }

    static size_t caculate_ciphertext_size(const size_t plaintext_size)
    {
        size_t r = C1_BOX_BIT_SIZE;
        size_t box_num = (plaintext_size + M_BOX_BIT_SIZE - 1) / M_BOX_BIT_SIZE; //div_ceil
        r += box_num * C2_BOX_BIT_SIZE;
        return r;
    }
};

template <typename FieldT>
class elgamal_plaintext_gadget : public gadget<FieldT>
{
    //将需要加密的离散二进制数组明文数据，拼接成一个二进制数组，并按照248字节为单位，不足则补位
    static const size_t M_BOX_BIT_SIZE = ELGamal<FieldT>::M_BOX_BIT_SIZE;

  public:
    std::shared_ptr<digest_variable<FieldT>> plaintext_p;
    pb_variable_array<FieldT> plaintext_fill_back; //补位数组

    elgamal_plaintext_gadget(
        protoboard<FieldT> &pb,
        std::shared_ptr<digest_variable<FieldT>> plaintext_p) : gadget<FieldT>(pb), plaintext_p(plaintext_p) {}

    void generate_r1cs_constraints()
    {
        if (is_need_fill_back())
            fill_back();
        for (size_t i = 0; i < plaintext_fill_back.size(); i++)
        {
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                plaintext_fill_back[i],
                "boolean_value");
        }
    }

    void generate_r1cs_witness()
    {
        //do nothing
    }

    void plaintext_append(pb_variable_array<FieldT> &var)
    {
        plaintext_p->bits.insert(plaintext_p->bits.end(), var.begin(), var.end());
    }

    bool is_need_fill_back()
    {
        return (plaintext_p->bits.size() % M_BOX_BIT_SIZE != 0);
    }

    static bool is_need_fill_back(size_t plaintext_bit_size)
    {
        return (plaintext_bit_size % M_BOX_BIT_SIZE != 0);
    }

    void fill_back()
    {
        if (is_need_fill_back())
        {
            size_t back_size = M_BOX_BIT_SIZE - (plaintext_p->bits.size() % M_BOX_BIT_SIZE);
            plaintext_fill_back.allocate(this->pb, back_size, "");
            plaintext_p->bits.insert(plaintext_p->bits.end(), plaintext_fill_back.begin(), plaintext_fill_back.end());
        }
    }
};

template <typename FieldT>
class elgamal_gadget : public gadget<FieldT>
{
    //每个加密box
    /*
        明文bits：ciphertext 密文bits：ciphertext 加密电路如下：

        ciphertext           [..........................][00] <- fill back
        m_boxs               [ 248bit ] [ 248bit ] [ 248bit ]
        ms                     FieldT     FieldT     FieldT
                                 |          |          |
        E()         c1 = g^y   -------c2 = m*(Gpk^y)-------
                       |         |          |          |
        c1           FieldT      |          |          |           
        c2             |       FieldT     FieldT     FieldT
        c1_box     [ 256bit ]    |          |          |
        c2_boxs        |     [ 256bit ] [ 256bit ] [ 256bit ]
        ciphertext [........................................]
    */

  private:
    //pi
    std::shared_ptr<digest_variable<FieldT>> g_p, Gpk_p, ciphertext_p;
    //ai shared
    std::shared_ptr<digest_variable<FieldT>> plaintext_p;
    //ai local
    pb_variable<FieldT> g, Gpk, c1;
    pb_variable_array<FieldT> ms, c2s;

    //中间变量
    pb_variable<FieldT> Gpk_exp_y, y;
    pb_variable_array<FieldT> c1_box;
    std::vector<pb_variable_array<FieldT>> m_boxs, c2_boxs;

    //gadgets
    //exp_gadget
    std::shared_ptr<exp_gadget<FieldT>> g_exp_y_gad, Gpk_exp_y_gad;

    //binary_gadget
    std::shared_ptr<binary_gadget<FieldT>> Gpk_binary_gad, g_binary_gad, c1_binary_gad;
    std::vector<std::shared_ptr<binary_gadget<FieldT>>> m_binary_gads, c2_binary_gads;

    //elgamal_plaintext_gadget
    std::shared_ptr<elgamal_plaintext_gadget<FieldT>> m_gad; //补位的时候才需要

    //加密协议，BOX大小与ELGamal统一起来
    size_t box_num;
    static const size_t M_BOX_BIT_SIZE = ELGamal<FieldT>::M_BOX_BIT_SIZE;
    static const size_t C1_BOX_BIT_SIZE = ELGamal<FieldT>::C1_BOX_BIT_SIZE;
    static const size_t C2_BOX_BIT_SIZE = ELGamal<FieldT>::C2_BOX_BIT_SIZE;
    static const size_t C_BOX_BIT_SIZE = ELGamal<FieldT>::C_BOX_BIT_SIZE;

  public:
    elgamal_gadget(
        protoboard<FieldT> &pb,
        std::shared_ptr<digest_variable<FieldT>> g_p,
        std::shared_ptr<digest_variable<FieldT>> Gpk_p,
        std::shared_ptr<digest_variable<FieldT>> ciphertext_p,
        std::shared_ptr<digest_variable<FieldT>> plaintext_p) : gadget<FieldT>(pb), g_p(g_p), Gpk_p(Gpk_p), ciphertext_p(ciphertext_p), plaintext_p(plaintext_p)
    {

        //进一步确认明文是否满足248的整数倍，若不是，则补位
        m_gad = std::make_shared<elgamal_plaintext_gadget<FieldT>>(pb, plaintext_p);
        m_gad->fill_back();

        //ciphertext_p是pi，应在外部开好空间，所以此处有个约定，根据plaintext_p需要实现确定好ciphertext_p的大小
        //开空间公式：ciphertext_p->bits.allocate(pb, C1_BOX_BIT_SIZE + C2_BOX_BIT_SIZE * box_num);//ciphertext开空间

        //C1 相关
        {
            //c1 = g^y
            g.allocate(pb);
            c1.allocate(pb);
            y.allocate(pb);
            g_binary_gad = std::make_shared<binary_gadget<FieldT>>(
                pb,
                g_p->bits,
                g);
            g_exp_y_gad = std::make_shared<exp_gadget<FieldT>>(
                pb,
                g,
                y,
                c1);

            //c1 -> c1_box -> ciphertext_p开头256字节
            c1_box.insert(c1_box.begin(), ciphertext_p->bits.begin(), ciphertext_p->bits.begin() + C1_BOX_BIT_SIZE);
            c1_binary_gad = std::make_shared<binary_gadget<FieldT>>(
                pb,
                c1_box,
                c1);
        }

        //Box相关（C2）
        {
            //加密Box 个数
            assert((plaintext_p->bits.size() % M_BOX_BIT_SIZE) == 0);
            box_num = plaintext_p->bits.size() / M_BOX_BIT_SIZE;

            //创建box中的元素
            ms.allocate(pb, box_num);
            c2s.allocate(pb, box_num);

            //plaintext -> m_boxs -> m
            for (size_t i = 0; i < box_num; i++)
            {
                m_boxs.emplace_back(
                    plaintext_p->bits.begin() + i * M_BOX_BIT_SIZE,
                    plaintext_p->bits.begin() + (i + 1) * M_BOX_BIT_SIZE); //pb_variable_array<FieldT>

                m_binary_gads.emplace_back(new binary_gadget<FieldT>(
                    pb,
                    m_boxs[i],
                    ms[i]));
            }

            //Gpk_exp_y = Gpk^y
            Gpk.allocate(pb);
            Gpk_binary_gad = std::make_shared<binary_gadget<FieldT>>(
                pb,
                Gpk_p->bits,
                Gpk);

            Gpk_exp_y.allocate(pb);
            Gpk_exp_y_gad = std::make_shared<exp_gadget<FieldT>>(
                pb,
                Gpk,
                y,
                Gpk_exp_y);

            //c2 = m*(Gpk^y)
            for (size_t i = 0; i < box_num; i++)
            {
                //do nothing 下面直接构造约束, 此处没有用gadget封装，不需要初始化
            }

            //c2 -> c2_box -> ciphertext后面字段
            for (size_t i = 0; i < box_num; i++)
            {
                c2_boxs.emplace_back(
                    ciphertext_p->bits.begin() + C1_BOX_BIT_SIZE + i * C2_BOX_BIT_SIZE,
                    ciphertext_p->bits.begin() + C1_BOX_BIT_SIZE + (i + 1) * C2_BOX_BIT_SIZE);

                c2_binary_gads.emplace_back(new binary_gadget<FieldT>(
                    pb,
                    c2_boxs[i],
                    c2s[i]));
            }
        }
    }

    void generate_r1cs_constraints()
    {
        m_gad->generate_r1cs_constraints();

        //C1相关
        {
            g_binary_gad->generate_r1cs_constraints();
            g_exp_y_gad->generate_r1cs_constraints();
            c1_binary_gad->generate_r1cs_constraints();
        }

        //Box相关（C2）
        {
            //plaintext -> m_boxs -> m
            for (size_t i = 0; i < box_num; i++)
            {
                m_binary_gads[i]->generate_r1cs_constraints();
                ;
            }

            //Gpk_exp_y = Gpk^y
            Gpk_binary_gad->generate_r1cs_constraints();
            Gpk_exp_y_gad->generate_r1cs_constraints();

            //c2 = m*(Gpk^y)
            for (size_t i = 0; i < box_num; i++)
            {
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(ms[i], Gpk_exp_y, c2s[i]), FMT(" S_%zu"));
            }

            //c2 -> c2_box -> ciphertext后面字段
            for (size_t i = 0; i < box_num; i++)
            {
                //c2_binary_gads[i]->generate_r1cs_constraints();
            }
            //*/
        }
    }

    void generate_r1cs_witness(vector<bool> &r_ciphertex)
    {

        //随机y，只在此处出现，之后丢弃
        FieldT fy = FieldT::random_element();

        //C1相关
        {
            this->pb.val(y) = fy; //填入y

            //print y
            //this->pb.val(y).print();

            g_binary_gad->generate_r1cs_witness(); //得到g
            g_exp_y_gad->generate_r1cs_witness();  //得到c1

            //c1 -> c1_box -> ciphertext_p开头256字节
            c1_binary_gad->generate_r1cs_witness(false); //填入ciphertext的开头字段
            //*/
        }

        //Box相关（C2）
        {
            //plaintext -> m_boxs -> m
            for (size_t i = 0; i < box_num; i++)
            {
                m_binary_gads[i]->generate_r1cs_witness(); //得到m
            }

            //Gpk_exp_y = g^Gpk
            Gpk_binary_gad->generate_r1cs_witness(); //得到Gpk

            Gpk_exp_y_gad->generate_r1cs_witness(); //得到Gpk_exp_y

            for (size_t i = 0; i < box_num; i++)
            {
                this->pb.val(c2s[i]) = this->pb.lc_val(ms[i]) * this->pb.lc_val(Gpk_exp_y);
            }

            //c2 -> c2_box -> ciphertext后面字段
            for (size_t i = 0; i < box_num; i++)
            {
                c2_binary_gads[i]->generate_r1cs_witness(false);
            }
            //*/
        }

        r_ciphertex = ciphertext_p->get_digest();
        //check_witness(ciphertex, g_str, Gpk_str, plaintext);
    }

    void check_witness(vector<bool> &ciphertex,
                       uint256 g_256, uint256 Gpk_256,
                       vector<bool> plaintext)
    {

        LOG(DEBUG) << "----------elgamal check witness----------" << endl;
        LOG(DEBUG) << "Check prepared: " << (this->pb.is_satisfied() ? "True" : "False!") << endl;

        LOG(DEBUG) << "plaintext: ";
        print_vector<bool>(plaintext);
        LOG(DEBUG) << endl;
        plaintext_p->bits.fill_with_bits(this->pb, plaintext);
        LOG(DEBUG) << "Check plaintext_p witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;

        LOG(DEBUG) << "g: " << g_256.GetHex() << endl;
        g_p->bits.fill_with_bits(this->pb, uint256_to_bool_vector(g_256));
        LOG(DEBUG) << "Check g witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;

        LOG(DEBUG) << "Gpk: " << Gpk_256.GetHex() << endl;
        Gpk_p->bits.fill_with_bits(this->pb, uint256_to_bool_vector(Gpk_256));
        LOG(DEBUG) << "Check Gpk witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;

        LOG(DEBUG) << "ciphertext: ";
        print_vector<bool>(ciphertex);
        LOG(DEBUG) << endl;
        ciphertext_p->bits.fill_with_bits(this->pb, ciphertex);
        LOG(DEBUG) << "Check ciphertext_p witness: " << (this->pb.is_satisfied() ? "Verified" : "Failed!") << endl;
    }

    static size_t caculate_ciphertext_size(const size_t plaintext_size)
    {
        return ELGamal<FieldT>::caculate_ciphertext_size(plaintext_size);
    }
};
