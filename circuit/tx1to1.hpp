/*
 * @file: tx1to1.hpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include <ctime>
#include "libff/common/default_types/ec_pp.hpp"
#include "libff/common/profiling.hpp"
#include "libff/common/utils.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

#include "util/sha256.h"
#include "util/uint256.h"
#include "util/util.h"
#include "util/IncrementalMerkleTree.hpp"
#include "util/fileoperation.hpp"
#include "util/utilstrencodings.h"
#include "util/zkglog.h"

#include <iostream>
#include <sys/time.h>
#include <fstream>

#include "gadget/gadget.hpp"

#include "cm_pool.hpp"
#include "zkgexception.hpp"

namespace zkg
{

class Tx1To1Data
{
  private:
    static const int PROOF_IN_BASE64_SIZE = 408; //hard code for tx1to1 senario
    static const int GDATA_IN_BASE64_SIZE = 300; //hard code for tx1to1 senario

  public:
    //pi
    boost::array<uint256, 2> s_rts, s_sns, r_cms;
    uint64_t vpub_old, vpub_new;
    uint256 g, Gpk;

    //proof
    string proof; //Base64
    //Gov data
    string G_data; //Base64

    //secrect data
    uint64_t v_to_payee, v_change;
    uint256 v_to_payee_r, v_change_r;

    //Base64 编码
    void set_proof(const string &str)
    {
        proof = EncodeBase64(str);
        LOG(INFO) << "proof in base64 size: " << proof.length() << endl; 
    }

    void set_G_data(const vector<bool> bits)
    {
        vector<unsigned char> bytes = convertBoolVectorToBytesVector(bits);
        G_data = EncodeBase64((unsigned char *)&(bytes[0]), bytes.size());
        LOG(INFO) << "G_data in base64 size: " << G_data.length() << endl; 
    }

    string get_proof()
    {
        LOG(DEBUG) << "get_proof size: " <<proof.length() << endl;
        if (proof.length() != PROOF_IN_BASE64_SIZE)
            throw ProofLengthException();
        if (!IsBase64String(proof))
            throw NotBase64StringException();
        string res = DecodeBase64(proof);
        return res;
    }

    vector<bool> get_G_data()
    {
        LOG(DEBUG) << "get_G_data size: " <<G_data.length() << endl;

        if (G_data.length() != GDATA_IN_BASE64_SIZE)
            throw GDataLengthException();
        if (!IsBase64String(G_data))
            throw NotBase64StringException();

        vector<unsigned char> bytes = DecodeBase64(G_data.c_str());
        return convertBytesVectorToVector(bytes);
    }
};

class Tx1To1
{
    /*
    hide tx：1 to 1， from S -> R   
                          ______
    S ---  vpub_old  --->|      |--- vpub_new---> R
                         |      |
    S ---s_cm0, s_sn0--->|  Tx  |---  r_cm0  ---> R
                         |      |
    S ---s_cm1, s_sn1--->|______|---  r_cm1  ---> S (change)
                            ||
                            \/ 
                          G_data
*/
    using FieldT = ppT::Fp_type;

  public:
    bool is_pk_loaded, is_vk_loaded;
    string pk_file, vk_file;
    r1cs_ppzksnark_proving_key<ppT> pk;
    r1cs_ppzksnark_verification_key<ppT> vk;

    Tx1To1(
        bool is_preload_pk = false,
        bool is_preload_vk = false,
        const string &pk_file = "pk.data",
        const string &vk_file = "vk.data") : pk_file(pk_file), vk_file(vk_file)
    {
        setup();
        if (is_preload_pk && !is_pk_loaded)
        {
            LOG(INFO) << "PK loading..." << endl;
            loadFromFile(pk_file, pk);
            is_pk_loaded = true;
            LOG(INFO) << "PK loaded" << endl;
        }

        if (is_preload_vk && !is_vk_loaded)
        {
            LOG(INFO) << "VK loading..." << endl;
            loadFromFile(vk_file, vk);
            is_vk_loaded = true;
            LOG(INFO) << "VK loaded" << endl;
        }
    }

    ~Tx1To1() {}

    static void setup()
    {
        ppT::init_public_params();
        if (zkg_log_verbosity & ZKG_LOG_ALL)
        {
            //if the flag is set, output all libsnark's running message
            libff::inhibit_profiling_info = false;
            libff::inhibit_profiling_counters = false;
        }
    }

    static void generate(string pk_file, string vk_file)
    {
        setup();
        LOG(INFO) << "PK VK generating..." << endl;
        protoboard<FieldT> pb;
        tx_gadget<FieldT, 2, 2> tx_gad(pb);

        tx_gad.generate_r1cs_constraints();
        auto cs = pb.get_constraint_system();
        auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

        //Write PK VK to disk
        saveToFile(pk_file, keypair.pk);
        LOG(INFO) << "PK generated" << endl;

        saveToFile(vk_file, keypair.vk);
        LOG(INFO) << "VK generated" << endl;
    }

    Tx1To1Data prove(
        std::shared_ptr<CMPool> cm_pool,
        //seft side
        uint256 s_ask,
        uint64_t vpub_old_64,
        boost::array<uint64_t, 2> s_vs, boost::array<uint256, 2> s_rs,
        boost::array<bool, 2> is_zero_cms,
        //right side
        uint256 r_apk,
        uint64_t vpub_new_64, uint64_t r_v,
        //gov param
        uint256 g_256, uint256 Gpk_256)
    {
        //setup();
        //gadget定义
        LOG(TRACE) << "Generate tx1to1 gadget" << endl;
        protoboard<FieldT> pb;
        tx_gadget<FieldT, 2, 2> tx_gad(pb);

        LOG(TRACE) << "Generate constraints" << endl;
        tx_gad.generate_r1cs_constraints();

        //入参
        LOG(TRACE) << "Prepare/Check witness parameters" << endl;
        boost::array<std::shared_ptr<CMPool>, 2> cm_pools;
        boost::array<uint256, 2> input_asks_256, input_rs_256, output_apks_256;
        boost::array<uint64_t, 2> input_vs_64, output_vs_64;
        //交易数据，计算得到
        boost::array<uint256, 2> r_input_rts, r_input_sns, r_output_cms, r_output_rs;
        std::vector<bool> r_G_data_v;

        //cm_pool
        cm_pools[0] = cm_pool;
        cm_pools[1] = cm_pool;

        //S->
        for (size_t i = 0; i < 2; i++)
        {
            if (is_zero_cms[i])
            {
                //0承诺赋值
                input_asks_256[i] = uint256S("0");
                input_vs_64[i] = s_vs[i] = 0;
                input_rs_256[i] = s_rs[i] = uint256S("0");
                //ZERO_CM = "ed6dd816927506bf94f63865d5792bfca5a1a14237494b74367e143df2caf7c6"
            }
            else
            {
                input_asks_256[i] = s_ask;
                input_vs_64[i] = s_vs[i];
                input_rs_256[i] = s_rs[i];
            }
        }

        //->R
        output_apks_256[0] = r_apk;
        output_vs_64[0] = r_v;

        //->S 找零
        uint64_t v_back_to_s = vpub_old_64 + s_vs[0] + s_vs[1] - vpub_new_64 - r_v;
        assert(v_back_to_s >= 0);
        uint256 s_apk = prf_caculator::prf(s_ask);
        output_apks_256[1] = s_apk;
        output_vs_64[1] = v_back_to_s;

        LOG(TRACE) << "Generate witness" << endl;
        tx_gad.generate_r1cs_witness(
            r_input_rts, r_input_sns, r_output_cms, r_output_rs, r_G_data_v,
            vpub_old_64, vpub_new_64,
            cm_pools,
            input_asks_256, input_rs_256, input_vs_64,
            output_apks_256, output_vs_64,
            g_256, Gpk_256);
        /*
        tx_gad.check_witness(
            r_input_rts, r_input_sns, r_output_cms, r_output_rs, r_G_data_v,
            vpub_old_64, vpub_new_64,
            cm_pools,
            input_asks_256, input_rs_256, input_vs_64,
            output_apks_256, output_vs_64,
            g_256, Gpk_256
        );
//*/
        if (!pb.is_satisfied())
        {
            LOG(ERROR) << "----------> Failed " << endl;
            throw ProveNotSatisfiedException();
            //Tx1To1Data tx_data;
            //return tx_data;
        }

        LOG(TRACE) << "----------> Success " << endl;

        if (!is_pk_loaded)
        {
            LOG(TRACE) << "Loading PK..." << endl;
            loadFromFile(pk_file, pk);
            is_pk_loaded = true;
            LOG(TRACE) << "----------> PK loaded" << endl;
        }

        //生成密钥对pi ai
        LOG(TRACE) << "Generate pi ai" << endl;
        auto pi = pb.primary_input();
        auto ai = pb.auxiliary_input();

        //生成证明
        LOG(TRACE) << "Generate proof" << endl;
        libsnark::r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(pk, pi, ai);

        //*/
        //写入结果
        Tx1To1Data tx_data;
        tx_data.s_rts = r_input_rts;
        tx_data.s_sns = r_input_sns;
        tx_data.r_cms = r_output_cms;
        tx_data.vpub_old = vpub_old_64;
        tx_data.vpub_new = vpub_new_64;
        tx_data.v_to_payee = output_vs_64[0];
        tx_data.v_change = output_vs_64[1];
        tx_data.v_to_payee_r = r_output_rs[0];
        tx_data.v_change_r = r_output_rs[1];

        stringstream ss("");
        ss << proof;
        tx_data.set_proof(ss.str());

        tx_data.g = g_256;
        tx_data.Gpk = Gpk_256;
        tx_data.set_G_data(r_G_data_v);

        LOG(INFO) << "-----------------------tx data------------------------" << endl;
        for (size_t i = 0; i < 2; i++)
        {
            LOG(INFO) << "input_rts[" << i << "]:\t" << tx_data.s_rts[i].GetHex() << endl;
            LOG(INFO) << "input_sns[" << i << "]:\t" << tx_data.s_sns[i].GetHex() << endl;
        }

        for (size_t i = 0; i < 2; i++)
        {
            LOG(INFO) << "output_cms[" << i << "]:\t" << tx_data.r_cms[i].GetHex() << endl;
        }

        LOG(INFO) << "vpub_old:\t" << tx_data.vpub_old << endl;
        LOG(INFO) << "vpub_new:\t" << tx_data.vpub_new << endl;
        LOG(INFO) << "g:\t" << tx_data.g.GetHex() << endl;
        LOG(INFO) << "Gpk:\t" << tx_data.Gpk.GetHex() << endl;
        LOG(INFO) << "G_data:\t" << tx_data.G_data << endl;
        LOG(INFO) << "proof:\t" << tx_data.proof << endl;

        LOG(INFO) << endl;
        LOG(INFO) << "------------------ secret data --------------------" << endl;
        LOG(INFO) << "To reveiver:" << endl;
        LOG(INFO) << "value:\t" << output_vs_64[0] << "\t r: " << r_output_rs[0].GetHex() << endl;
        LOG(INFO) << "Your change:" << endl;
        LOG(INFO) << "value:\t" << output_vs_64[1] << "\t r: " << r_output_rs[1].GetHex() << endl;
        LOG(INFO) << "---------------------------------------------------" << endl;

        return tx_data;
    }

    //节点自身验证
    bool verify(Tx1To1Data tx_data)
    {
        //load VK
        if (!is_vk_loaded)
        {
            LOG(INFO) << "VK loading..." << endl;
            loadFromFile(vk_file, vk);
            is_vk_loaded = true;
            LOG(INFO) << "VK loaded" << endl;
        }

        LOG(TRACE) << "Generate witness map" << endl;
        //Parse tx_data
        auto pi_v = tx_gadget<FieldT, 2, 2>::witness_map(
            tx_data.s_rts,
            tx_data.s_sns,
            tx_data.r_cms,
            tx_data.vpub_old, tx_data.vpub_new,
            tx_data.g, tx_data.Gpk, tx_data.get_G_data());

        LOG(TRACE) << "Verify proof" << endl;
        r1cs_ppzksnark_proof<ppT> proof;
        stringstream ss("");
        ss << tx_data.get_proof();
        ss >> proof;

        return r1cs_ppzksnark_verifier_strong_IC<ppT>(vk, pi_v, proof);
    }

    //解密监管密文
    static TxGovInfo<2, 2> decrypt_tx_info(uint256 Gsk_256, vector<bool> G_data)
    {
        setup();
        TxGovInfo<2, 2> info;
        info = tx_gadget<FieldT, 2, 2>::decrypt_tx_gov_info(Gsk_256, G_data);

        LOG(INFO) << "----------------- Gov Info -----------------" << endl;
        LOG(INFO) << "vpub_old:\t" << info.vpub_old << endl;
        LOG(INFO) << "vpub_new:\t" << info.vpub_new << endl;
        LOG(INFO) << "in_apks[0]:\t" << info.in_apks[0].GetHex() << endl;
        LOG(INFO) << "in_values[0]:\t" << info.in_values[0] << endl;
        LOG(INFO) << "in_apks[1]:\t" << info.in_apks[1].GetHex() << endl;
        LOG(INFO) << "in_values[1]:\t" << info.in_values[1] << endl;
        LOG(INFO) << "out_apks[0]:\t" << info.out_apks[0].GetHex() << endl;
        LOG(INFO) << "out_values[0]:\t" << info.out_values[0] << endl;
        LOG(INFO) << "out_apks[1]:\t" << info.out_apks[1].GetHex() << endl;
        LOG(INFO) << "out_values[1]:\t" << info.out_values[1] << endl;
        LOG(INFO) << endl;

        return info;
    }
};
}