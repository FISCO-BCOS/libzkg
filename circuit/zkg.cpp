/*
 * @file: zkg.cpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#include <map>
#include <vector>
#include <memory>
#include "tx1to1.hpp"
#include "zkg.hpp"
#include "cm_pool.hpp"
#include "util/uint256.h"
#include "util/IncrementalMerkleTree.hpp"

std::map<std::string, zkg::Tx1To1 *> tx1to1_table;

Tx1To1API::Tx1To1API(
    bool is_preload_pk,
    bool is_preload_vk,
    const std::string &pk_file,
    const std::string &vk_file)
{
    do
    {
        full_name = random_uint256().GetHex();
    } while (tx1to1_table[full_name] != NULL);
    tx1to1_table[full_name] = new zkg::Tx1To1(is_preload_pk, is_preload_vk, pk_file, vk_file);
}

Tx1To1API::~Tx1To1API()
{
    delete tx1to1_table[full_name];
    tx1to1_table[full_name] = NULL;
}

void Tx1To1API::generate(const std::string &pk_file, const std::string &vk_file)
{
    zkg::Tx1To1::generate(pk_file, vk_file);
}

Tx1To1Param Tx1To1API::prove(
    std::shared_ptr<CMPool> cm_pool,
    //left side
    const std::string &s_ask,
    uint64_t vpub_old_64,
    uint64_t s_v0, uint64_t s_v1,
    const std::string &s_r0, const std::string &s_r1,
    bool is_zero_cm0, bool is_zero_cm1,
    //right side
    const std::string &r_apk,
    uint64_t vpub_new_64, uint64_t r_v,
    //gov param
    const std::string &g, const std::string &Gpk)
{
    boost::array<uint64_t, 2> s_vs = {s_v0, s_v1};
    boost::array<uint256, 2> s_rs = {uint256S(s_r0), uint256S(s_r1)};
    boost::array<bool, 2> is_zero_cms = {is_zero_cm0, is_zero_cm1};

    zkg::Tx1To1Data data;
    Tx1To1Param param;

    try
    {
        //check params, if is invalid throw exception
        LOG(TRACE) << "Check prove parameters" << endl;
        check_prove_params(
            cm_pool,
            s_ask,
            vpub_old_64,
            s_v0, s_v1,
            s_r0, s_r1,
            is_zero_cm0, is_zero_cm1,
            r_apk,
            vpub_new_64, r_v,
            g, Gpk);

        LOG(TRACE) << "Prove start" << endl;
        data = tx1to1_table[full_name]->prove(
            cm_pool,
            uint256S(s_ask),
            vpub_old_64,
            s_vs, s_rs,
            is_zero_cms,
            uint256S(r_apk),
            vpub_new_64, r_v,
            uint256S(g), uint256S(Gpk));
    }
    catch (std::exception &e)
    {
        LOG(TRACE) << "Prove failed for " << e.what() << endl;
        param.error_code = 1;
        param.description = e.what();
        return param;
    }

    param.s_rts[0] = data.s_rts[0].GetHex();
    param.s_rts[1] = data.s_rts[1].GetHex();
    param.s_sns[0] = data.s_sns[0].GetHex();
    param.s_sns[1] = data.s_sns[1].GetHex();
    param.r_cms[0] = data.r_cms[0].GetHex();
    param.r_cms[1] = data.r_cms[1].GetHex();
    param.vpub_old = data.vpub_old;
    param.vpub_new = data.vpub_new;
    param.g = data.g.GetHex();
    param.Gpk = data.Gpk.GetHex();
    param.G_data = data.G_data;
    param.proof = data.proof;

    param.v_to_payee = data.v_to_payee;
    param.v_change = data.v_change;
    param.v_to_payee_r = data.v_to_payee_r.GetHex();
    param.v_change_r = data.v_change_r.GetHex();

    param.error_code = 0;
    param.description = "Prove success!";

    LOG(TRACE) << "Prove success!" << endl;
    return param;
}

bool Tx1To1API::verify(
    const std::string &input_rt0_str, const std::string &input_rt1_str,
    const std::string &input_sn0_str, const std::string &input_sn1_str,
    const std::string &output_cm0_str, const std::string &output_cm1_str,
    uint64_t vpub_old_64,
    uint64_t vpub_new_64,
    const std::string &g_str,
    const std::string &Gpk_str,
    const std::string &G_data_str,
    const std::string &proof)
{
    LOG(TRACE) << "Verify start" << endl;
    zkg::Tx1To1Data tx_data;
    tx_data.s_rts[0] = uint256S(input_rt0_str);
    tx_data.s_rts[1] = uint256S(input_rt1_str);
    tx_data.s_sns[0] = uint256S(input_sn0_str);
    tx_data.s_sns[1] = uint256S(input_sn1_str);
    tx_data.r_cms[0] = uint256S(output_cm0_str);
    tx_data.r_cms[1] = uint256S(output_cm1_str);
    tx_data.vpub_old = vpub_old_64;
    tx_data.vpub_new = vpub_new_64;
    tx_data.g = uint256S(g_str);
    tx_data.Gpk = uint256S(Gpk_str);
    tx_data.G_data = G_data_str;
    tx_data.proof = proof;

    bool result = false;
    try
    {
        LOG(TRACE) << "Check parameters" << endl;
        check_verify_params(
            input_rt0_str, input_rt1_str,
            input_sn0_str, input_sn1_str,
            output_cm0_str, output_cm1_str,
            vpub_old_64,
            vpub_new_64,
            g_str,
            Gpk_str,
            G_data_str,
            proof);

        result = tx1to1_table[full_name]->verify(tx_data);
    }
    catch (std::exception &e)
    {
        LOG(TRACE) << "Verify failed for " << e.what() << endl;
        result = false;
    }

    LOG(TRACE) << "Verify result: " << (result ? "true" : "false") << endl;
    return result;
}

bool Tx1To1API::verify(const Tx1To1Param &param)
{
    return verify(
        param.s_rts[0], param.s_rts[1],
        param.s_sns[0], param.s_sns[1],
        param.r_cms[0], param.r_cms[1],
        param.vpub_old,
        param.vpub_new,
        param.g,
        param.Gpk,
        param.G_data,
        param.proof);
}

Tx1To1GovInfo Tx1To1API::decrypt_tx_info(const std::string &Gsk, const std::string &G_data)
{
    Tx1To1GovInfo res;
    try
    {
        check_decrypt_tx_params(Gsk, G_data);

        vector<unsigned char> G_bytes = DecodeBase64(G_data.c_str());
        vector<bool> G_bits = convertBytesVectorToVector(G_bytes);
        TxGovInfo<2, 2> info = zkg::Tx1To1::decrypt_tx_info(uint256S(Gsk), G_bits);

        res.vpub_old = info.vpub_old;
        res.vpub_new = info.vpub_new;
        res.in_apks[0] = info.in_apks[0].GetHex();
        res.in_apks[1] = info.in_apks[1].GetHex();
        res.in_values[0] = info.in_values[0];
        res.in_values[1] = info.in_values[1];
        res.out_apks[0] = info.out_apks[0].GetHex();
        res.out_apks[1] = info.out_apks[1].GetHex();
        res.out_values[0] = info.out_values[0];
        res.out_values[1] = info.out_values[1];
    }
    catch (std::exception &e)
    {
        LOG(TRACE) << "Decrypt failed for " << e.what() << endl;
    }
    return res;
}

size_t Tx1To1API::TREE_DEPTH()
{
    return size_t(INCREMENTAL_MERKLE_TREE_DEPTH);
}

void Tx1To1API::check_prove_params(
    std::shared_ptr<CMPool> cm_pool,
    //left side
    const std::string &s_ask,
    uint64_t vpub_old_64,
    uint64_t s_v0, uint64_t s_v1,
    const std::string &s_r0, const std::string &s_r1,
    bool is_zero_cm0, bool is_zero_cm1,
    //right side
    const std::string &r_apk,
    uint64_t vpub_new_64, uint64_t r_v,
    //gov param
    const std::string &g, const std::string &Gpk)
{
    //value balance
    if (vpub_old_64 + (is_zero_cm0 ? 0 : s_v0) + (is_zero_cm1 ? 0 : s_v1) < vpub_new_64 + r_v)
        throw ProveValueException();

    //s_ask
    if (!ZkgTool::is_uint256_hex(s_ask))
        throw NotUint256Exception("Prove payer's secret_key(ask)");

    //s_r0 and s_r1
    if (!ZkgTool::is_uint256_hex(s_r0) || !ZkgTool::is_uint256_hex(s_r0))
        throw NotUint256Exception("Prove payer's spend_key(r)");

    //r_apk
    if (!ZkgTool::is_uint256_hex(r_apk))
        throw NotUint256Exception("Prove payee's public_key(apk)");

    //g
    if (!ZkgTool::is_valid_fp_generator(g))
        throw GovGeneratorException();

    //Gpk
    if (!ZkgTool::is_uint256_hex(Gpk))
        throw NotUint256Exception("Prove overseer's public_key(Gpk)");
}

void Tx1To1API::check_verify_params(
    const std::string &input_rt0_str, const std::string &input_rt1_str,
    const std::string &input_sn0_str, const std::string &input_sn1_str,
    const std::string &output_cm0_str, const std::string &output_cm1_str,
    uint64_t vpub_old_64,
    uint64_t vpub_new_64,
    const std::string &g_str,
    const std::string &Gpk_str,
    const std::string &G_data_str,
    const std::string &proof)
{
    //CM Root
    if (!ZkgTool::is_uint256_hex(input_rt0_str) || !ZkgTool::is_uint256_hex(input_rt1_str))
        throw NotUint256Exception("Verify CM root");

    //SN
    if (!ZkgTool::is_uint256_hex(input_sn0_str) || !ZkgTool::is_uint256_hex(input_sn1_str))
        throw NotUint256Exception("Verify SN");

    ///New CM
    if (!ZkgTool::is_uint256_hex(output_cm0_str) || !ZkgTool::is_uint256_hex(output_cm1_str))
        throw NotUint256Exception("Verify new CM");

    //g
    if (!ZkgTool::is_valid_fp_generator(g_str))
        throw GovGeneratorException();

    //Gpk
    if (!ZkgTool::is_uint256_hex(Gpk_str))
        throw NotUint256Exception("Prove overseer's public_key(Gpk)");
}

void Tx1To1API::check_decrypt_tx_params(const std::string &Gsk, const std::string &G_data)
{
    if (!ZkgTool::is_uint256_hex(Gsk))
        throw NotUint256Exception("Decrypt, overseer's secret key(gsk)");
}

//Merkle API
std::map<std::string, ZCIncrementalMerkleTree *> treePool; //use a pool, containing all merkle tree

MerkleTree::MerkleTree(const std::string &name)
{
    do
    {
        full_name = random_uint256().GetHex() + name;
    } while (tx1to1_table[full_name] != NULL);
    treePool[full_name] = new ZCIncrementalMerkleTree(); //create an IncrementalMerkleTree
}

MerkleTree::~MerkleTree()
{
    if (treePool[full_name] != NULL)
    {
        delete treePool[full_name];
        treePool[full_name] = NULL;
    }
}

void MerkleTree::clear()
{
    delete treePool[full_name];
    treePool[full_name] = new ZCIncrementalMerkleTree();
}

void MerkleTree::append(const std::string &hash)
{
    treePool[full_name]->append(libzcash::SHA256Compress(uint256S(hash)));
}

std::string MerkleTree::root()
{
    return treePool[full_name]->root().GetHex();
}

//ZkgTool

std::string ZkgTool::generate_apk(const std::string &ask)
{
    if (is_uint256_hex(ask))
        return prf_caculator::prf(uint256S(ask)).GetHex();
    else
        return "";
}

std::string ZkgTool::generate_gpk(const std::string &gsk)
{
    if (is_uint256_hex(gsk))
    {
        ppT::init_public_params();
        return ELGamal<ppT::Fp_type>::pk_generator(gsk); //use default generator
    }
    else
        return "";
}

std::string ZkgTool::generate_gpk(const std::string &gsk, const std::string &generator)
{
    if (is_uint256_hex(gsk) && is_valid_fp_generator(generator))
    {
        ppT::init_public_params();
        return ELGamal<ppT::Fp_type>::pk_generator(gsk, generator);
    }
    else
        return "";
}

bool ZkgTool::is_hex_char(char c)
{
    return ('0' <= c && c <= '9') ||
           ('A' <= c && c <= 'F') ||
           ('a' <= c && c <= 'f');
}

bool ZkgTool::is_uint256_hex(const std::string &str)
{
    if (str.length() > 64)
    {
        LOG(INFO) << "Hex string is out of bound(64 bytes)" << endl;
        return false;
    }

    for (size_t i = 0; i < str.length(); i++)
    {
        char c = str[i];
        if (!is_hex_char(c))
        {
            LOG(INFO) << "Illegal hex string of character " << c << endl;
            return false;
        }
    }
    return true;
}

bool ZkgTool::is_valid_fp_generator(const std::string &str)
{
    if (!is_uint256_hex(str))
        return false;

    if (str.length() != 64 || !('2' < str[0] && str[0] < '4'))
    {
        LOG(INFO) << "Illegal generator. " << endl;
        LOG(INFO) << "generator min: 2000000000000000000000000000000000000000000000000000000000000000" << endl;
        LOG(INFO) << "generator max: 4000000000000000000000000000000000000000000000000000000000000000" << endl;
        return false;
    }
    return true;
}

bool ZkgTool::is_same_uint256_str(const std::string &a_str, const std::string &b_str)
{
    uint256 a = uint256S(a_str), b = uint256S(b_str);
    return a == b;
}

void zkg_set_log_verbosity(unsigned verbosity)
{
    zkg_log_verbosity = verbosity;
}
