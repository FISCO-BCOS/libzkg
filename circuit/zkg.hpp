/*
 * @file: zkg.hpp
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#ifndef ZKG_H_
#define ZKG_H_
#include <boost/array.hpp>
#include <memory>
#include <string>
#include "cm_pool.hpp"
#include "zkgexception.hpp"

class Tx1To1Param
{
  public:
    //pi
    boost::array<std::string, 2> s_rts, s_sns, r_cms;
    uint64_t vpub_old, vpub_new;
    std::string g, Gpk;

    //proof
    std::string proof; //Base64
    //Gov data
    std::string G_data; //Base64

    //secret data
    uint64_t v_to_payee, v_change;
    std::string v_to_payee_r, v_change_r;

    //description
    uint64_t error_code; //0 sucess, 1 error
    std::string description;
};

class Tx1To1GovInfo
{
  public:
    uint64_t vpub_old, vpub_new;
    boost::array<std::string, 2> in_apks;
    boost::array<uint64_t, 2> in_values;
    boost::array<std::string, 2> out_apks;
    boost::array<uint64_t, 2> out_values;
};

class Tx1To1API
{
  public:
    std::string full_name;

    Tx1To1API(
        bool is_preload_pk = false,
        bool is_preload_vk = false,
        const std::string &pk_file = "pk.data",
        const std::string &vk_file = "vk.data");
    ~Tx1To1API();

    static void generate(const std::string &pk_file, const std::string &vk_file);

    Tx1To1Param prove(
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
        const std::string &g, const std::string &Gpk);

    bool verify(
        const std::string &input_rt0_str, const std::string &input_rt1_str,
        const std::string &input_sn0_str, const std::string &input_sn1_str,
        const std::string &output_cm0_str, const std::string &output_cm1_str,
        uint64_t vpub_old_64,
        uint64_t vpub_new_64,
        const std::string &g_str,
        const std::string &Gpk_str,
        const std::string &G_data_str,
        const std::string &proof);

    bool verify(const Tx1To1Param &param);

    static Tx1To1GovInfo decrypt_tx_info(const std::string &Gsk, const std::string &G_data);

    //Important parameter
    static std::string ZERO_CM()
    {
        return "ed6dd816927506bf94f63865d5792bfca5a1a14237494b74367e143df2caf7c6";
    }
    static std::string ZERO_CM_ROOT()
    {
        //return "00ce690d97c002d9e2b7fae65bd6c28423c29b5727d3201a1c5ad9223771c576"; //single tee (tree depth 29)
        return "a7927ccee105a1ef28862f9bd501ac50c675809ec13880e1cbe1cd889834f160"; //multi tree (tree depth 4)
    }
    static std::string ZERO_SN()
    {
        return "d8a93718eaf9feba4362d2c091d4e58ccabe9f779957336269b4b917be9856da";
    }

    static size_t TREE_DEPTH();

    static void check_prove_params(
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
        const std::string &g, const std::string &Gpk);

    static void check_verify_params(
        const std::string &input_rt0_str, const std::string &input_rt1_str,
        const std::string &input_sn0_str, const std::string &input_sn1_str,
        const std::string &output_cm0_str, const std::string &output_cm1_str,
        uint64_t vpub_old_64,
        uint64_t vpub_new_64,
        const std::string &g_str,
        const std::string &Gpk_str,
        const std::string &G_data_str,
        const std::string &proof);
    
    static void check_decrypt_tx_params(const std::string &Gsk, const std::string &G_data);
};

class MerkleTree
{
  private:
    std::string full_name;

  public:
    MerkleTree(const std::string &name = "");
    ~MerkleTree();
    void clear();
    void append(const std::string &hash);
    std::string root();
};

class ZkgTool
{
  public:
    static std::string generate_apk(const std::string &ask);
    static std::string generate_gpk(const std::string &ask);
    static std::string generate_gpk(const std::string &ask, const std::string &generator);
    static inline bool is_hex_char(char c);
    static bool is_uint256_hex(const std::string &str);
    static bool is_valid_fp_generator(const std::string &str);
    static bool is_same_uint256_str(const std::string &a_str, const std::string &b_str);
};

//Log Verbosity
#define ZKG_LOG_NONE (0)
#define ZKG_LOG_INFO (0x1 << 0)
#define ZKG_LOG_DEBUG (0x1 << 1)
#define ZKG_LOG_TRACE (0x1 << 2)
#define ZKG_LOG_WARNING (0x1 << 3)
#define ZKG_LOG_ERROR (0x1 << 4)
#define ZKG_LOG_ALL (ZKG_LOG_INFO | ZKG_LOG_DEBUG | ZKG_LOG_TRACE | ZKG_LOG_WARNING | ZKG_LOG_ERROR)

void zkg_set_log_verbosity(unsigned verbosity); //zkg_set_log_verbosity(ZKG_LOG_INFO | ZKG_LOG_DEBUG | ZKG_LOG_TRACE)
#endif