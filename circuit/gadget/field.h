/*
 * @file: field.h
 * @author: jimmyshi 
 * @date: 4th May 2018
 * @copyright: MIT license (see LICENSE file)
 */


#ifndef ZKG_FIELD_H_
#define ZKG_FIELD_H_
#include "util/uint256.h"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/relations/variable.hpp"
#include "libff/common/default_types/ec_pp.hpp"
#include "libff/common/profiling.hpp"
#include "libff/common/utils.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

#include <fstream>
#include <string>
#include <exception>

using namespace std;
using namespace libsnark;
using namespace libff;

using ppT = default_r1cs_ppzksnark_pp;

#endif