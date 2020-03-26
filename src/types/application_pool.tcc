// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_APPLICATION_POOL_TCC__
#define __ZECALE_APPLICATION_POOL_TCC__

#include <queue>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libzeth/libsnark_helpers/extended_proof.hpp>

namespace libzecale
{

template<
    typename ppT,
    size_t NumProofs>
application_pool<ppT, NumProofs>::application_pool(
    std::string name,
    libsnark::r1cs_ppzksnark_verification_key<ppT> vk) : proofs_queue()
{
    this->name = name;
    this->verification_key = std::make_shared<libsnark::r1cs_primary_input<ppT>>(vk);
}

template<
    typename ppT,
    size_t NumProofs>
std::array<libzeth::extended_proof<ppT>, NumProofs> get_next_batch() {
   std::array<libzeth::extended_proof<ppT>, NumProofs> res;
   for (size_t i = 0; i < NumProofs; i++) {
       res[i] = this->proofs_queue.pop_front()
   }

   return res;
}

template<
    typename ppT,
    size_t NumProofs>
libsnark::r1cs_ppzksnark_verification_key<ppT> get_verification_key() {
    return this->verification_key;
}

} // namespace libzecale

#endif // __ZECALE_APPLICATION_POOL_TCC__