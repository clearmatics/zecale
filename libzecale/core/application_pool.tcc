// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_APPLICATION_POOL_TCC__
#define __ZECALE_CORE_APPLICATION_POOL_TCC__

#include "libzecale/core/application_pool.hpp"

namespace libzecale
{

template<typename nppT, typename nsnarkT, size_t NumProofs>
application_pool<nppT, nsnarkT, NumProofs>::application_pool(
    const std::string &name, const typename nsnarkT::verification_key &vk)
    : _name(name), _verification_key(vk), _tx_pool()
{
}

template<typename nppT, typename nsnarkT, size_t NumProofs>
const std::string &application_pool<nppT, nsnarkT, NumProofs>::name() const
{
    return _name;
}

template<typename nppT, typename nsnarkT, size_t NumProofs>
const typename nsnarkT::verification_key &application_pool<
    nppT,
    nsnarkT,
    NumProofs>::verification_key() const
{
    return _verification_key;
}

template<typename nppT, typename nsnarkT, size_t NumProofs>
void application_pool<nppT, nsnarkT, NumProofs>::add_tx(
    const transaction_to_aggregate<nppT, nsnarkT> &tx)
{
    _tx_pool.push(tx);
}

template<typename nppT, typename nsnarkT, size_t NumProofs>
size_t application_pool<nppT, nsnarkT, NumProofs>::tx_pool_size() const
{
    return _tx_pool.size();
}

template<typename nppT, typename nsnarkT, size_t NumProofs>
size_t application_pool<nppT, nsnarkT, NumProofs>::get_next_batch(
    std::array<transaction_to_aggregate<nppT, nsnarkT>, NumProofs> &batch)
{
    // TODO: For now, only return whole batches (to avoid nasty errors where
    // elements in the array are not initialized properly). Later, clean up the
    // data structures to support partial-batches in a safe way.
    if (_tx_pool.size() < NumProofs) {
        return 0;
    }
    for (size_t entry_idx = 0; entry_idx < NumProofs; ++entry_idx) {
        batch[entry_idx] = _tx_pool.top();
        _tx_pool.pop();
    }
    return NumProofs;
}

} // namespace libzecale

#endif // __ZECALE_CORE_APPLICATION_POOL_TCC__
