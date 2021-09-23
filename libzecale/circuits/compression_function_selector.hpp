// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libzeth/circuits/circuit_types.hpp>

namespace libzecale
{

/// Used to select a compression function depending on the scalar field of the
/// wrapping pairing-friendly curve.
template<typename wppT> class compression_function_selector
{
public:
    /// By default, use the tree_hash_selector from zeth.
    using compression_function =
        typename libzeth::tree_hash_selector<wppT>::tree_hash;
};

template<> class compression_function_selector<libff::bw6_761_pp>
{
public:
    // Constants e=17, r=93 computed via scripts/mimc_constraints.sage in
    // http://github.com/clearmatics/zeth.
    using compression_function = libzeth::MiMC_mp_gadget<
        libff::bw6_761_Fr,
        libzeth::MiMC_permutation_gadget<libff::bw6_761_Fr, 17, 93>>;
};

template<> class compression_function_selector<libff::mnt4_pp>
{
public:
    // Constants e=17, r=73 computed via scripts/mimc_constraints.sage in
    // http://github.com/clearmatics/zeth.
    using compression_function = libzeth::MiMC_mp_gadget<
        libff::mnt4_Fr,
        libzeth::MiMC_permutation_gadget<libff::mnt4_Fr, 17, 73>>;
};

template<> class compression_function_selector<libff::mnt6_pp>
{
public:
    // Constants e=17, r=73 computed via scripts/mimc_constraints.sage in
    // http://github.com/clearmatics/zeth.
    using compression_function = libzeth::MiMC_mp_gadget<
        libff::mnt6_Fr,
        libzeth::MiMC_permutation_gadget<libff::mnt6_Fr, 17, 73>>;
};

template<typename ppT>
using compression_function_gadget =
    typename compression_function_selector<ppT>::compression_function;

} // namespace libzecale
