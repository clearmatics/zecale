// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CONSTANTS__
#define __ZECALE_CONSTANTS__

#include <stddef.h>

// Constants that determines how many proofs are verified
// in the aggregator circuit
static const size_t ZECALE_BATCH_SIZE = 2;

// Max depth of the Proofs pool/Zeth tx pool
static const size_t ZECALE_MAX_POOL_DEPTH = 10;

#endif // __ZECALE_CONSTANTS__
