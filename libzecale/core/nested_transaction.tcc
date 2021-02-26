// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_NESTED_TRANSACTION_TCC__
#define __ZECALE_CORE_NESTED_TRANSACTION_TCC__

#include "libzecale/core/nested_transaction.hpp"

#include <libzeth/core/utils.hpp>

namespace libzecale
{

template<typename nppT, typename nsnarkT>
nested_transaction<nppT, nsnarkT>::nested_transaction()
{
}

template<typename nppT, typename nsnarkT>
nested_transaction<nppT, nsnarkT>::nested_transaction(
    const std::string &application_name,
    const libzeth::extended_proof<nppT, nsnarkT> &extended_proof,
    const std::vector<uint8_t> &parameters,
    uint32_t fee_wei)
    : _application_name(application_name)
    , _parameters(parameters)
    , _fee_wei(fee_wei)
{
    this->_extended_proof =
        std::make_shared<libzeth::extended_proof<nppT, nsnarkT>>(
            extended_proof);
}

template<typename nppT, typename nsnarkT>
const std::string &nested_transaction<nppT, nsnarkT>::application_name() const
{
    return _application_name;
};

template<typename nppT, typename nsnarkT>
const libzeth::extended_proof<nppT, nsnarkT>
    &nested_transaction<nppT, nsnarkT>::extended_proof() const
{
    return *(_extended_proof);
};

template<typename nppT, typename nsnarkT>
const std::vector<uint8_t> &nested_transaction<nppT, nsnarkT>::parameters()
    const
{
    return _parameters;
}

template<typename nppT, typename nsnarkT>
uint32_t nested_transaction<nppT, nsnarkT>::fee_wei() const
{
    return _fee_wei;
}

template<typename nppT, typename nsnarkT>
std::ostream &nested_transaction<nppT, nsnarkT>::write_json(
    std::ostream &os) const
{
    os << "{\n"
          "\t\"app_name\": "
       << "\"" << _application_name << "\"";
    os << ",\n"
          "\t\"ext_proof\": ";
    _extended_proof->write_json(os);
    os << ",\n"
          "\t\"parameters\": "
       << "\"" << libzeth::bytes_to_hex(_parameters.data(), _parameters.size())
       << ",\n\t\"fee_wei\": " << _fee_wei << "\"\n}\n";
    return os;
}

template<typename nppT, typename nsnarkT>
bool nested_transaction<nppT, nsnarkT>::operator<(
    const nested_transaction<nppT, nsnarkT> &right) const
{
    return fee_wei() < right.fee_wei();
}

} // namespace libzecale

#endif // __ZECALE_CORE_NESTED_TRANSACTION_TCC__
