// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZECALE_CORE_TRANSACTION_TO_AGGREGATE_TCC__
#define __ZECALE_CORE_TRANSACTION_TO_AGGREGATE_TCC__

namespace libzecale
{

template<typename nppT, typename nsnarkT>
transaction_to_aggregate<nppT, nsnarkT>::transaction_to_aggregate(
    const std::string &application_name,
    const libzeth::extended_proof<nppT, nsnarkT> &extended_proof,
    uint32_t fee_wei)
    : _application_name(application_name), _fee_wei(fee_wei)
{
    this->_extended_proof =
        std::make_shared<libzeth::extended_proof<nppT, nsnarkT>>(
            extended_proof);
}

template<typename nppT, typename nsnarkT>
std::ostream &transaction_to_aggregate<nppT, nsnarkT>::write_json(
    std::ostream &os) const
{
    os << "{\n"
          "\t\"app_name\": "
       << "\"" << _application_name << "\"";
    os << ",\n"
          "\t\"fee_wei\": "
       << "\"" << _fee_wei << "\"";
    os << "\n"
          "}\n";
    return os;
}

template<typename nppT, typename nsnarkT>
bool transaction_to_aggregate<nppT, nsnarkT>::operator<(
    const transaction_to_aggregate<nppT, nsnarkT> &right) const
{
    return _fee_wei < right._fee_wei;
}

} // namespace libzecale

#endif // __ZECALE_CORE_TRANSACTION_TO_AGGREGATE_TCC__
