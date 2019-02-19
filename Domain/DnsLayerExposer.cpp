//
// Created by mio on 2019-02-18.
//

#include "CustomDnsLayer.h"

size_t pcpp::DnsLayerExposer::getOffsetInLayer(const pcpp::IDnsResource &res) {
    return res.m_OffsetInLayer;
}

/*
 * It is the length of the name filed, not the length of the name string.
 */
size_t pcpp::DnsLayerExposer::getNameFieldLength(const pcpp::IDnsResource &res) {
    return res.m_NameLength;
}

size_t pcpp::DnsLayerExposer::decodeName(pcpp::IDnsResource& res,u_int8_t* buffer, const char* encodedName, char* result, int iteration) {
    auto tmp = res.m_DnsLayer->m_Data;
    res.m_DnsLayer->m_Data = buffer;
    auto len = res.decodeName(encodedName, result, iteration);
    res.m_DnsLayer->m_Data = tmp;
    return len;
}