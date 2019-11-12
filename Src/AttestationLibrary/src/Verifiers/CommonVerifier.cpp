/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "CommonVerifier.h"

#include <OpensslHelpers/SignatureVerification.h>
#include <OpensslHelpers/KeyUtils.h>

#include <algorithm>

namespace intel { namespace sgx { namespace qvl {

bool CommonVerifier::checkStandardExtensions(const std::vector<pckparser::Extension> &presentExtensions,
                                             const std::vector<int> &opensslExtensionNids) const
{
    if(opensslExtensionNids.size() > presentExtensions.size())
    {
        return false;
    }

    for(const auto &requiredNid : opensslExtensionNids)
    {
        const auto found = std::find_if(presentExtensions.begin(),
                                        presentExtensions.end(),
                                        [&requiredNid](const pckparser::Extension &ext){
                                            return ext.opensslNid == requiredNid; 
                                        });
        
        if(found == presentExtensions.end())
        {
            return false;
        }
    }

    return true;
}

Status CommonVerifier::verifyRootCACert(const dcap::parser::x509::Certificate &rootCa) const
{
    if(rootCa.getIssuer() != rootCa.getSubject())
    {
        return STATUS_SGX_ROOT_CA_INVALID_ISSUER;
    }

    if (!crypto::verifySha256EcdsaSignature(rootCa.getSignature(), rootCa.getInfo(), rootCa.getPubKey()))
    {
        return STATUS_SGX_ROOT_CA_INVALID_ISSUER;
    }

    return STATUS_OK;
}

Status CommonVerifier::verifyIntermediate(const dcap::parser::x509::Certificate &intermediate,
                                          const dcap::parser::x509::Certificate &root) const
{
    if (intermediate.getIssuer() != root.getSubject())
    {
        return STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER;
    }

    if (!crypto::verifySha256EcdsaSignature(intermediate.getSignature(), intermediate.getInfo(), root.getPubKey()))
    {
        return STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER;
    }

    return STATUS_OK;
}

bool CommonVerifier::checkSignature(const dcap::parser::x509::Certificate &certificate, const dcap::parser::x509::Certificate &issuer) const
{
    return crypto::verifySha256EcdsaSignature(certificate.getSignature(), certificate.getInfo(), issuer.getPubKey());
}

bool CommonVerifier::checkSignature(const pckparser::CrlStore &crl, const dcap::parser::x509::Certificate &crlIssuer) const
{
    return crypto::verifySignature(crl, crlIssuer.getPubKey());
}

bool CommonVerifier::checkSha256EcdsaSignature(const Bytes &signature, const std::vector<uint8_t> &message,
                                               const std::vector<uint8_t> &publicKey) const {
    auto pubKey = crypto::rawToP256PubKey(publicKey);
    if (pubKey == nullptr)
    {
        return false;
    }
    return crypto::verifySha256EcdsaSignature(signature, message, *pubKey);
}

}}} // namespace intel { namespace sgx { namespace qvl {

