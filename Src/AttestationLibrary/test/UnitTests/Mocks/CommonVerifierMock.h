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

#ifndef INTEL_SGX_QVL_TEST_COMMON_VERIFIER_H_
#define INTEL_SGX_QVL_TEST_COMMON_VERIFIER_H_

#include <gmock/gmock.h>
#include <Verifiers/CommonVerifier.h>

namespace intel { namespace sgx { namespace qvl { namespace test {

class CommonVerifierMock : public qvl::CommonVerifier
{
public:
    MOCK_CONST_METHOD1(verifyRootCACert, Status(const dcap::parser::x509::Certificate &));
   
    MOCK_CONST_METHOD2(verifyIntermediate, Status(
                const dcap::parser::x509::Certificate &,
                const dcap::parser::x509::Certificate &));

    MOCK_CONST_METHOD2(checkStandardExtensions, bool(
                const std::vector<pckparser::Extension>&,
                const std::vector<int>&));

    MOCK_CONST_METHOD2(checkSignature, bool(
            const dcap::parser::x509::Certificate&,
            const dcap::parser::x509::Certificate&));

    MOCK_CONST_METHOD2(checkSignature, bool(
            const pckparser::CrlStore&,
            const dcap::parser::x509::Certificate&));

    MOCK_CONST_METHOD3(checkSha256EcdsaSignature, bool(
            const Bytes&,
            const std::vector<uint8_t>&,
            const std::vector<uint8_t>&));


};

}}}}// namespace intel { namespace sgx { namespace qvl { namespace test {

#endif
