/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

#ifndef SGXECDSAATTESTATION_TCBINFO_JSON_VERIFIER_MOCK_H_
#define SGXECDSAATTESTATION_TCBINFO_JSON_VERIFIER_MOCK_H_

#include <gmock/gmock.h>

#include <SgxEcdsaAttestation/AttestationParsers.h>

#include <string>
#include <vector>


namespace intel { namespace sgx { namespace dcap { namespace test {


class TcbInfoMock: public dcap::parser::json::TcbInfo
{
public:
    MOCK_METHOD1(parse, Status(const std::string&));

    MOCK_CONST_METHOD0(getInfoBody, const std::vector<uint8_t>&());
    MOCK_CONST_METHOD0(getSignature, const std::vector<uint8_t>&());
    MOCK_CONST_METHOD0(getFmspc, const std::vector<uint8_t>&());
    MOCK_CONST_METHOD0(getPceId, const std::vector<uint8_t>&());
    MOCK_CONST_METHOD0(getId, std::string());
    MOCK_CONST_METHOD0(getVersion, uint32_t());
    MOCK_CONST_METHOD0(getTcbLevels, const std::set<dcap::parser::json::TcbLevel, std::greater<dcap::parser::json::TcbLevel>>&());
    MOCK_CONST_METHOD0(getNextUpdate, time_t());
    MOCK_CONST_METHOD0(getTdxModule, const dcap::parser::json::TdxModule&());
    MOCK_CONST_METHOD0(getTdxModuleIdentities, const std::vector<dcap::parser::json::TdxModuleIdentity>&());
};


}}}}

#endif
