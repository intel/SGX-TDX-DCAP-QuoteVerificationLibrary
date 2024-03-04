/*
 * Copyright (C) 2024 Intel Corporation. All rights reserved.
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

#ifndef SGXECDSAATTESTATION_TDRELAUNCHCHECK_H
#define SGXECDSAATTESTATION_TDRELAUNCHCHECK_H

#include "SgxEcdsaAttestation/QuoteVerification.h"
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "QuoteVerification/QuoteStructures.h"

#include <optional>

using namespace intel::sgx::dcap::parser::json;

namespace intel::sgx::dcap {

#ifdef SGX_LOGS
inline std::vector<uint8_t> tcbComponentsToVectorOfBytes(const std::vector<TcbComponent> &tcbComponents)
{
    std::vector<uint8_t> tcbComponentsVec;
    tcbComponentsVec.reserve(tcbComponents.size());
    for (const auto& component : tcbComponents)
    {
        tcbComponentsVec.push_back(component.getSvn());
    }
    return tcbComponentsVec;
}
#endif //SGX_LOGS

Status checkForRelaunch(const std::array<uint8_t, 16> &tdReport, const TcbInfo &tcbInfo,
                        Status sgxTcbStatus,
                        Status tdxTcbStatus,
                        Status tdxModuleTcbStatus,
                        std::optional<Status> qeTcbStatus);

}

#endif //SGXECDSAATTESTATION_TDRELAUNCHCHECK_H