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

#ifndef SGXECDSAATTESTATION_TCBSTATUS_H
#define SGXECDSAATTESTATION_TCBSTATUS_H

#include <string>

namespace intel { namespace sgx { namespace qvl {

enum class TcbStatus {
    UpToDate,
    ConfigurationNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
};

inline TcbStatus parseStringToTcbStatus(const std::string& status)
{
    if (status == "UpToDate")
    {
        return TcbStatus::UpToDate;
    }
    else if (status == "ConfigurationNeeded")
    {
        return TcbStatus::ConfigurationNeeded;
    }
    else if (status == "OutOfDate")
    {
        return TcbStatus::OutOfDate;
    }
    else if (status == "OutOfDateConfigurationNeeded")
    {
        return TcbStatus::OutOfDateConfigurationNeeded;
    }
    else if (status == "Revoked")
    {
        return TcbStatus::Revoked;
    }
    else
    {
        throw std::runtime_error("Cannot parse TCB status - unknown value");
    }
}

}}} // namespace intel { namespace sgx { namespace qvl {

#endif //SGXECDSAATTESTATION_TCBSTATUS_H
