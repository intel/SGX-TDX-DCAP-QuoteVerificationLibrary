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

#ifndef SGXECDSAATTESTATION_TCBSTATUS_H
#define SGXECDSAATTESTATION_TCBSTATUS_H

#include <string>
#include <set>
#include <map>
#include "SgxEcdsaAttestation/QuoteVerification.h"
#include "Utils/Logger.h"
#include "Utils/RuntimeException.h"

namespace intel::sgx::dcap {

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

static const std::set<std::string> VALID_TCB_INFO_STATUSES =
        {{ "UpToDate", "OutOfDate", "ConfigurationNeeded", "Revoked", "OutOfDateConfigurationNeeded",
           "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded" }};

static const std::set<std::string> VALID_MODULE_TCB_STATUSES =
        {{ "UpToDate", "OutOfDate", "Revoked" }};

static const std::map<std::string, Status> TCB_STATUS_MAP = {
        {"UpToDate", STATUS_OK},
        {"Revoked", STATUS_TCB_REVOKED},
        {"ConfigurationNeeded", STATUS_TCB_CONFIGURATION_NEEDED},
        {"OutOfDate", STATUS_TCB_OUT_OF_DATE},
        {"OutOfDateConfigurationNeeded", STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED},
        {"SWHardeningNeeded", STATUS_TCB_SW_HARDENING_NEEDED},
        {"ConfigurationAndSWHardeningNeeded", STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED},
};

inline Status stringToTcbStatus(const std::string& tcbStatus, const std::set<std::string> &validStatuses)
{
    if (validStatuses.find(tcbStatus) == validStatuses.end())
    {
        LOG_ERROR("TCB status of this structure is unrecognized: {}", tcbStatus);
        throw RuntimeException(STATUS_TCB_UNRECOGNIZED_STATUS);
    }

    const auto &found = TCB_STATUS_MAP.find(tcbStatus);
    if (found == TCB_STATUS_MAP.end())
    {
        LOG_ERROR("Unsupported TCB status: {}", tcbStatus);
        throw RuntimeException(STATUS_TCB_UNRECOGNIZED_STATUS);
    }

    return found->second;
}

} // namespace intel::sgx::dcap {

#endif //SGXECDSAATTESTATION_TCBSTATUS_H
