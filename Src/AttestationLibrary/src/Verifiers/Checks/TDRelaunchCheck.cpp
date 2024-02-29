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

#include "TDRelaunchCheck.h"
#include "TdxModuleCheck.h"
#include "Utils/Logger.h"
#include "OpensslHelpers/Bytes.h"

namespace intel::sgx::dcap {

bool isConfigurationNeeded(const Status &status)
{
    switch (status) {
        case STATUS_TCB_CONFIGURATION_NEEDED:
        case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
        case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
        case STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED:
            return true;
        default:
            return false;
    }
}

Status checkForRelaunch(const std::array<uint8_t, 16> &teeTcbSvn2, const TcbInfo &tcbInfo,
                        const Status sgxTcbStatus,
                        const Status tdxTcbStatus,
                        const Status tdxModuleTcbStatus,
                        const std::optional<Status> qeTcbStatus)
{
    LOG_INFO("TD Report - TdxSvn2: {}", bytesToHexString(std::vector<uint8_t>(begin(teeTcbSvn2), end(teeTcbSvn2))));

    // ifception, but that is a literal implementation from documentation
    if (!qeTcbStatus.has_value() || (
            qeTcbStatus != STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE &&
            qeTcbStatus != STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED &&
            qeTcbStatus != STATUS_SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED))
    {
        if (sgxTcbStatus == STATUS_OK ||
            sgxTcbStatus == STATUS_TCB_SW_HARDENING_NEEDED ||
            sgxTcbStatus == STATUS_TCB_CONFIGURATION_NEEDED ||
            sgxTcbStatus == STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED)
        {
            if (tdxTcbStatus == STATUS_TCB_OUT_OF_DATE ||
                tdxTcbStatus == STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED)
            {
                if (tdxModuleTcbStatus == STATUS_TCB_OUT_OF_DATE)
                {
                    if (tcbInfo.getTcbLevels().empty())
                    {
                        LOG_ERROR("Could not find any TDX TCB level");
                        return STATUS_TCB_NOT_SUPPORTED;
                    }

                    const auto &latestTcbLevel = tcbInfo.getTcbLevels().begin();
                    LOG_INFO("Latest TDX TCB Level - sgx: {}, tdx: {}, pceSvn: {}, status: {}",
                             bytesToHexString(latestTcbLevel->getCpuSvn()),
                             bytesToHexString(tcbComponentsToVectorOfBytes(latestTcbLevel->getTdxTcbComponents())),
                             latestTcbLevel->getPceSvn(),
                             latestTcbLevel->getStatus());
                    if (teeTcbSvn2[1] == 0)
                    {
                        if (teeTcbSvn2[0] >= latestTcbLevel->getTdxTcbComponent(0).getSvn() &&
                            teeTcbSvn2[2] >= latestTcbLevel->getTdxTcbComponent(2).getSvn())
                        {
                            if (isConfigurationNeeded(sgxTcbStatus) ||
                                isConfigurationNeeded(tdxTcbStatus))
                            {
                                return STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED;
                            }
                            else
                            {
                                return STATUS_TCB_TD_RELAUNCH_ADVISED;
                            }
                        }
                    }
                    else
                    {
                        const auto &tdxModuleIdentity2 = findTdxModuleIdentity(
                                tcbInfo.getTdxModuleIdentities(),
                                teeTcbSvn2[1]);
                        if (!tdxModuleIdentity2)
                        {
                            return STATUS_TDX_MODULE_MISMATCH;
                        }

                        if (tdxModuleIdentity2->getTcbLevels().empty())
                        {
                            LOG_ERROR("Could not find any TDX Module TCB level");
                            return STATUS_TCB_NOT_SUPPORTED;
                        }

                        const auto &latestTdxModuleIdentity = tdxModuleIdentity2->getTcbLevels().begin();
                        LOG_INFO("Latest TDX Module Identity - IsvSvn: {}, status: {}",
                                 latestTdxModuleIdentity->getTcb().getIsvSvn(),
                                 latestTdxModuleIdentity->getStatus());
                        if (teeTcbSvn2[0] >= latestTdxModuleIdentity->getTcb().getIsvSvn() &&
                            teeTcbSvn2[2] >= latestTcbLevel->getTdxTcbComponent(2).getSvn())
                        {
                            if (isConfigurationNeeded(sgxTcbStatus) ||
                                isConfigurationNeeded(tdxTcbStatus))
                            {
                                return STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED;
                            }
                            else
                            {
                                return STATUS_TCB_TD_RELAUNCH_ADVISED;
                            }
                        }
                    }
                }
            }
        }
    }
    return tdxTcbStatus;
}

} // namespace intel::sgx::dcap