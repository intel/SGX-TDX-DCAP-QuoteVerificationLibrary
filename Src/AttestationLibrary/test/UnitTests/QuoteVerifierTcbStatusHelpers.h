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

#include <Verifiers/QuoteVerifier.h>
#include <SgxEcdsaAttestation/AttestationParsers.h>

#include <utility>
#include "Utils/StatusPrinter.h"
#include "QuoteVerification/QuoteConstants.h"

using namespace intel::sgx;
using namespace dcap::parser::json;
using namespace dcap::parser::x509;
using namespace ::testing;

inline std::vector<uint8_t> toBytes(const std::vector<TcbComponent>& tcbComponents)
{
    std::vector<uint8_t> tcbComponentsVec;
    tcbComponentsVec.reserve(tcbComponents.size());
    for (const auto& component : tcbComponents)
    {
        tcbComponentsVec.push_back(component.getSvn());
    }
    return tcbComponentsVec;
}
inline std::array<uint8_t, 16> toArray(const std::vector<TcbComponent>& tcbComponents)
{
    std::array<uint8_t, 16> uint8Array = {};
    for (size_t i=0; i<16; i++)
    {
        uint8Array[i] = tcbComponents[i].getSvn();
    }
    return uint8Array;
}

namespace intel::sgx::dcap::parser {
namespace json {
class TcbInfoTest : public TcbInfo
{
public:
    explicit TcbInfoTest(const std::vector<TcbLevel>& tcbs, std::vector<TdxModuleIdentity>& modules)
    {
        _id = TcbInfo::TDX_ID;
        _version = Version::V3;
        for (const auto& tcb : tcbs)
        {
            _tcbLevels.insert(tcb);
        }
        for (const auto& module : modules)
        {
            _tdxModuleIdentities.emplace_back(module);
        }
    };
};
}
namespace x509 {
class PckCertificateTest : public PckCertificate
{
public:
    explicit PckCertificateTest(const std::vector<TcbComponent> &cpuSvn, const uint32_t pceSvn)
    {
        auto svn = toBytes(cpuSvn);
        _tcb = Tcb(svn, svn, pceSvn);
    }
};

}}

class QuoteTest : public Quote
{
public:
    explicit QuoteTest(std::array<uint8_t, 16> teeTcbSvn, std::array<uint8_t, 16> teeTcbSvn2)
    {
        header.teeType = constants::TEE_TYPE_TDX;
        body.bodyType = dcap::constants::BODY_TD_REPORT15_TYPE;
        tdReport15.teeTcbSvn = teeTcbSvn;
        tdReport15.teeTcbSvn2 = teeTcbSvn2;
    }
};

inline static const std::string UTD = "UpToDate";
inline static const std::string RKD = "Revoked";
inline static const std::string OOD = "OutOfDate";
inline static const std::string SHN = "SWHardeningNeeded";
inline static const std::string CN = "ConfigurationNeeded";
inline static const std::string CN_SHN = "ConfigurationAndSWHardeningNeeded";
inline static const std::string OOD_CN = "OutOfDateConfigurationNeeded";

inline static const uint32_t latestPceSvn = 10;
inline static const uint32_t earliestPceSvn = 5;
inline static const std::vector<TcbComponent> latestSvn = std::vector<TcbComponent>(16, TcbComponent(0xF0));
inline static const std::vector<TcbComponent> earliestSvn = std::vector<TcbComponent>(16, TcbComponent(0x00));

class Params {

public:
    explicit Params(const TcbInfo& p_tcbInfo,
                    PckCertificate p_certificate,
                    Quote p_quote,
                    const std::optional<Status> p_qeTcbStatus,
                    const Status p_result) :
            tcbInfo(p_tcbInfo),
            certificate(std::move(p_certificate)),
            quote(std::move(p_quote)),
            qeTcbStatus(p_qeTcbStatus),
            result(p_result) {}

    // test input
    const TcbInfo tcbInfo;
    const PckCertificate certificate;
    const Quote quote;
    const std::optional<Status> qeTcbStatus;
    // test output
    const Status result;

    [[nodiscard]] std::string getName() const
    {
        std::ostringstream oss;
        oss << "TcbInfo";
        for (const auto& tcb : tcbInfo.getTcbLevels())
        {
            oss << tcb.getStatus();
        }
        oss << "_Module";
        for (const auto& module : tcbInfo.getTdxModuleIdentities())
        {
            if (!module.getTcbLevels().empty())
            {
                oss << module.getTcbLevels().begin()->getStatus();
            }
        }
        oss << "_Cert" << ((certificate.getTcb().getPceSvn() == latestPceSvn) ? "Latest_" : "Earliest_");
        oss << "Quote" << ((quote.getTeeTcbSvn() == toArray(latestSvn)) ? "Svn1Latest" : "Svn1Earliest");
        oss << ((quote.getTdReport15().teeTcbSvn2 == toArray(latestSvn)) ? "Svn2Latest_" : "Svn2Earliest_");
        oss << "QeTcbStatus";
        if (qeTcbStatus.has_value())
        {
            oss << printStatusOnly(qeTcbStatus.value());
        }
        else
        {
            oss << "NotPresent";
        }
        return oss.str();
    }
};

std::string CaseName(const testing::TestParamInfo<Params>& params) {
    return params.param.getName();
}

PckCertificate latestCert()
{
    return PckCertificateTest(latestSvn, latestPceSvn);
}

PckCertificate earliestCert()
{
    return PckCertificateTest(earliestSvn, earliestPceSvn);
}

TcbLevel latest(const std::string& status)
{
    return TcbLevel("TDX", latestSvn, latestSvn, latestPceSvn, status);
}

TcbLevel earliest(const std::string& status)
{
    return TcbLevel("TDX", earliestSvn, earliestSvn, earliestPceSvn, status);
}

std::vector<TdxModuleIdentity> module(const std::string& latest, const std::string& earliest)
{
    return { TdxModuleIdentity("TDX_F0", {}, {}, {}, {TdxModuleTcbLevel(TdxModuleTcb(0), 0, latest, {})}),
             TdxModuleIdentity("TDX_00", {}, {}, {}, {TdxModuleTcbLevel(TdxModuleTcb(0), 0, earliest, {})}) };
}

TcbInfo ti(const TcbLevel& tcb1, const TcbLevel& tcb2, std::vector<TdxModuleIdentity> modules)
{
    return TcbInfoTest({ tcb1, tcb2 }, modules);
}
Quote q(const std::vector<TcbComponent>& teeTcbSvn, const std::vector<TcbComponent>& teeTcbSvn2)
{
    return QuoteTest(toArray(teeTcbSvn), toArray(teeTcbSvn2));
}
