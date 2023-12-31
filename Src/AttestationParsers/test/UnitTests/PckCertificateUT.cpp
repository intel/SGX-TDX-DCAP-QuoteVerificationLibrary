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

#include <gtest/gtest.h>
#include <gmock/gmock-matchers.h>

#include "SgxEcdsaAttestation/AttestationParsers.h"

#include "X509TestConstants.h"
#include "X509CertGenerator.h"

using namespace intel::sgx::dcap;
using namespace intel::sgx::dcap::parser;
using namespace ::testing;


struct PckCertificateUT: public testing::Test {
    int timeNow = 0;
    int timeOneHour = 3600;

    Bytes sn { 0x40, 0x66, 0xB0, 0x01, 0x4B, 0x71, 0x7C, 0xF7, 0x01, 0xD5,
               0xB7, 0xD8, 0xF1, 0x36, 0xB1, 0x99, 0xE9, 0x73, 0x96, 0xC8 };
    Bytes ppid = Bytes(16, 0xaa);
    Bytes cpusvn = Bytes(16, 0x09);
    Bytes pcesvn = {0x03, 0xf2};
    Bytes pceId = {0x04, 0xf3};
    Bytes fmspc = {0x05, 0xf4, 0x44, 0x45, 0xaa, 0x00};
    Bytes platformInstanceId = {0x0A, 0xBB, 0xFF, 0x05, 0xf4, 0x44, 0xB0, 0x01,
                                0x4B, 0x71, 0xB1, 0x99, 0xE9, 0xE9, 0x73, 0x96};
    test::X509CertGenerator certGenerator;

    crypto::EVP_PKEY_uptr keyRoot = crypto::make_unique<EVP_PKEY>(nullptr);
    crypto::EVP_PKEY_uptr keyInt = crypto::make_unique<EVP_PKEY>(nullptr);
    crypto::EVP_PKEY_uptr key = crypto::make_unique<EVP_PKEY>(nullptr);
    crypto::X509_uptr rootCert = crypto::make_unique<X509>(nullptr);
    crypto::X509_uptr intCert = crypto::make_unique<X509>(nullptr);
    crypto::X509_uptr processorCert = crypto::make_unique<X509>(nullptr);
    crypto::X509_uptr platformCert = crypto::make_unique<X509>(nullptr);
    crypto::X509_uptr platformWithIntegrityCert = crypto::make_unique<X509>(nullptr);
    crypto::X509_uptr unknownCert = crypto::make_unique<X509>(nullptr);

    std::string pemProcessorPckCert, pemPlatformPckCert, pemPlatformIntegrityPckCert, pemIntCert, pemRootCert;
    std::string pemUnknownCert;

    PckCertificateUT()
    {
        keyRoot = certGenerator.generateEcKeypair();
        keyInt = certGenerator.generateEcKeypair();
        key = certGenerator.generateEcKeypair();
        rootCert = certGenerator.generateCaCert(2, sn, timeNow, timeOneHour, keyRoot.get(), keyRoot.get(),
                                                constants::ROOT_CA_SUBJECT, constants::ROOT_CA_SUBJECT);

        intCert = certGenerator.generateCaCert(2, sn, timeNow, timeOneHour, keyInt.get(), keyRoot.get(),
                                               constants::PLATFORM_CA_SUBJECT, constants::ROOT_CA_SUBJECT);

        processorCert = certGenerator.generatePCKCert(2, sn, timeNow, timeOneHour, key.get(), keyInt.get(),
                                                      constants::PCK_SUBJECT, constants::PLATFORM_CA_SUBJECT,
                                                      ppid, cpusvn, pcesvn, pceId, fmspc, 0);
        platformCert = certGenerator.generatePCKCert(2, sn, timeNow, timeOneHour, key.get(), keyInt.get(),
                                                      constants::PCK_SUBJECT, constants::PLATFORM_CA_SUBJECT,
                                                      ppid, cpusvn, pcesvn, pceId, fmspc, 1, platformInstanceId,
                                                      true, true, true);
        platformWithIntegrityCert = certGenerator.generatePCKCert(2, sn, timeNow, timeOneHour, key.get(), keyInt.get(),
                                                                  constants::PCK_SUBJECT, constants::PLATFORM_CA_SUBJECT,
                                                                  ppid, cpusvn, pcesvn, pceId, fmspc, 2, platformInstanceId,
                                                                  true, true, true);
        unknownCert = certGenerator.generatePCKCert(999, sn, timeNow, timeOneHour, key.get(), keyInt.get(),
                                                    constants::PCK_SUBJECT, constants::PLATFORM_CA_SUBJECT,
                                                    ppid, cpusvn, pcesvn, pceId, fmspc, 999, platformInstanceId,
                                                    true, true, true);


        pemProcessorPckCert = certGenerator.x509ToString(processorCert.get());
        pemPlatformPckCert = certGenerator.x509ToString(platformCert.get());
        pemPlatformIntegrityPckCert = certGenerator.x509ToString(platformWithIntegrityCert.get());
        pemIntCert = certGenerator.x509ToString(intCert.get());
        pemRootCert = certGenerator.x509ToString(rootCert.get());
        pemUnknownCert = certGenerator.x509ToString(unknownCert.get());
    }
};

TEST_F(PckCertificateUT, pckCertificateParse)
{
    ASSERT_NO_THROW(x509::PckCertificate::parse(pemProcessorPckCert));
    ASSERT_NO_THROW(x509::PckCertificate::parse(pemPlatformPckCert));
    // Exception thrown because of missing SGX TCB extensions
    ASSERT_THROW(x509::PckCertificate::parse(pemIntCert), InvalidExtensionException);
    // Exception thrown because of missing SGX TCB extensions
    ASSERT_THROW(x509::PckCertificate::parse(pemRootCert), InvalidExtensionException);
}

TEST_F(PckCertificateUT, pckCertificateConstructors)
{
    const auto& certificate = x509::Certificate::parse(pemProcessorPckCert);
    const auto& pckCertificateFromCert = x509::PckCertificate(certificate);
    const auto& pckCertificate = x509::PckCertificate::parse(pemProcessorPckCert);

    ASSERT_EQ(pckCertificateFromCert.getVersion(), pckCertificate.getVersion());
    ASSERT_EQ(pckCertificateFromCert.getSerialNumber(), pckCertificate.getSerialNumber());
    ASSERT_EQ(pckCertificateFromCert.getSubject(), pckCertificate.getSubject());
    ASSERT_EQ(pckCertificateFromCert.getIssuer(), pckCertificate.getIssuer());
    ASSERT_EQ(pckCertificateFromCert.getValidity(), pckCertificate.getValidity());
    ASSERT_EQ(pckCertificateFromCert.getExtensions(), pckCertificate.getExtensions());
    ASSERT_EQ(pckCertificateFromCert.getSignature(), pckCertificate.getSignature());
    ASSERT_EQ(pckCertificateFromCert.getPubKey(), pckCertificate.getPubKey());

    ASSERT_EQ(pckCertificateFromCert.getTcb(), pckCertificate.getTcb());
    ASSERT_EQ(pckCertificateFromCert.getPpid(), pckCertificate.getPpid());
    ASSERT_EQ(pckCertificateFromCert.getPceId(), pckCertificate.getPceId());
    ASSERT_EQ(pckCertificateFromCert.getSgxType(), pckCertificate.getSgxType());
}

TEST_F(PckCertificateUT, processorPckCertificateGetters)
{
    const auto& pckCertificate = x509::PckCertificate::parse(pemProcessorPckCert);

    ASSERT_EQ(pckCertificate.getVersion(), 3);
    ASSERT_THAT(pckCertificate.getSerialNumber(), ElementsAreArray(sn));

    uint8_t *pubKey = nullptr;
    auto pKeyLen = i2d_PublicKey(key.get(), &pubKey);
    std::vector<uint8_t> expectedPublicKey { pubKey, pubKey + pKeyLen };

    ASSERT_THAT(pckCertificate.getPubKey(), ElementsAreArray(expectedPublicKey));
    ASSERT_EQ(pckCertificate.getIssuer(), constants::PLATFORM_CA_SUBJECT);
    ASSERT_EQ(pckCertificate.getSubject(), constants::PCK_SUBJECT);
    ASSERT_NE(pckCertificate.getIssuer(), pckCertificate.getSubject()); // PCK certificate should not be self-signed

    ASSERT_LT(pckCertificate.getValidity().getNotBeforeTime(), pckCertificate.getValidity().getNotAfterTime());

    const std::vector<x509::Extension> expectedExtensions = constants::PCK_X509_EXTENSIONS;
    ASSERT_THAT(pckCertificate.getExtensions().size(), expectedExtensions.size());

    ASSERT_THAT(pckCertificate.getPpid(), ElementsAreArray(ppid));
    ASSERT_THAT(pckCertificate.getPceId(), ElementsAreArray(pceId));
    ASSERT_THAT(pckCertificate.getFmspc(), ElementsAreArray(fmspc));
    ASSERT_EQ(pckCertificate.getSgxType(), x509::SgxType::Standard);

    const auto &tcb = x509::Tcb(cpusvn, cpusvn, 1010);
    ASSERT_THAT(pckCertificate.getTcb().getCpuSvn(), ElementsAreArray(tcb.getCpuSvn()));
    ASSERT_THAT(pckCertificate.getTcb().getSgxTcbComponents(), ElementsAreArray(tcb.getSgxTcbComponents()));
    ASSERT_EQ(pckCertificate.getTcb().getPceSvn(), tcb.getPceSvn());
    ASSERT_EQ(pckCertificate.getTcb(), tcb);

    free(pubKey);
}

TEST_F(PckCertificateUT, platformPckCertificateGetters)
{
    const auto& pckCertificate = x509::PckCertificate::parse(pemPlatformPckCert);

    ASSERT_EQ(pckCertificate.getVersion(), 3);
    ASSERT_THAT(pckCertificate.getSerialNumber(), ElementsAreArray(sn));

    uint8_t *pubKey = nullptr;
    auto pKeyLen = i2d_PublicKey(key.get(), &pubKey);
    std::vector<uint8_t> expectedPublicKey { pubKey, pubKey + pKeyLen };

    ASSERT_THAT(pckCertificate.getPubKey(), ElementsAreArray(expectedPublicKey));
    ASSERT_EQ(pckCertificate.getIssuer(), constants::PLATFORM_CA_SUBJECT);
    ASSERT_EQ(pckCertificate.getSubject(), constants::PCK_SUBJECT);
    ASSERT_NE(pckCertificate.getIssuer(), pckCertificate.getSubject()); // PCK certificate should not be self-signed

    ASSERT_LT(pckCertificate.getValidity().getNotBeforeTime(), pckCertificate.getValidity().getNotAfterTime());

    const std::vector<x509::Extension> expectedExtensions = constants::PCK_X509_EXTENSIONS;
    ASSERT_THAT(pckCertificate.getExtensions().size(), expectedExtensions.size());

    ASSERT_THAT(pckCertificate.getPpid(), ElementsAreArray(ppid));
    ASSERT_THAT(pckCertificate.getPceId(), ElementsAreArray(pceId));
    ASSERT_THAT(pckCertificate.getFmspc(), ElementsAreArray(fmspc));
    ASSERT_EQ(pckCertificate.getSgxType(), x509::SgxType::Scalable);

    const auto &tcb = x509::Tcb(cpusvn, cpusvn, 1010);
    ASSERT_THAT(pckCertificate.getTcb().getCpuSvn(), ElementsAreArray(tcb.getCpuSvn()));
    ASSERT_THAT(pckCertificate.getTcb().getSgxTcbComponents(), ElementsAreArray(tcb.getSgxTcbComponents()));
    ASSERT_EQ(pckCertificate.getTcb().getPceSvn(), tcb.getPceSvn());
    ASSERT_EQ(pckCertificate.getTcb(), tcb);

    free(pubKey);
}

TEST_F(PckCertificateUT, platformPckCertificateWithIntegrityGetters)
{
    const auto& pckCertificate = x509::PckCertificate::parse(pemPlatformIntegrityPckCert);

    ASSERT_EQ(pckCertificate.getVersion(), 3);
    ASSERT_THAT(pckCertificate.getSerialNumber(), ElementsAreArray(sn));

    uint8_t *pubKey = nullptr;
    auto pKeyLen = i2d_PublicKey(key.get(), &pubKey);
    std::vector<uint8_t> expectedPublicKey { pubKey, pubKey + pKeyLen };

    ASSERT_THAT(pckCertificate.getPubKey(), ElementsAreArray(expectedPublicKey));
    ASSERT_EQ(pckCertificate.getIssuer(), constants::PLATFORM_CA_SUBJECT);
    ASSERT_EQ(pckCertificate.getSubject(), constants::PCK_SUBJECT);
    ASSERT_NE(pckCertificate.getIssuer(), pckCertificate.getSubject()); // PCK certificate should not be self-signed

    ASSERT_LT(pckCertificate.getValidity().getNotBeforeTime(), pckCertificate.getValidity().getNotAfterTime());

    const std::vector<x509::Extension> expectedExtensions = constants::PCK_X509_EXTENSIONS;
    ASSERT_THAT(pckCertificate.getExtensions().size(), expectedExtensions.size());

    ASSERT_THAT(pckCertificate.getPpid(), ElementsAreArray(ppid));
    ASSERT_THAT(pckCertificate.getPceId(), ElementsAreArray(pceId));
    ASSERT_THAT(pckCertificate.getFmspc(), ElementsAreArray(fmspc));
    ASSERT_EQ(pckCertificate.getSgxType(), x509::SgxType::ScalableWithIntegrity);

    const auto &tcb = x509::Tcb(cpusvn, cpusvn, 1010);
    ASSERT_THAT(pckCertificate.getTcb().getCpuSvn(), ElementsAreArray(tcb.getCpuSvn()));
    ASSERT_THAT(pckCertificate.getTcb().getSgxTcbComponents(), ElementsAreArray(tcb.getSgxTcbComponents()));
    ASSERT_EQ(pckCertificate.getTcb().getPceSvn(), tcb.getPceSvn());
    ASSERT_EQ(pckCertificate.getTcb(), tcb);

    free(pubKey);
}

TEST_F(PckCertificateUT, unknownTypeCertificateGetters)
{
    const auto& pckCertificate = x509::PckCertificate::parse(pemUnknownCert);

    ASSERT_EQ(pckCertificate.getVersion(), 1000);
    ASSERT_THAT(pckCertificate.getSerialNumber(), ElementsAreArray(sn));

    uint8_t *pubKey = nullptr;
    auto pKeyLen = i2d_PublicKey(key.get(), &pubKey);
    std::vector<uint8_t> expectedPublicKey { pubKey, pubKey + pKeyLen };

    ASSERT_THAT(pckCertificate.getPubKey(), ElementsAreArray(expectedPublicKey));
    ASSERT_EQ(pckCertificate.getIssuer(), constants::PLATFORM_CA_SUBJECT);
    ASSERT_EQ(pckCertificate.getSubject(), constants::PCK_SUBJECT);
    ASSERT_NE(pckCertificate.getIssuer(), pckCertificate.getSubject()); // PCK certificate should not be self-signed

    ASSERT_LT(pckCertificate.getValidity().getNotBeforeTime(), pckCertificate.getValidity().getNotAfterTime());

    const std::vector<x509::Extension> expectedExtensions = constants::PCK_X509_EXTENSIONS;
    ASSERT_THAT(pckCertificate.getExtensions().size(), expectedExtensions.size());

    ASSERT_THAT(pckCertificate.getPpid(), ElementsAreArray(ppid));
    ASSERT_THAT(pckCertificate.getPceId(), ElementsAreArray(pceId));
    ASSERT_THAT(pckCertificate.getFmspc(), ElementsAreArray(fmspc));
    ASSERT_EQ(pckCertificate.getSgxType(), 999);

    const auto &tcb = x509::Tcb(cpusvn, cpusvn, 1010);
    ASSERT_THAT(pckCertificate.getTcb().getCpuSvn(), ElementsAreArray(tcb.getCpuSvn()));
    ASSERT_THAT(pckCertificate.getTcb().getSgxTcbComponents(), ElementsAreArray(tcb.getSgxTcbComponents()));
    ASSERT_EQ(pckCertificate.getTcb().getPceSvn(), tcb.getPceSvn());
    ASSERT_EQ(pckCertificate.getTcb(), tcb);

    free(pubKey);
}

TEST_F(PckCertificateUT, certificateOperators)
{
    const auto& certificate1 = x509::PckCertificate::parse(pemProcessorPckCert);
    const auto& certificate2 = x509::PckCertificate::parse(pemProcessorPckCert);
    const auto ucert = certGenerator.generatePCKCert(3, sn, timeNow, timeOneHour, key.get(), keyInt.get(),
                                                     constants::PCK_SUBJECT, constants::PLATFORM_CA_SUBJECT,
                                                     ppid, cpusvn, pcesvn, pceId, fmspc, 0);
    const auto pemCert = certGenerator.x509ToString(ucert.get());
    const auto& certificate3 = x509::PckCertificate::parse(pemCert);

    ASSERT_EQ(certificate1, certificate2);
    ASSERT_FALSE(certificate1 == certificate3);
    ASSERT_FALSE(certificate2 == certificate3);
}

TEST_F(PckCertificateUT, pckCertificateParseWithWrongAmountOfExtensions)
{
    const auto& brokenCert = certGenerator.generatePCKCert(2, sn, timeNow, timeOneHour, key.get(), keyInt.get(),
                                  constants::PCK_SUBJECT, constants::PLATFORM_CA_SUBJECT,
                                  ppid, cpusvn, pcesvn, pceId, fmspc, 0, {}, false, false, false, true);
    pemProcessorPckCert = certGenerator.x509ToString(brokenCert.get());
    // Exception thrown because of SGX TCB extension is not equal 5 or 7
    ASSERT_THROW(x509::PckCertificate::parse(pemProcessorPckCert), InvalidExtensionException);
}

// Parsing certificate issued by Fuzzer
std::string FuzzerPEM = "-----BEGIN CERTIFICATE-----\n"
                        "MIIEgjCCBCmgAwIBAgIVAPj86fa3dpXXSaait3YKJklN2QV2MAoGCCqGSM49BAMC\n"
                        "MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK\n"
                        "DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\n"
                        "BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMTA4MDYxMzU1MTRaFw0yODA4MDYxMzU1\n"
                        "MTRaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV\n"
                        "BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG\n"
                        "A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
                        "IcT6WLztCuV6iT8zziAYQb/k2fBUVL2rYYL9ifodAbswe1E2vHfIl3nX5TKmXsPp\n"
                        "1PQ64JP8Wa5UK5TiCxdmC6OCAp0wggKZMB8GA1UdIwQYMBaAFANWISC6W4XP1Nt6\n"
                        "peRxuHn4tZixMFgGA1UdHwRRME8wTaBLoEmGR2h0dHBzOi8vY2VydGlmaWNhdGVz\n"
                        "LnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vSW50ZWxTR1hQQ0tQcm9jZXNzb3Iu\n"
                        "Y3JsMB0GA1UdDgQWBBSUMBN/O1dgNPo1uGvZXakTI9+FcTAOBgNVHQ8BAf8EBAMC\n"
                        "BsAwDAYDVR0TAQH/BAIwADCCAd0GCSqGSIb4TQENAQSCAc4wggHKMB4GCiqGSIb4\n"
                        "TQENAQEEECEddULzbDUR7X+23WNJs+IwggFtBgoqhkiG+E0BDQECMIIBXTAQBgsq\n"
                        "hkiG+E0BDQECAQIBUjARBgsqhkiG+E0BDQECAgICAMEwEQYLKoZIhvhNAQ0BAgMC\n"
                        "AgCjMBEGCyqGSIb4TQENAQIEAgIAjDARBgsqhkiG+E0BDQECBQICAPcwEQYLKoZI\n"
                        "hvhNAQ0BAgYCAgDtMBEGCyqGSIb4TQENAQIHAgIA8zAQBgsqhkiG+E0BDQECCAIB\n"
                        "CjAQBgsqhkiG+E0BDQECCQIBUjAQBgsqhkiG+E0BDQECCgIBSzAQBgsqhkiG+E0B\n"
                        "DQECCwIBTjARBgsqhkiG+E0BDQECDAICALswEAYLKoZIhvhNAQ0BAg0CAQQwEQYL\n"
                        "KoZIhvhNAQ0BAg4CAgCfMBMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgENAQIQ\n"
                        "AgIAxzARBgsqhkiG+E0BDQECEQICKWEwHwYLKoZIhvhNAQ0BAhIEEFLBo4z37fMK\n"
                        "UktOuwSfWccwEAYKKoZIhvhQBNA0AwQCimcwFAYKKoZIhvhNAQ0BBAQG7XQq+K31\n"
                        "MA8GCiqGSIb4TQENAQKUAQAwCgYIKoZIzj0EAwIDRwAwRAIgX3COA7iS3GwLO1v4\n"
                        "Ft2fL1WUlShk19OJb1W5GcZSrPMCIEwEmDStayUNO/c02Vas+Oc9rGkC6VVagXmx\n"
                        "jE1xxVlK\n"
                        "-----END CERTIFICATE-----";


/*
 * The certificate above has the wrong OIDname type because expected type for correct parsing is V_ASN1_OBJECT
 * which indicates we are dealing with an identifier while IODname has the type V_ASN1_BOOLEAN which represent
 * a boolean logical value for specific characteristic or atribute. In this case it should be an identifier.
*/
TEST_F(PckCertificateUT, pckCertificateParseWithInvalidOIDnameTypeCert)
{
    // Exception thrown because of wrong type oidName
    ASSERT_THROW(x509::PckCertificate::parse(FuzzerPEM), parser::FormatException);
}