/*
    Copyright 2010 DanID

    This file is part of OpenOcesAPI.

    OpenOcesAPI is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

    OpenOcesAPI is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with OpenOcesAPI; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


    Note to developers:
    If you add code to this file, please take a minute to add an additional
    @author statement below.
*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.exceptions;
using CertificateStatus=org.openoces.ooapi.certificate.CertificateStatus;
using X509Certificate=Org.BouncyCastle.X509.X509Certificate;
using Org.BouncyCastle.Asn1.X509;

namespace org.openoces.ooapi.utils.ocsp
{
    class ResponseParser
    {
        public static bool CertificateIsValid(CertID id, OcspResp ocspResp, IOcesCertificate certificate)
        {            
            return CertificateIsValid(id, ocspResp, SerialNumberConverter.FromCertificate(certificate), certificate.IssuingCa);
        }

        private static X509Certificate2[] CreateOcspCertificateChain(Ca ca)
        {
            var chain = new List<X509Certificate2> ();            
            while (ca != null)
            {
                chain.Add(ca.Certificate);
                ca = ca.IssuingCa;
            }
            return chain.ToArray();
        }

        static bool CertificateIsValid(CertID id, OcspResp ocspResp, string serialNumber, Ca ca)
        {
            CheckOcspResp(ocspResp);
            BasicOcspResp response = GetResponseObject(ocspResp);
            CheckValidityOfResponse(id, response, ca);

            return SerialNumberInResponseIsNotRevoked(response, serialNumber);
        }

        static void CheckOcspResp(OcspResp resp)
        {
            if (resp.Status != OcspRespStatus.Successful)
            {
                throw new OcspException("ocsp response status: " + resp.Status);
            }
        }

        static bool SerialNumberInResponseIsNotRevoked(BasicOcspResp response, string serialNumber)
        {
            var responseElements = new List<SingleResp>(response.Responses);
            return responseElements
                .Exists(r => r.GetCertStatus() == null &&
                             r.GetCertID().SerialNumber.ToString() == serialNumber);
        }

        static BasicOcspResp GetResponseObject(OcspResp ocspResp)
        {
            var response = (BasicOcspResp) ocspResp.GetResponseObject();
            if (response == null)
            {
                throw new OcspException("Did not return basic response");
            }
            return response;
        }

        static void CheckValidityOfResponse(CertID id, BasicOcspResp responseObject, Ca ca)
        {
            var inputStream = new MemoryStream(responseObject.GetEncoded());
            var asn1Sequence = (Asn1Sequence)new Asn1InputStream(inputStream).ReadObject();

            var response = BasicOcspResponse.GetInstance(asn1Sequence);

            var ocspChain = CreateOcspCertificateChain(ca); 
            if(ocspChain.Length == 0)
            {
                throw new OcspException("OCSP certificate chain is invalid");
            }
            var ocesOcspCertificate = OcesCertificateFactory.Instance.Generate(CompleteOcspChain(response, ocspChain));
            CheckBasicOcspResp(id, responseObject, ocesOcspCertificate, ca);

            var signingCertificate = new X509CertificateParser().ReadCertificate(response.Certs[0].GetEncoded()); 
            var issuingCertificate = new X509CertificateParser().ReadCertificate(ocspChain[0].GetRawCertData());
            signingCertificate.Verify(issuingCertificate.GetPublicKey());
            if (!responseObject.Verify(signingCertificate.GetPublicKey()))
            {
                throw new OcspException("Signature is invalid");
            }
        }

        private static List<X509Certificate2> CompleteOcspChain(BasicOcspResponse ocspResponse, IEnumerable<X509Certificate2> ocspChain)
        {
            var ocspCertificate = new X509Certificate2(ocspResponse.Certs[0].GetEncoded());
            return new List<X509Certificate2>(ocspChain) {ocspCertificate};
        }

        private static void CheckBasicOcspResp(CertID id, BasicOcspResp basicResp, OcesCertificate ocspCertificate, Ca ca)
        {
            DateTime nowInGmt = DateTime.Now.ToUniversalTime();

            /* check condition:
                 The certificate identified in a received response corresponds to
                 that which was identified in the corresponding request;
             */
            SingleResp[] responses = basicResp.Responses;
            if (responses.Length != 1)
            {
                throw new OcspException("unexpected number of responses received");
            }

            if (!id.SerialNumber.Value.Equals(responses[0].GetCertID().SerialNumber))
            {
                throw new OcspException("Serial number mismatch problem");
            }

            /* check condition
               The signature on the response is valid;
            */
            try
            {
                ChainVerifier.VerifyTrust(ocspCertificate.ExportCertificate(), ca);
            }
            catch(ChainVerificationException e)
            {
                throw new OcspException("OCSP response certificate chain is invalid", e);
            }

            /* check the signature on the ocsp response */
            var ocspBcCertificate =
                new X509CertificateParser().ReadCertificate(ocspCertificate.ExportCertificate().RawData);
            if (!basicResp.Verify(ocspBcCertificate.GetPublicKey()))
            {
                throw new OcspException("signature validation failed for ocsp response");
            }

            if (!CanSignOcspResponses(ocspBcCertificate))
            {
                throw new OcspException("ocsp signing certificate has not been cleared for ocsp response signing");
            }

            /* check expiry of the signing certificate */
            if (ocspCertificate.ValidityStatus() != CertificateStatus.Valid)
            {
                throw new OcspException("OCSP certificate expired or not yet valid");
            }

            /* check condition
               The time at which the status being indicated is known to be
               correct (thisUpdate) is sufficiently recent.
            */
            SingleResp response = responses[0];

            var diff = response.ThisUpdate - nowInGmt;
            if (diff > new TimeSpan(0, 1, 0))
            {
                throw new OcspException("OCSP response signature is from the future. Timestamp of thisUpdate field: "
                                        + response.ThisUpdate);
            }

            if (response.NextUpdate != null && response.NextUpdate.Value < nowInGmt)
            {
                throw new OcspException("OCSP response is no longer valid");
            }
        }

        static bool CanSignOcspResponses(X509Certificate ocspCertificate)
        {
            return ocspCertificate.GetExtendedKeyUsage().Contains(KeyPurposeID.IdKPOcspSigning.Id);
        }

    }
}
