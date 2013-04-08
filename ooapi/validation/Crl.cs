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
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.exceptions;

namespace org.openoces.ooapi.validation
{
    /// <summary>
    /// Models a Certificate Revocation List (CRL).
    /// </summary>
    public class Crl
    {
        readonly X509Crl _crl;
        TimeService _timeService = new CurrentTimeTimeService();

        protected Crl()
        {
            // For testing purposes
        }

        public Crl(byte[] crlBytes)
        {
            _crl = new X509CrlParser().ReadCrl(crlBytes);
            try
            {
                _crl.GetSignature();
            }
            catch (Exception)
            {
                throw new InvalidOperationException("Error parsing CRL");
               
            }
            
        }

        /// <summary>
        /// Returns <code>true</code> if the given certificate is revoked and false otherwise 
        /// </summary>
        /// <param name="certificate">certificate certificate to check for revocation</param>
        /// <returns><code>true</code> if the given certificate is revoked and false otherwise 
        /// including if this CRL has expired.</returns>
        /// <throws>InvalidOperationException if this CRL is not valid or is not signed by the certificate's issuing CA.</throws>
        public bool IsRevoked(IOcesCertificate certificate)
        {
            try {
                VerifyCrl(certificate.IssuingCa.Certificate);
            }
            catch (SignatureException e)
            {
                throw new InvalidSignatureException("CRL Issued by" + _crl.IssuerDN
                                                    + " does not have valid signature by certificate's issuer certificate "
                                                    + certificate.IssuingCa.Certificate.SubjectName.Name, e);
            }

            return IsRevoked(certificate.ExportCertificate());
        }       

        internal bool IsRevoked(Ca ca)
        {
            if (ca.IsRoot)
            {
                throw new InvalidOperationException("Cannot check revocation for root CA");
            }

            try {
                VerifyCrl(ca.IssuingCa.Certificate);
            }
            catch (SignatureException e)
            {
                throw new InvalidSignatureException("CRL Issued by" + _crl.IssuerDN
                                                    + " does not have valid signature by ca's issuer certificate "
                                                    + ca.IssuingCa.Certificate.SubjectName.Name, e);
            }
            return IsRevoked(ca.Certificate);
        }

        private bool IsRevoked(X509Certificate2 certificate)
        {
            AssertCrlCurrentlyValid();
            AssertCrlIssuedByCertificateIssuer(certificate);

            var bcCert = new X509CertificateParser().ReadCertificate(certificate.RawData);
            return _crl.IsRevoked(bcCert);
        }

        private void AssertCrlIssuedByCertificateIssuer(X509Certificate2 certificate)
        {
            var certiticateIssuerName = new X509Name(certificate.IssuerName.Name);
            if (!_crl.IssuerDN.Equivalent(certiticateIssuerName))
            {
                throw new InvalidOperationException("CRL is not issued by the certificate's issuing CA. CRL is issued by: "
                    + _crl.IssuerDN + ", certificate is issued by: " + certiticateIssuerName);
            }
        }

        public virtual bool IsCrlExpired()
        {
            AssertCrlNotBeforeValidity();
            try
            {
                AssertCrlNotExpired();
            }
            catch (InvalidOperationException)
            {
                return true;
            }

            return false;
        }


        private void AssertCrlCurrentlyValid()
        {
            AssertCrlNotExpired();
            AssertCrlNotBeforeValidity();
        }

        private void AssertCrlNotBeforeValidity()
        {
            DateTime now = _timeService.GetTime();
            if (now < _crl.ThisUpdate)
            {
                throw new CrlNotYetValidException("CRL is not yet valid, crl is valid from " + _crl.ThisUpdate);
            }
        }

        private void AssertCrlNotExpired()
        {
            DateTime now = _timeService.GetTime();
            if (now > _crl.NextUpdate.Value)
            {
                throw new CrlExpiredException("CRL is expired, crl is valid to " + _crl.NextUpdate);
            }
        }

        public bool IsValid
        {
            get { return !IsCrlExpired(); }
        }

        private void VerifyCrl(X509Certificate2 certificate)
        {
            var bcIssuingCaCert = new X509CertificateParser().ReadCertificate(certificate.RawData);
            
            try
            {
                _crl.Verify(bcIssuingCaCert.GetPublicKey());
            }
            catch (SignatureException e)
            {
                throw new InvalidSignatureException("CRL Issued by" + _crl.IssuerDN
                                                    + " does not have valid signature by certificate's issuer certificate "
                                                    + certificate.IssuerName, e);
            }
        }

        public virtual bool IsPartial()
        {
            return _crl.GetExtensionValue(new DerObjectIdentifier(ObjectIdentifiers.PartialDistributionPointOid)) != null;
        }

        public bool IsCorrectPartialCrl(string crlLdapUrl)
        {
            string distributionPointInfo = Encoding.ASCII.GetString(_crl.GetExtensionValue(new DerObjectIdentifier(ObjectIdentifiers.PartialDistributionPointOid)).GetDerEncoded()).ToLower();
            if (distributionPointInfo == null)
            {
                return false;
            }
            string partialCrlNumber = GetCrlNumberFromPartitionCrlUrl(crlLdapUrl);
            return distributionPointInfo.Contains(partialCrlNumber);
        }

        private string GetCrlNumberFromPartitionCrlUrl(string crlUrl)
        {
            string[] crlUrlSplit = crlUrl.ToLower().Split(Convert.ToChar(","));
            if (crlUrlSplit == null || crlUrlSplit.Length < 1) throw new InvalidCrlException("the crl url is malformed" + crlUrl);
            string crlNumber = crlUrlSplit[0];
            if (crlNumber.Length < "cn=crl".Length) throw new InvalidCrlException("The DN is not of expected format." + crlUrl);
            return crlNumber.Substring("cn=".Length);
        }

        protected internal void SetTimeservice(TimeService service)
        {
            _timeService = service;
        }

        private class CurrentTimeTimeService : TimeService
        {
            public DateTime GetTime()
            {
                return DateTime.Now;
            }
        }

    }
}