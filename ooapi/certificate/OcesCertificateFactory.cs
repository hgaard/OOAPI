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
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.certificate
{
    /// <summary>
    /// Factory able to create an <code>OcesCertificate</code>. 
    /// </summary>
    public class OcesCertificateFactory
    {
        static readonly OcesCertificateFactory TheInstance = new OcesCertificateFactory();

        OcesCertificateFactory()
        {
        }

        /// <summary>
        /// Gives the singleton instance.
        /// </summary>
        public static OcesCertificateFactory Instance
        {
            get { return TheInstance; }
        }

        /// <summary>
        ///  Generates an <code>OcesCertificate</code>. The returned <code>OcesCertificate</code> is the end user certificate, which has a parent relation 
        ///  to the certificate of its issuing CA which again can have a parent relation to the certificate of the root CA. 
        ///  The root CA has no parent relation.
        ///  
        /// The factory verifies that each certificate in the certificate chain has been signed by its issuing CA.
        /// </summary>
        /// <param name="certificates">List of certificates to create OcesCertificate chain from.</param>
        /// <returns><code>OcesCertificate</code> with parent relation to (chain of) issuing CAs. Depending on the Subject DN in the 
        /// certificate a <code>PocesCertificate</code>, <code>MocesCertificate</code>, <code>VocesCertificate</code>, or <code>FocesCertificate</code> will be created.</returns>
        ///  <exception cref="org.openoces.ooapi.exceptions.TrustCouldNotBeVerifiedException">when a OcesCertificate in the chain cannot be trusted, i.e. has not been signed by its issuing CA.</exception>
        public OcesCertificate Generate(List<X509Certificate2> certificates)
        {
            certificates = SortCertificatesIssuerLast(certificates);
            AddIssuerCertificateIfNeeded(certificates);
            ValidateExactlyOneChainInList(certificates);
            AppendRootIfMissing(certificates);
            X509Certificate2 endUserCertificate = certificates[0];
            Ca signingCa = CreateCaChain(certificates);
            string subjectSerialNumber = ExtractSubjectSerialNumber(endUserCertificate);
            OcesCertificate certificate = SelectCertificateSubclass(subjectSerialNumber, signingCa, endUserCertificate);
            if(ChainVerifier.VerifyTrust(certificate))
            {
                return certificate;
            }
            throw new TrustCouldNotBeVerifiedException(certificate, Environments.TrustedEnvironments);
        }

        static void AddIssuerCertificateIfNeeded(IList<X509Certificate2> certificates)
        {
            if (certificates.Count == 1)
            {
                var certificate = certificates[0];
                if (certificate.Issuer.ToUpper().Contains("TRUST2408"))
                {
                    var url = X509CertificatePropertyExtrator.GetCaIssuerUrl(certificate);
                    var icaCertificate = new X509Certificate2(HttpClient.Download(url));
                    certificates.Add(icaCertificate);
                }
            }
        }


        static void ValidateExactlyOneChainInList(IList<X509Certificate2> certificates)
        {
            if (certificates.Count == 0)
            {
                throw new ArgumentException("Did not find any certificates");
            }

            for (var i = 0; i < certificates.Count - 1; i++)
            {
                var issuer = certificates[i].Issuer;
                var nextSubject = certificates[i + 1].Subject;
                if (issuer != nextSubject)
                {
                    throw new InvalidChainException("Certificate list holds something that is not a certificate chain");
                }
            }
        }

        /// <summary>
        /// Find all certificates that are not self-signed and has key usage "digital signature".
        /// Then sort all certificates, so that issuers are after the certificates they sign.
        /// Certificates in the list that were not part of the trust chain for the digital signatures are not retained.
        /// </summary>
        /// <returns>sorted certificates needed to verify the digital signatures from the input list</returns>
        static List<X509Certificate2> SortCertificatesIssuerLast(IEnumerable<X509Certificate2> inputCertificates)
        {
            var result = new List<X509Certificate2>();
            var certBySubject = new Dictionary<string, X509Certificate2>();

            foreach (var certificate in inputCertificates)
            {
                certBySubject[certificate.Subject] = certificate;
                var keyUsage = X509CertificatePropertyExtrator.GetKeyUsage(certificate);
                if (keyUsage != null && keyUsage.KeyUsages.ToString().Contains("DigitalSignature") &&
                    !keyUsage.KeyUsages.ToString().Contains("CrlSign"))
                {
                    result.Add(certificate);
                }
            }
            for (var i = 0; i < result.Count; i++)
            {
                var certificate = result[i];
                if (!certBySubject.ContainsKey(certificate.Issuer)) continue;

                var issuer = certBySubject[result[i].Issuer];
                if (!result.Contains(issuer))
                {
                    result.Add(issuer);
                }
            }
            return result;
        }

        static string ExtractSubjectSerialNumber(X509Certificate2 endUserCertificate)
        {
            var subject = endUserCertificate.Subject;
            const string subjectSerialNumberPattern = @"((OID.2.5.4.5)|(?i:serialnumber))(\s)*=(\s)*(?<ssn>([^+,\s])*)";

            var ssn = new Regex(subjectSerialNumberPattern);
            if (!ssn.IsMatch(subject))
            {
                throw new NonOcesCertificateException("Could not find subject serial number");
            }
            var match = ssn.Match(subject);
            return match.Groups["ssn"].Value;
        }

        static OcesCertificate SelectCertificateSubclass(String subjectSerialNumber, Ca signingCa, X509Certificate2 endUserCertificate)
        {
            var currentEnv = GetEnvironmentForRoot(signingCa);
            if (subjectSerialNumber.StartsWith("PID:") && MatchPocesPolicy(endUserCertificate, currentEnv))
            {
                return new PocesCertificate(endUserCertificate, signingCa);
            }
            const int lengthOfCvrXxxxxxxx = 12;
            if (subjectSerialNumber.StartsWith("CVR:") &&
                subjectSerialNumber.Substring(lengthOfCvrXxxxxxxx).StartsWith("-RID:") && MatchMocesPolicy(endUserCertificate, currentEnv))
            {
                return new MocesCertificate(endUserCertificate, signingCa);
            }
            if (subjectSerialNumber.StartsWith("CVR:") &&
                subjectSerialNumber.Substring(lengthOfCvrXxxxxxxx).StartsWith("-UID:") && MatchVocesPolicy(endUserCertificate, currentEnv))
            {
                return new VocesCertificate(endUserCertificate, signingCa);
            }
            if (subjectSerialNumber.StartsWith("CVR:") &&
                subjectSerialNumber.Substring(lengthOfCvrXxxxxxxx).StartsWith("-FID:") && MatchFocesPolicy(endUserCertificate, currentEnv))
            {
                return new FocesCertificate(endUserCertificate, signingCa);
            }
            throw new NonOcesCertificateException("End user certificate is not POCES, MOCES, VOCES og FOCES");
        }

        private static bool MatchFocesPolicy(X509Certificate2 endUserCertificate, OcesEnvironment currentEnv)
        {
            if (OcesEnvironment.OcesIDanidEnvDevelopment.Equals(currentEnv) || OcesEnvironment.OcesIDanidEnvSystemtest.Equals(currentEnv))
            {
                return true; // we do not validate OCES1 dev and systemtest.
            }
            return MatchPolicy(endUserCertificate, Properties.Get("foces.policies.prefix.danid." + currentEnv));
        }

        private static bool MatchVocesPolicy(X509Certificate2 endUserCertificate, OcesEnvironment currentEnv)
        {
            if (OcesEnvironment.OcesIDanidEnvDevelopment.Equals(currentEnv) || OcesEnvironment.OcesIDanidEnvSystemtest.Equals(currentEnv))
            {
                return true; // we do not validate OCES1 dev and systemtest.
            }
            return MatchPolicy(endUserCertificate, Properties.Get("voces.policies.prefix.danid." + currentEnv));
        }

        private static bool MatchMocesPolicy(X509Certificate2 endUserCertificate, OcesEnvironment currentEnv)
        {
            if (OcesEnvironment.OcesIDanidEnvDevelopment.Equals(currentEnv) || OcesEnvironment.OcesIDanidEnvSystemtest.Equals(currentEnv) || OcesEnvironment.CampusIDanidEnvProd.Equals(currentEnv))
            {
                return true; // we do not validate OCES1 dev and systemtest.
            }
            return MatchPolicy(endUserCertificate, Properties.Get("moces.policies.prefix.danid." + currentEnv));
        }

        private static bool MatchPocesPolicy(X509Certificate2 endUserCertificate, OcesEnvironment currentEnv)
        {
            if (OcesEnvironment.OcesIDanidEnvDevelopment.Equals(currentEnv) || OcesEnvironment.OcesIDanidEnvSystemtest.Equals(currentEnv))
            {
                return true; // we do not validate OCES1 dev and systemtest.
            }
            if (OcesEnvironment.OcesIiDanidEnvPreprod.Equals(currentEnv))
            {
                return true; // we do not validate OCES2 preprod as external partners might have older certificates not satisfying this.
            }
            return MatchPolicy(endUserCertificate, Properties.Get("poces.policies.prefix.danid." + currentEnv));
        }

        private static bool MatchPolicy(X509Certificate2 endUserCertificate, string oidPrefix)
        {
            return X509CertificatePropertyExtrator.GetCertificatePolicyOid(endUserCertificate).StartsWith(oidPrefix);
        }

        private static OcesEnvironment GetEnvironmentForRoot(Ca ca)
        {
            if (!ca.IsRoot)
            {
                return GetEnvironmentForRoot(ca.IssuingCa);
            }
            return RootCertificates.GetEnvironment(ca);
        }

        static Ca CreateCaChain(IList<X509Certificate2> certificates)
        {
            Ca parent = null;
            for (int i = certificates.Count - 1; i > 0; i--)
            {
                parent = new Ca(certificates[i], parent);
            }
            return parent;
        }

        static void AppendRootIfMissing(IList<X509Certificate2> certificates)
        {
            if (certificates.Count == 0) return;
            var last = certificates[certificates.Count - 1];
            if (!IsSelfSigned(last))
            {
                certificates.Add(RootCertificates.LookupCertificateBySubjectDn(last.IssuerName));
            }
        }

        static bool IsSelfSigned(X509Certificate2 certificate)
        {
            try
            {
                var bcCertificate = new X509CertificateParser().ReadCertificate(certificate.RawData);
                bcCertificate.Verify(bcCertificate.GetPublicKey());
                return true;
            }
            catch (InvalidKeyException)
            {
            }
            catch (CertificateException)
            {
            }
            catch (SignatureException)
            {
            }
            return false;
        }
    }
}
