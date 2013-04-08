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
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.utils;
using System;

namespace org.openoces.ooapi.certificate
{
    public class ChainVerifier
    {
        public static bool VerifyTrust(OcesCertificate certificate)
        {
            return VerifyTrust(certificate.ExportCertificate(), certificate.IssuingCa);
        }

        public static bool VerifyTrust(X509Certificate2 certificate, Ca signingCa)
        {
            var basicConstraints = X509CertificatePropertyExtrator.GetBasicConstraints(certificate);
            if (Verify(certificate, GetPublicKey(signingCa.Certificate)))
            {
                if (VerifyChain(signingCa, 0))
                {
                    return VerifyRoot(signingCa);
                }
            }
            return false;
        }

        private static bool VerifyChain(Ca ca, int pathLength)
        {
            var basicConstraints = X509CertificatePropertyExtrator.GetBasicConstraints(ca.Certificate);
            //check that CA certificate is in fact a CA
            if (!basicConstraints.CertificateAuthority)
            {
                return false;
            }

            //check that CA certificate must sign other certificates
            X509KeyUsageFlags flags = X509CertificatePropertyExtrator.GetKeyUsage(ca.Certificate).KeyUsages;
                        
            if((flags & (X509KeyUsageFlags.KeyCertSign))!=X509KeyUsageFlags.KeyCertSign)
            {
                return false;
            }
            
            
            // Check path length
            if (basicConstraints.HasPathLengthConstraint && basicConstraints.PathLengthConstraint < pathLength)
            {
                return false;
            }
            if (IsSelfSigned(ca) && !ca.IsRoot)
            {
                return false;
            }
            if (ca.IsRoot)
            {
                return true;
            }
            if (ca.IssuingCa == null)
            {
                return false;
            }
            Ca signingCa = ca.IssuingCa;
            if (X509CertificatePropertyExtrator.GetBasicConstraints(signingCa.Certificate).PathLengthConstraint >= 0)
            {
                if (Verify(ca.Certificate, GetPublicKey(signingCa.Certificate)))
                {
                    return VerifyChain(ca.IssuingCa, ++pathLength);
                }
            }
            return false;
        }

        private static bool IsSelfSigned(Ca ca)
        {
            return Verify(ca.Certificate, GetPublicKey(ca.Certificate));
        }

        static bool VerifyRoot(Ca ca)
        {
            if (ca.IsRoot)
            {
                var certificates = Environments.TrustedCertificates;
                foreach (var certificate in certificates)
                {
                    if (certificate.Equals(ca.Certificate))
                    {
                        return true;
                    }
                }
                return false;
            }
            return VerifyRoot(ca.IssuingCa);
        }

        private static bool Verify(X509Certificate2 certificate, AsymmetricKeyParameter publicKey)
        {
            try
            {
                var bcCertificate = new X509CertificateParser().ReadCertificate(certificate.RawData);
                bcCertificate.Verify(publicKey);
                return true;
            }
            catch (InvalidKeyException)
            {
                //ignore on purpose
            }
            catch (CertificateException)
            {
                //ignore on purpose
            }
            catch (SignatureException)
            {
                //ignore on purpose
            }
            return false;
        }

        private static AsymmetricKeyParameter GetPublicKey(X509Certificate2 certificate)
        {
            return new X509CertificateParser().ReadCertificate(certificate.RawData).GetPublicKey();
        }

        public static void main(String[] args)
        {
            
        }
    }

    
}
