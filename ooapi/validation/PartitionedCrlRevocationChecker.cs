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
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.exceptions;

namespace org.openoces.ooapi.validation
{
    /// <summary>
    /// <code>RevocationChecker</code> based on a partitioned CRL.
    /// </summary>
    public class PartitionedCrlRevocationChecker : IRevocationChecker
    {
        static readonly PartitionedCrlRevocationChecker OurInstance = new PartitionedCrlRevocationChecker();
        readonly CachedLdapCrlDownloader _crlDownloader = new CachedLdapCrlDownloader();

        PartitionedCrlRevocationChecker() { }

        public static PartitionedCrlRevocationChecker Instance { get { return OurInstance; } }

        /// <summary>
        /// The partitioned CRL to check for revocation is retrieved using LDAP.
        /// </summary>
        public bool IsRevoked(IOcesCertificate certificate)
        {
            string ldapPath = certificate.PartitionedCrlDistributionPoint;
            OcesEnvironment environment = RootCertificates.GetEnvironment(certificate.IssuingCa);

            Crl crl = _crlDownloader.Download(environment, ldapPath);

            if (!crl.IsPartial())
            {
                throw new InvalidCrlException("Crl was downloaded successfully, but is not a partial CRL:" + ldapPath);
            }
            if (!crl.IsCorrectPartialCrl(ldapPath))
            {
                throw new InvalidCrlException("Crl was downloaded successfully, but is not the correct partitioned crl:" + ldapPath);
            }


            return crl.IsRevoked(certificate) || IsRevoked(certificate.IssuingCa);
        }

        public bool IsRevoked(Ca ca)
        {
            if (ca.IsRoot)
            {
                return false;
            }
            OcesEnvironment environment = RootCertificates.GetEnvironment(ca.IssuingCa);
            return DownloadCrl(ca, environment).IsRevoked(ca) || IsRevoked(ca.IssuingCa);
        }

        Crl DownloadCrl(Ca ca, OcesEnvironment environment)
        {
            string crlDistributionPoint = CrlDistributionPointsExtractor.ExtractCrlDistributionPoints(ca.Certificate).PartitionedCrlDistributionPoint;
            return _crlDownloader.Download(environment, crlDistributionPoint);
        }
    }
}
