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
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.exceptions;

namespace org.openoces.ooapi.validation
{
    public class FullCrlRevocationChecker : ICaCrlRevokedChecker
    {
        static readonly FullCrlRevocationChecker OurInstance = new FullCrlRevocationChecker();
        readonly HttpCrlDownloader _crlDownloader = new CachedHttpCrlDownloader();

        FullCrlRevocationChecker() { 
            _crlDownloader = new CachedHttpCrlDownloader();
        }
 	 
        internal FullCrlRevocationChecker(HttpCrlDownloader crlDownloader) {
            _crlDownloader = crlDownloader;
        } 


        /// <summary>
        /// The <code>FullCrlRevocationChecker</code> instance.
        /// </summary>
        public static FullCrlRevocationChecker Instance { get { return OurInstance; } }

        public bool IsRevoked(IOcesCertificate certificate)
        {
            Crl crl = DownloadCrl(certificate);
            return crl.IsRevoked(certificate) || IsRevoked(certificate.IssuingCa);
        }

        public bool IsRevoked(Ca ca)
        {
            if (ca.IsRoot)
            {
                return false;
            }
            return DownloadCrl(ca).IsRevoked(ca) || IsRevoked(ca.IssuingCa);
        }

        /// <summary>
        /// Downloads the full CRL for the given certificate.
        /// </summary>
        /// <param name="certificate">certificate to download full CRL for</param>
        /// <returns>full CRL for given certificate</returns>
        public Crl DownloadCrl(IOcesCertificate certificate)
        {
            string crlDistributionPoint = certificate.CrlDistributionPoint;
            return DownloadCrl(crlDistributionPoint);
        }

        public Crl DownloadCrl(string crlDistributionPoint)
        {
            var crl = _crlDownloader.Download(crlDistributionPoint);
            if (crl.IsPartial())
            {
                throw new InvalidCrlException("Crl was downloaded successfully, but is not a partial CRL, not a full CRL" + crlDistributionPoint);
            }
            return crl;
        }

        Crl DownloadCrl(Ca ca)
        {
            string crlDistributionPoint = CrlDistributionPointsExtractor.ExtractCrlDistributionPoints(ca.Certificate).CrlDistributionPoint;
            return DownloadCrl(crlDistributionPoint);
        }
    }
}
