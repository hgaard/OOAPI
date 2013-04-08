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
using System.Linq;
using NLog;
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.validation
{
    public class OcspCertificateRevocationChecker : IRevocationChecker
    {
        static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public bool IsRevoked(IOcesCertificate certificate)
        {
            return IsIssuingCaRevoked(certificate) || IsCertificateRevoked(certificate);
        }

        static bool IsCertificateRevoked(IOcesCertificate certificate)
        {
            if (Environments.TrustedEnvironments.Contains(OcesEnvironment.OcesIDanidEnvDevelopment))
            {
                /* OCSP checking is not supported in this environment - since this is a test environment, we assume
                   the certificate is *not* revoked */
                Logger.Info("OCSP checking is not supported in this environment. Assuming certificate is not revoked");
                return false;
            }
            return !OcspClient.IsValid(certificate);
        }

        static bool IsIssuingCaRevoked(IOcesCertificate certificate)
        {
            return FullCrlRevocationChecker.Instance.IsRevoked(certificate.IssuingCa);
        }
    }
}
