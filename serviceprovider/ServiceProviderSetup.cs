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
using org.openoces.ooapi.environment;
using org.openoces.ooapi.pidservice;
using org.openoces.ooapi.utils;
using org.openoces.ooapi.validation;

namespace org.openoces.serviceprovider
{
    /// <summary>
    /// High-level set-up of the environment. This class is used for setting the
    /// CRL revocation checker, the environment that the system is used in, and
    /// the certificate used to communicate with the PID service.
    /// 
    /// The default settings are:
    /// <list type="bullet">
    /// <item>Revocation checking is done using partitioned CRLs.</item>
    /// <item>The OCES-II production environment is used.</item>
    /// </list>
    /// </summary>
    public class ServiceProviderSetup
    {
        static IRevocationChecker _currentChecker = PartitionedCrlRevocationChecker.Instance;
        const string ServiceStringPrefix = "pid.service.url.";

        /// <summary>
        /// Instructs OOAPI to check revocation of certificates using OCSP.
        /// </summary>
        public static void SetOcspRevocationChecker()
        {
            _currentChecker = new OcspCertificateRevocationChecker();
        }

        /// <summary>
        /// Instructs OOAPI to check revocation of certificates by downloading
        /// the full CRL.
        /// </summary>
        public static void SetFullCrlRevocationChecker()
        {
            _currentChecker = FullCrlRevocationChecker.Instance;
        }

        /// <summary>
        /// Instructs OOAPI to check revocation of certificates by downloading
        /// partial CRLs. This is the default.
        /// </summary>
        public static void SetPartitionedCrlRevocationChecker()
        {
            _currentChecker = PartitionedCrlRevocationChecker.Instance;
        }

        /// <summary>
        /// Gets the current checker.
        /// </summary>
        public static IRevocationChecker CurrentChecker
        {
            get { return _currentChecker; }
        }

        /// <summary>
        /// Sets the environment to OCES-II production. This is the default.
        /// </summary>
        public static void SetEnvironmentToOcesIiProduction()
        {
            Environments.OcesEnvironments = new[] { OcesEnvironment.OcesIiDanidEnvProd };
        }

        //sets the environment to OCES-II pre production / test
        public static void SetEnvironmentToOcesIiPreProd()
        {
            Environments.OcesEnvironments = new[] { OcesEnvironment.OcesIiDanidEnvPreprod };
        }

        /// <summary>
        /// Sets the environment to OCES-II external test.
        /// </summary>
        public static void SetEnvironmentToOcesIiExternalTest()
        {
            Environments.OcesEnvironments = new[] { OcesEnvironment.OcesIiDanidEnvExternaltest };
        }

        /// <summary>
        /// Creates a new <see cref="PidService">PID service client</see> for the
        /// current environment.
        /// </summary>
        public static PidService CreatePidServiceClient()
        {
            var wsUrl = Properties.Get(ServiceStringPrefix + Environments.TrustedEnvironments.First());
            return new PidService(wsUrl);
        }
    }
}
