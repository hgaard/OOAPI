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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using NLog;

namespace org.openoces.ooapi.environment
{
    /// <summary>
    /// Defines the supported OCESI and OCESII test and production environments
    /// </summary>
    public class Environments
    {
        static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        protected static bool HasBeenSet;
        protected static IEnumerable<OcesEnvironment> TheTrustedEnvironments = new[] { OcesEnvironment.OcesIiDanidEnvProd };

        /// <summary>
        /// Sets the environments that must be supported in this execution context.
        /// The list of environments that must be supported can only be set once in a specific execution context.
        /// </summary>
        public static IEnumerable<OcesEnvironment> OcesEnvironments
        {
            set
            {
                lock (typeof(Environments))
                {
                    if (HasBeenSet)
                    {
                        throw new InvalidOperationException("Environments cannot be set twice.");
                    }
                    if (value == null)
                    {
                        throw new ArgumentException("Environments cannot be null");
                    }
                    if (value.Count() == 0)
                    {
                        Logger.Warn("No environments are trusted. This can cause all sorts of problems.");
                    }
                    foreach (var environment in value)
                    {
                        if (!RootCertificates.HasCertificate(environment))
                        {
                            throw new ArgumentException("No root certificate for environment: " + environment);
                        }
                    }
                    int numberOfProductionEnvironments = CountNumberOfProductionEnvironments(value);
                    if (numberOfProductionEnvironments > 0 && numberOfProductionEnvironments != value.Count())
                    {
                        throw new ArgumentException("Production environments cannot be mixed with test environments.");
                    }

                    HasBeenSet = true;
                    TheTrustedEnvironments = value;
                }
            }
        }

        private static int CountNumberOfProductionEnvironments(IEnumerable<OcesEnvironment> environments)
        {
            int numberOfProductionEnvironments = 0;
            foreach (var e in environments)
            {
                if (OcesEnvironment.OcesIDanidEnvProd == e || OcesEnvironment.OcesIiDanidEnvProd == e)
                {
                    numberOfProductionEnvironments++;
                }
            }
            return numberOfProductionEnvironments;
        }

        /// <summary>
        /// Gets list of <code>X509Certificate</code>s of the CAs that are currently trusted.
        /// </summary>
        public static IEnumerable<X509Certificate2> TrustedCertificates
        {
            get
            {
                return from environment in TheTrustedEnvironments
                       select RootCertificates.LookupCertificate(environment);
            }
        }

        /// <summary>
        /// Gets the trusted environments. An empty set is
        /// returned if no environments are trusted or if the
        /// set of trusted environments has not yet been set.
        /// </summary>
        public static IEnumerable<OcesEnvironment> TrustedEnvironments
        {
            get { return new List<OcesEnvironment>(TheTrustedEnvironments); }
        }
    }
}
