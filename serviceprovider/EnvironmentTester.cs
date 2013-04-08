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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.utils;
using org.openoces.ooapi.validation;

namespace org.openoces.serviceprovider
{
    /// <summary>
    /// Use the Main method of this Class to test if the Environment has been setup correctly. 
    /// </summary>
    public class EnvironmentTester
    {
        static readonly Dictionary<string, OcesEnvironment> EnvDictionary = CreateEnvDictionary();

        /// <summary>
        /// Tests if the environment has been setup correctly.
        /// </summary>
        /// <param name="args">none - reacts on user input</param>
        public static void Main(string[] args)
        {
            PrintLine("OOAPI environment tester\n---------------------------\n");
            PrintLine("Tjensteudbyder / service provider choose 9 for test !");
            PrintEnviromentList();
            Enviroment = Prompt();


            if (AskYesNo("Ping LDAP?"))
            {
                PingLdap();
            }

            if (AskYesNo("Ping PID service?"))
            {
                PingPid();
            }

            if (AskYesNo("Ping RID service?"))
            {
                PingRid();
            }

            X509Certificate2 cert = null;
            if (AskYesNo("Ping OCSP service?"))
            {
                cert = FindCertificateToUse();
                if (cert != null)
                {
                    PingOcsp(cert);
                }
                
            }

            if (AskYesNo("Ping CRL service?"))
            {
                if(cert == null)
                    cert = FindCertificateToUse();
                
                if (cert != null)
                {
                    PingCrls(cert);
                }
                
            }

            PrintLine("\n\n---------------------------\n");
            
        }

        static X509Certificate2 FindCertificateToUse()
        {
            PrintLine("\n\n Enter path to certificate\n");
            var pathToCertificate = Prompt();
            PrintLine("\n\n Enter password to certificate (default Test1234)\n");
            var certPassword = Prompt();
            if (!File.Exists(pathToCertificate) || !Path.HasExtension(pathToCertificate))
            {
                PrintLine("\nCould not find valid certificate\n");
                return null;
            }

            return new X509Certificate2(pathToCertificate, certPassword);
            
        }

        static Dictionary<string, OcesEnvironment> CreateEnvDictionary()
        {
            var ocesEnvironments = new Dictionary<string, OcesEnvironment>
                                       {
                                           {"1", OcesEnvironment.OcesIDanidEnvDevelopment},
                                           {"2", OcesEnvironment.OcesIDanidEnvProd},
                                           {"3", OcesEnvironment.OcesIDanidEnvSystemtest},
                                           {"4", OcesEnvironment.OcesIiDanidEnvDevelopment},
                                           {"5", OcesEnvironment.OcesIiDanidEnvDevelopmenttest},
                                           {"6", OcesEnvironment.OcesIiDanidEnvExternaltest},
                                           {"7", OcesEnvironment.OcesIiDanidEnvInternaltest},
                                           {"8", OcesEnvironment.OcesIiDanidEnvOperationstest},
                                           {"9", OcesEnvironment.OcesIiDanidEnvPreprod},
                                           {"10", OcesEnvironment.OcesIiDanidEnvProd}
                                       };
            return ocesEnvironments;
        }

        static void PrintEnviromentList()
        {
            Console.WriteLine("Set enviroment:\n");

            foreach (var key in EnvDictionary.Keys.OrderBy(k => int.Parse(k)))
            {
                Console.WriteLine(key + " = " + EnvDictionary[key]);
            }
        }

        static string Enviroment
        {
            set
            {
                var currentenv = EnvDictionary[value];
                Environments.OcesEnvironments = new[] { currentenv };
            }
        }

        static void PingLdap()
        {
            try
            {
                ConfigurationChecker.VerifyRootCertificateFromLdap();
                PrintLine("Success");
            }
            catch (Exception e)
            {
                Console.Write("Calling LDAP failed" + e.Message);
            }
        }

        static void PingPid()
        {
            try
            {
                ConfigurationChecker.VerifyPidService();
                PrintLine("Success");
            }
            catch (Exception e)
            {
                Console.Write("Calling PID service failed " + e.Message);
            }
        }

        static void PingRid()
        {
            try
            {
                ConfigurationChecker.VerifyRidService();
                PrintLine("Success");
            }
            catch (Exception e)
            {
                Console.Write("Calling PID service failed " + e.Message);
            }
        }

        static void PingCrls(X509Certificate2 certificate)
        {
            var extractCrlDistributionPoints = CrlDistributionPointsExtractor.ExtractCrlDistributionPoints(certificate);

            Crl crl = FullCrlRevocationChecker.Instance.DownloadCrl(extractCrlDistributionPoints.CrlDistributionPoint);
            if (crl.IsValid)
            {
                PrintLine("Success");
            }
            else
            {
                PrintLine("Invalid CRL retrieved");
            }

        }

        static string FindOcspUrlInCertificate(X509Certificate2 cert)
        {
            return X509CertificatePropertyExtrator.GetOcspUrl(cert);
        }

        static void PingOcsp(X509Certificate2 cert)
        {
            try
            {
                var ocspUrl = FindOcspUrlInCertificate(cert);
                if (ConfigurationChecker.CanCallOcsp(ocspUrl))
                {
                    PrintLine("Success");
                }
                else
                {
                    PrintLine("Could not call OCSP");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error calling OCSP");
                Console.WriteLine(e.StackTrace);
            }
        }

        static bool AskYesNo(string question)
        {
            PrintLine("\n\n" + question + "\n---------------------------\ny/n[n]");
            return Prompt() == "y";
        }

        static string Prompt()
        {
            Print("> ");
            return Console.ReadLine();
        }

        static void Print(string s)
        {
            Console.Write(s);
        }

        static void PrintLine(string line)
        {
            Console.WriteLine(line);
        }
    }
}
