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
using org.openoces.ooapi.certificate;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.signatures;
using org.openoces.ooapi.validation;
using org.openoces.serviceprovider;

namespace org.openoces.securitypackage
{
    /// <summary>
    /// This class handles validation and extraction of person ID from the output data provided by the Open Logon applet.
    /// </summary>
    public class LogonHandler
    {
        /// <summary>
        /// Given the output data from the Open Logon applet, the person ID (pid) is extracted if the login data is valid.
        /// </summary>
        /// <param name="loginData">the output data from the Open Logon applet.</param>
        /// <param name="challenge">the challenge applet parameter.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended).</param>
        /// <returns>the pid of the certificate that is used for logging in. Only valid pids are returned.</returns>
        /// <throws>ServiceProviderException in case that no pid can be extracted from the data provided.</throws>
        /// <throws>AppletException in case the applet returned an error code.</throws>
        public static PersonId ValidateAndExtractPid(string loginData, string challenge, string logonto)
        {
            var certAndStatus = ValidateAndExtractCertificateAndStatus(loginData, challenge, logonto);
            if (certAndStatus.CertificateStatus == CertificateStatus.Valid)
            {
                var pocesCertificate = ((PocesCertificate)certAndStatus.Certificate);
                return new PersonId(pocesCertificate.Pid);
            }

            throw new NonOcesCertificateException("certificate is invalid. Status: " + certAndStatus.CertificateStatus);
        }

        /// <summary>
        /// Given the output data from the Open Logon applet, the certificate is extracted if the login data is valid.
        /// NB! The validity of the certificate is *NOT* checked 
        /// (i.e. it is not checked if the certificate is valid, invalid, revoked, not yet valid or expired) 
        /// </summary>
        /// <param name="loginData">the output data from the Open Logon applet.</param>
        /// <param name="challenge">the challenge applet parameter.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended).</param>
        /// <returns>the certificate that is used for logging in.</returns>
        public static OcesCertificate ValidateSignatureAndExtractCertificate(string loginData, string challenge, string logonto)
        {
            var signature = CreateOpenlogonSignature(loginData);
            ValidateSignatureParameters(signature, challenge, logonto); 
            if (signature.Verify())
            {
                return signature.SigningCertificate;
            }

            throw new NonOcesCertificateException("the signature of the login data is invalid, data is " + loginData);
        }

        /// <summary>
        /// Given the output data from the Open Logon applet, the certificate extracted if the login data is valid. 
        /// The status of the certificate is checked and a the certificate and its status is returned wrapped in a 
        /// CertificateStatus instance.
        /// </summary>
        /// <param name="loginData">the output data from the Open Logon applet.</param>
        /// <param name="challenge">the challenge applet parameter.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended).</param>
        /// <returns>the certificate that is used for logging in and the status of this certificate (wrapped in a CertificateStatus instance)</returns>
        public static CertificateAndStatus ValidateAndExtractCertificateAndStatus(string loginData, string challenge, string logonto)
        {
            var signature = CreateOpenlogonSignature(loginData);
            ValidateSignatureParameters(signature, challenge, logonto);

            if (signature.Verify())
            {
                var certificate = signature.SigningCertificate;
                var status = certificate.ValidityStatus();

                if (status == CertificateStatus.Valid && ServiceProviderSetup.CurrentChecker.IsRevoked(certificate))
                {
                    status = CertificateStatus.Revoked;
                }
                return new CertificateAndStatus(certificate, status);
            }
    
            throw new NonOcesCertificateException("the signature of the login data is invalid. Data is " + loginData);
        }

        private static OpenlogonSignature CreateOpenlogonSignature(string loginData)
        {
            var errorCodeChecker = new ErrorCodeChecker(loginData);
            if (errorCodeChecker.HasError())
            {
                throw new AppletException(errorCodeChecker.ExtractError());
            }
            var abstractSignature =
                OpensignSignatureFactory.Instance.GenerateOpensignSignature(loginData);
            if (!(abstractSignature is OpenlogonSignature))
            {
                throw new ArgumentException("argument of type " + abstractSignature.GetType() +
                                            " is not valid output from the logon applet");
            }
            var signature = (OpenlogonSignature)abstractSignature;
            return signature;
        }

        private static void ValidateSignatureParameters(OpenlogonSignature signature, string challenge, string logonto)
        {
            ValidateChallenge(signature, challenge);
            if (logonto != null)
            {
                ValidateLogonto(signature, logonto);
            }
        }

        private static void ValidateChallenge(OpenlogonSignature signature, string challenge)
        {
            ChallengeVerifier.VerifyChallenge(signature, challenge);
        }

        private static void ValidateLogonto(OpenlogonSignature signature, string logonto)
        {
            SignatureProperty logontoProperty = GetSignatureProperty(signature, "logonto");
            SignatureProperty requestIssuerProperty = GetSignatureProperty(signature, "RequestIssuer");

            if (logontoProperty != null && requestIssuerProperty != null)
            {
                throw new InvalidOperationException("Invalid signature logonto and RequestIssuer parameters cannot both be set");
            }

            if (logontoProperty == null && requestIssuerProperty == null)
            {
                throw new InvalidOperationException("Invalid signature either logonto or RequestIssuer parameters must be set");
            }

            if (logontoProperty != null)
            {
                String logontoPropertyValue = logontoProperty.Value;
                if (logontoPropertyValue != logonto)
                {
                    throw new ServiceProviderException("Invalid signature logonto parameter does not match expected value. Expected: "
                            + logonto + " actual: " + logontoPropertyValue);
                }
            }

            if (requestIssuerProperty != null)
            {
                String requestIssuerValue = requestIssuerProperty.Value;
                if (requestIssuerValue != logonto)
                {
                    throw new ServiceProviderException("Invalid signature RequestIssuer parameter does not match expected value. Expected: "
                            + logonto + " actual: " + requestIssuerValue);
                }
            }
        }

        private static SignatureProperty GetSignatureProperty(OpenlogonSignature signature, string propertyKey)
        {
            try
            {
                return signature.SignatureProperties[propertyKey];
            } 
            catch (KeyNotFoundException)
            {
                return null;
            }
        }
    }
}