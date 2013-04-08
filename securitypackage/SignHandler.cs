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
using System.Text;
using System.Collections.Generic;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.signatures;
using org.openoces.ooapi.validation;
using org.openoces.serviceprovider;
using org.openoces.ooapi.certificate;
using Org.BouncyCastle.Crypto.Digests;


namespace org.openoces.securitypackage
{
    /// <summary>
    /// This class handles validation and extraction of person ID from the output data provided by the Open Sign applet. 
    /// </summary>
    public class SignHandler
    {
        /// <summary>
        /// Given the output data from the Open Sign applet, signed text is extracted if the login data is valid.
        /// </summary>
        /// <param name="loginData">the output data from the Open Sign applet (base64 encoded).</param>
        /// <param name="agreement">the string to match against the signed text in the login data.</param>
        /// <param name="logonto">expected value of the signature parameter <code>logonto</code> for OCESI applet responses or 
        /// of the signature parameter <code>RequestIssuer</code> for OCESII applet responses. Can be set to <code>null</code>
        /// if validation should not be performed (this is not recommended)</param>.
        /// <returns>true if the signed text matches the agreement parameter</returns>
        /// <throws>AppletException in case the applet returned an error code.</throws>
        public static SignatureValidationStatus ValidateSignatureAgainstAgreement(string loginData, string agreement, string stylesheet, string challenge, string logonto)
        {
            var errorCodeChecker = new ErrorCodeChecker(loginData);
            if (errorCodeChecker.HasError())
            {
                throw new AppletException(errorCodeChecker.ExtractError());
            }
            var opensignSignature = CreateOpensignSignature(Base64Decode(loginData));
            ValidateSignatureParameters(opensignSignature, challenge, logonto);
            var encodedSignature = EncodeSignature(opensignSignature);
            var encodedAgreement = Base64Encode(agreement);

            var certificate = opensignSignature.SigningCertificate;
            CertificateStatus status = certificate.ValidityStatus();
            if (ServiceProviderSetup.CurrentChecker.IsRevoked(certificate))
            {
                status = CertificateStatus.Revoked;
            }

            var signatureMatches = SignatureMatches(encodedSignature, encodedAgreement, stylesheet, opensignSignature);
            return new SignatureValidationStatus(opensignSignature, status, signatureMatches);
        }

        private static Boolean SignatureMatches(string encodedSignature, string encodedAgreement, string signTextTransformation, OpensignSignature opensignSignature)
        {
            if (!encodedAgreement.Equals(encodedSignature))
            {
                return false;
            }

            var stylesheetDigest = opensignSignature.StylesheetDigest;
            if (stylesheetDigest != null)
            {
                if (signTextTransformation == null)
                {
                    throw new ArgumentException("signTextTransformation is required for XML signing");
                }

                var digest = new Sha256Digest();
                var encode = new ASCIIEncoding();
                byte[] stylesheetBytes = encode.GetBytes(signTextTransformation);
                digest.BlockUpdate(stylesheetBytes, 0, stylesheetBytes.Length);
                var digestBytes = new byte[digest.GetDigestSize()];
                digest.DoFinal(digestBytes, 0);
                var calculatedDigest = Encoding.UTF8.GetString(digestBytes, 0, digestBytes.Length);

                return stylesheetDigest.Equals(calculatedDigest);
            }
            return true;
        }


        public static SignatureValidationStatus ValidateSignatureAgainstAgreement(string loginData, string agreement, string challenge, string logonto)
        {
            return ValidateSignatureAgainstAgreement(loginData, agreement, null, challenge, logonto);
        }

        public static SignatureValidationStatus validateSignatureAgainstAgreementPDF(String loginData, String agreement, String challenge, String logonto)
        {
		    var errorCodeChecker = new ErrorCodeChecker(loginData);
            if (errorCodeChecker.HasError())
            {
                throw new AppletException(errorCodeChecker.ExtractError());
            }
            var opensignSignature = CreateOpensignSignature(Base64Decode(loginData));
            ValidateChallenge(opensignSignature, challenge);
            
            if (logonto != null)
            {
                ValidateLogonto(opensignSignature, logonto);
            }

            String encodedSignature = Base64Encode(Encoding.ASCII.GetString(opensignSignature.SignedDocument.SignedContent));
            var encodedAgreement = Base64Encode(agreement);

            var certificate = opensignSignature.SigningCertificate;
            CertificateStatus status = certificate.ValidityStatus();
            if (ServiceProviderSetup.CurrentChecker.IsRevoked(certificate))
            {
                status = CertificateStatus.Revoked;
            }

            var signatureMatches = SignatureMatches(encodedSignature, encodedAgreement, null, opensignSignature);

            //@TODO HER MANGLER CHECK AF ATTACHMENTS !

            return new SignatureValidationStatus(opensignSignature, status, signatureMatches);

	    }

        public static string Base64Encode(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            return Convert.ToBase64String(bytes);
        }

        public static string Base64Decode(string s)
        {
            var bytes = Convert.FromBase64String(s);
            return Encoding.UTF8.GetString(bytes);
        }

        private static OpensignSignature CreateOpensignSignature(string loginData)
        {
            var abstractSignature = OpensignSignatureFactory.Instance.GenerateOpensignSignature(loginData);
            if (!(abstractSignature is OpensignSignature))
            {
                throw new ArgumentException("argument of type " + abstractSignature.GetType() + " is not valid output from the sign applet");
            }
            VerifySignature(abstractSignature);
            return (OpensignSignature)abstractSignature;
        }

        private static void VerifySignature(OpensignAbstractSignature signature)
        {
            if (!signature.Verify())
            {
                throw new ArgumentException("sign signature is not valid");
            }
        }

        private static string EncodeSignature(OpensignSignature opensignSignature)
        {
            return Base64Encode(opensignSignature.Signtext);
        }

        private static void ValidateSignatureParameters(OpensignSignature opensignSignature, string challenge, string logonto)
        {
            ValidateChallenge(opensignSignature, challenge);
            ValidateVisibleToSignerForSignText(opensignSignature);
            if (logonto != null)
            {
                ValidateLogonto(opensignSignature, logonto);
            }
        }

        private static void ValidateChallenge(OpensignSignature opensignSignature, string challenge)
        {
            ChallengeVerifier.VerifyChallenge(opensignSignature, challenge);
        }

        private static void ValidateVisibleToSignerForSignText(OpensignSignature signature)
        {
            SignatureProperty signtextProperty = signature.SignatureProperties["signtext"];
            if (IsNotSignedXmlDocument(signature) && !signtextProperty.VisibleToSigner)
            {
                throw new ServiceProviderException("Invalid sign signature - the parameter signtext in the signature " +
                    "must have the attribute visibleToSigner set to true");
            }
        }

        private static Boolean IsNotSignedXmlDocument(OpensignSignature opensignSignature)
        {
            return opensignSignature.StylesheetDigest == null;
        }

        private static void ValidateLogonto(OpensignSignature signature, string logonto)
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

        private static SignatureProperty GetSignatureProperty(OpensignSignature signature, string propertyKey)
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
