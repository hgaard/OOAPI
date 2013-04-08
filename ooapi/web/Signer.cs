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

namespace org.openoces.ooapi.web
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Configuration;
    public class Signer
    {
        private readonly X509Certificate2 _certificate;

        public Signer(string pfxFile, string pfxPassword)
        {
            _certificate = new X509Certificate2(pfxFile, pfxPassword);
        }
        
        public string GetCertificate()
        {
            byte[] encodedCertificate = _certificate.Export(X509ContentType.Cert);
            String base64EncodedCertificate = Base64Encode(encodedCertificate);
            return base64EncodedCertificate.Replace("\r", "").Replace("\n", "");
        }

        public byte[] CalculateSignature(byte[] data)
        {
            try
            {
                var csp = (RSACryptoServiceProvider)_certificate.PrivateKey;
                return csp.SignData(data, CryptoConfig.MapNameToOID("SHA256"));
            }
            catch (CryptographicException ce)
            {
                //if its an algorithm exception then it should relate to a wrongs csp being loaded. Try again with the right csp(that supports sha256)
                X509Certificate2 cert = new X509Certificate2(ConfigurationManager.AppSettings["pfxFile"], ConfigurationManager.AppSettings["pfxPassword"], X509KeyStorageFlags.Exportable);
                RSACryptoServiceProvider rsa = cert.PrivateKey as RSACryptoServiceProvider;
                byte[] privateKeyBlob = rsa.ExportCspBlob(true);
                RSACryptoServiceProvider rsa2 = new RSACryptoServiceProvider();
                rsa2.ImportCspBlob(privateKeyBlob);
                return rsa2.SignData(data, "SHA256");


            }
        }

        static string Base64Encode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
    }
}