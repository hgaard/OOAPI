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
using System.IO;
using System.Net;
using Org.BouncyCastle.Ocsp;

namespace org.openoces.ooapi.utils.ocsp
{
    class Requester
    {
        public static OcspResp Send(OcspReq ocspRequest, string url)
        {
            HttpWebRequest request = CreateWebRequest(url, ocspRequest);
            HttpWebResponse response = GetWebResponse(request);
            return ExtractOcspResponseFromWebResponse(response);
        }

        static HttpWebRequest CreateWebRequest(string url, OcspReq ocspRequest)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.KeepAlive = false;
            request.Method = "POST";
            request.ContentType = "application/ocsp-request";
            request.ContentLength = ocspRequest.GetEncoded().Length;
            WriteOcspRequest(request, ocspRequest);
            return request;
        }

        static void WriteOcspRequest(WebRequest request, OcspReq ocspRequest)
        {
            using (var requestStream = request.GetRequestStream())
            {
                byte[] encodedRequest = ocspRequest.GetEncoded();
                requestStream.Write(encodedRequest, 0, encodedRequest.Length);
            }
        }

        static HttpWebResponse GetWebResponse(WebRequest request)
        {
            var response = (HttpWebResponse)request.GetResponse();
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new OcspException("Server status: " + response.StatusCode);
            }
            return response;
        }

        static OcspResp ExtractOcspResponseFromWebResponse(WebResponse response)
        {
            var buffer = new byte[0x400];
            using (var responseStream = response.GetResponseStream())
            {
                using (var memoryStream = new MemoryStream())
                {
                    int count;
                    do
                    {
                        count = responseStream.Read(buffer, 0, buffer.Length);
                        memoryStream.Write(buffer, 0, count);
                    }
                    while (count != 0);
                    byte[] rawResponse = memoryStream.ToArray();
                    return new OcspResp(rawResponse);
                }
            }
        }
    }
}
