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
using System.ServiceModel;
using org.openoces.ooapi.pidservice.impl;
using org.openoces.ooapi.utils;
using System.Security.Cryptography.X509Certificates;
using System.Configuration;

namespace org.openoces.ooapi.pidservice
{
    public class PidService
    {
        readonly pidwsdocPortClient _client;

        public PidService(string wsUrl)
        {
            _client = new pidwsdocPortClient("pidwsdocPort", new EndpointAddress(wsUrl));

            // The following line makes it possible to read the VOCES certificate used for calling the PID/CPR service, as a file on the filesystem instead of the certificate store (CAPI).
            // Remove the following line if you plan on using the certificate store instead.
            _client.ClientCredentials.ClientCertificate.Certificate = new X509Certificate2(ConfigurationManager.AppSettings["pfxFile"], ConfigurationManager.AppSettings["pfxPassword"]);
        }

        public void Test()
        {
            _client.test();
        }

        public int TestConnection(int value)
        {
            return _client.testConnection(value);
        }

        public string LookupCpr(string pid, string callerSpid)
        {
            var reply = Call(callerSpid, pid, null);
            return reply.CPR;
        }

        public bool Match(string cpr, string pid, string callerSpid)
        {
            var reply = Call(callerSpid, pid, cpr);
            if (reply.statusCode == "0")
            {
                return true;
            }
            if (reply.statusCode == "1")
            {
                return false;
            }

            return false; // her forventer vi aldrig at lande
        }

        PIDReply Call(string callerSpid, string pid, string cpr)
        {
            var requestsList = CreatePidRequestArray(callerSpid, pid, cpr);
            var reply = Call(requestsList);

            HandleErrorStatuses(reply);
            return reply;
        }

        PIDReply Call(PIDRequest[] requestsList)
        {
            var replyList = _client.pid(requestsList);
            return replyList[0];
        }

        static PIDRequest[] CreatePidRequestArray(string callerSpid, string pid, string cpr)
        {
            return new[] { CreatePidRequest(callerSpid, pid, cpr) };
        }

        static PIDRequest CreatePidRequest(string callerSpid, string pid, string cpr)
        {
            return new PIDRequest { PID = pid, CPR = cpr, serviceId = callerSpid };
        }

        static void HandleErrorStatuses(PIDReply reply)
        {
            int statusCode = int.Parse(reply.statusCode);
            var statusTextUK = reply.statusTextUK;
            var statusTextDK = reply.statusTextDK;


            if (statusCode == 0 || statusCode == 1)
            {
                return;
            }
            if (statusCode == CallerNotAuthorizedForCprLookupException.ErrorCode)
            {
                throw new CallerNotAuthorizedForCprLookupException(statusTextUK, statusTextDK);
            }
            if (statusCode == CallerNotAuthorizedException.ErrorCode)
            {
                throw new CallerNotAuthorizedException(statusTextUK, statusTextDK);
            }
            throw new PidServiceException(statusCode, statusTextUK, statusTextDK);
        }
    }
}
