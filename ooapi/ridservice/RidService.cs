using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Configuration;
using System.ServiceModel;
using org.openoces.ridService;

namespace org.openoces.ooapi.ridservice
{
    public class RidService
    {
        readonly HandleSundhedsportalWSPortClient _client;

        public RidService(string wsUrl)
        {
            _client = new HandleSundhedsportalWSPortClient("HandleSundhedsportalWSPort", new EndpointAddress(wsUrl));
            _client.ClientCredentials.ClientCertificate.Certificate = new X509Certificate2(ConfigurationManager.AppSettings["pfxFile"], ConfigurationManager.AppSettings["pfxPassword"]);
        }

        //Test RID with both moces1 and moces2 certificates
        public void Test()
        {
            _client.test();
        }

        public String getCPR(String RID)
        {
            return _client.getCPR(RID);
        }
   
    }
}