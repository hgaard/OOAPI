using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NLog;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.utils;
using org.openoces.ooapi.ridservice;

namespace org.openoces.ooapi.ping
{
    class RidAliveTester
    {
        const string ServiceStringPrefix = "rid.service.url.";
        static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public static void PingRid()
        {
            try
            {
                var environments = Environments.TrustedEnvironments;

                if (environments.Count() == 0)
                {
                    throw new ArgumentException("No Environment has been set");
                }

                Logger.Debug("Current env list " + environments);
                PingRid(environments);
            }
            catch (Exception e)
            {
                throw new InternalException("Exception while trying to ping rid/cpr service", e);
            }
        }

        static void PingRid(IEnumerable<OcesEnvironment> environments)
        {
            foreach (var environment in environments)
            {
                string service = Properties.Get(ServiceStringPrefix + environment);

                if (service == null)
                {
                    Logger.Error("Missing property in Properties: " + ServiceStringPrefix + environment);
                }

                Logger.Debug("calling rid with service url " + service);
                Ping(service);
            }
        }

        static void Ping(string serviceUrl)
        {
            var wsClient = new RidService(serviceUrl);
            wsClient.Test();
        }
    }

}

