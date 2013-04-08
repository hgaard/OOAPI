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
using NLog;
using org.openoces.ooapi.environment;
using org.openoces.ooapi.exceptions;
using org.openoces.ooapi.pidservice;
using org.openoces.ooapi.utils;

namespace org.openoces.ooapi.ping
{
    public class PidAlivetester
    {
        const string ServiceStringPrefix = "pid.service.url.";
        static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public static void PingPid()
        {
            try
            {
                var environments = Environments.TrustedEnvironments;

                if (environments.Count() == 0)
                {
                    throw new ArgumentException("No Environment has been set");
                }

                Logger.Debug("Current env list " + environments);
                PingPid(environments);
            }
            catch (Exception e)
            {
                throw new InternalException("Exception while trying to ping pid/cpr service", e);
            }
        }

        static void PingPid(IEnumerable<OcesEnvironment> environments)
        {
            foreach (var environment in environments)
            {
                string service = Properties.Get(ServiceStringPrefix + environment);

                if (service == null)
                {
                    Logger.Error("Missing property in ooapi.properties: " + ServiceStringPrefix + environment);
                }

                Logger.Debug("calling pid with service url " + service);
                Ping(service);
            }
        }

        static void Ping(string serviceUrl)
        {
            var wsClient = new PidService(serviceUrl);
            wsClient.Test();
        }
    }
}
