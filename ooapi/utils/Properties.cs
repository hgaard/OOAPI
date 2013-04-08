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
using System.Collections.Generic;

namespace org.openoces.ooapi.utils
{
    /// <summary>
    /// Reads properties from App.config / Web.config.
    /// </summary>
    public class Properties
    {
        static readonly Dictionary<string, string> _properties =
            new Dictionary<string, string>
      {
        // LDAP servers
        {"ldap.server.danid.OcesIDanidEnvProd", "dir.certifikat.dk"},
        {"ldap.server.danid.OcesIDanidEnvSystemtest", "fenris.certifikat.dk"},
        {"ldap.server.danid.OcesIDanidEnvDevelopment", "balder.certifikat.dk"},
        {"ldap.server.danid.OcesIiDanidEnvPreprod", "crldir.pp.certifikat.dk"},
        {"ldap.server.danid.OcesIiDanidEnvProd", "crldir.certifikat.dk"},
        {"ldap.server.danid.OcesIiDanidEnvExternaltest", "crldir.et.certifikat.dk"},
        {"ldap.server.danid.OcesIiDanidEnvInternaltest", "crldir.it.certifikat.dk"},
        {"ldap.server.danid.OcesIiDanidEnvOperationstest", "crldir.ot.certifikat.dk"},
        {"ldap.server.danid.OcesIiDanidEnvDevelopmenttest", "crldir.ut.certifikat.dk"},
        {"ldap.server.danid.OcesIiDanidEnvIgtest", "crldir.ig.certifikat.dk"},
        {"ldap.server.danid.OcesIiDanidEnvDevelopment", "nyx.certifikat.dk"},
        {"ldap.server.danid.CampusIDanidEnvProd", "directory.certifikat.dk"},


        // LDAP CA DNs
        {"ldap.ca.dn.danid.OcesIDanidEnvProd", "cn=TDC OCES CA,o=TDC,c=DK"},
        {"ldap.ca.dn.danid.OcesIDanidEnvSystemtest", "cn=TDC OCES SystemTest CA II,o=TDC,c=DK"},
        {"ldap.ca.dn.danid.OcesIDanidEnvDevelopment", "ou=TDC OCES SystemTest CA I,o=TDC,c=DK"},
        {"ldap.ca.dn.danid.OcesIiDanidEnvDevelopmenttest", "cn=TRUST2408 Systemtest III Primary CA,o=TRUST2408,c=DK"},
        {"ldap.ca.dn.danid.OcesIiDanidEnvExternaltest", "cn=TRUST2408 Systemtest IV Primary CA,o=TRUST2408,c=DK"},

     
        {"ldap.ca.dn.danid.OcesIiDanidEnvIgtest", "CN=TRUST2408 Systemtest IX Primary CA,O=TRUST2408,C=DK"},
        {"ldap.ca.dn.danid.OcesIiDanidEnvPreprod", "CN=TRUST2408 Systemtest VII Primary CA,O=TRUST2408,C=DK"},
        {"ldap.ca.dn.danid.OcesIiDanidEnvProd", "CN=TRUST2408 OCES Primary CA,O=TRUST2408,C=DK"},

        {"ldap.ca.dn.danid.CampusIDanidEnvProd", "ou=TDC Internet Class II CA,o=TDC Internet,c=DK"},


        // CRL cache timeouts in minutes
        {"crl.cache.timeout.ldap", "10"},
        {"crl.cache.timeout.http", "10"},

        // Full crl url
        // TODO: afgør om det skal gøres sådan og tilføj flere miljøer efter behov
        {"ldap.fullcrl.OcesIDanidEnvProd", "http://crl.oces.certifikat.dk/oces.crl"},
        {"ldap.fullcrl.OcesIDanidEnvSystemtest", "http://test.crl.oces.certifikat.dk/oces.crl"},

        // PID service
        {"pid.service.url.oces2.danidtest", "https://nyx.certifikat.dk/pid_server"},
        {"pid.service.url.OcesIDanidEnvProd", "https://pid.certifikat.dk/pidwsv2/pidwsdoc"},
        {"pid.service.url.OcesIDanidEnvSystemtest", "https://test.pid.certifikat.dk/pidwsv2/pidwsdoc"},
        {"pid.service.url.OcesIiDanidEnvPreprod", "https://pidws.pp.certifikat.dk/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.OcesIiDanidEnvProd", "https://pidws.certifikat.dk/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.OcesIiDanidEnvExternaltest", "https://pidws.et.certifikat.dk/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.OcesIiDanidEnvInternaltest", "https://pidws.it.certifikat.dk/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.OcesIiDanidEnvOperationstest", "https://pidws.ot.certifikat.dk/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.OcesIiDanidEnvDevelopmenttest", "https://pidws.ut.certifikat.dk/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.OcesIiDanidEnvIgtest", "https://pidws.ig.certifikat.dk/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.OcesIiDanidEnvDevelopment", "https://localhost:8443/pid_serviceprovider_server/pidws/"},
        {"pid.service.url.CampusIDanidEnvProd", "TODO"},

        // RID service
        {"rid.service.url.oces2.danidtest", "TODO"},
        {"rid.service.url.OcesIDanidEnvProd", "TODO"},
        {"rid.service.url.OcesIDanidEnvSystemtest", "TODO"},
        {"rid.service.url.OcesIiDanidEnvPreprod", "https://ws-erhverv.pp.certifikat.dk/rid_serviceprovider_server/services/HandleSundhedsportalWSPort"},
        {"rid.service.url.OcesIiDanidEnvProd", "https://ws-erhverv.certifikat.dk/rid_serviceprovider_server/services/HandleSundhedsportalWSPort"},
        {"rid.service.url.OcesIiDanidEnvExternaltest", "TODO"},
        {"rid.service.url.OcesIiDanidEnvInternaltest", "TODO"},
        {"rid.service.url.OcesIiDanidEnvOperationstest", "TODO"},
        {"rid.service.url.OcesIiDanidEnvDevelopmenttest", "TODO"},
        {"rid.service.url.OcesIiDanidEnvIgtest", "TODO"},
        {"rid.service.url.OcesIiDanidEnvDevelopment", "TODO"},
        {"rid.service.url.CampusIDanidEnvProd", "TODO"},

        //OCES1 - policies
        {"poces.policies.prefix.danid.OcesIDanidEnvProd", "1.2.208.169.1.1.1.1"},
        {"moces.policies.prefix.danid.OcesIDanidEnvProd", "1.2.208.169.1.1.1.2"},
        {"voces.policies.prefix.danid.OcesIDanidEnvProd", "1.2.208.169.1.1.1.3"},
        {"foces.policies.prefix.danid.OcesIDanidEnvProd", "1.2.208.169.1.1.1.4"},

        //OCES2 - policies
        //FIX UT
        {"poces.policies.prefix.danid.OcesIiDanidEnvDevelopmenttest", "1.3.6.1.4.1.31313.2.4.2.1"},
        {"moces.policies.prefix.danid.OcesIiDanidEnvDevelopmenttest", "1.3.6.1.4.1.31313.2.4.2.1"},
        {"voces.policies.prefix.danid.OcesIiDanidEnvDevelopmenttest", "1.3.6.1.4.1.31313.2.4.2.1"},
        {"foces.policies.prefix.danid.OcesIiDanidEnvDevelopmenttest", "1.3.6.1.4.1.31313.2.4.2.1"},

        {"poces.policies.prefix.danid.OcesIiDanidEnvProd", "1.2.208.169.1.1.1.1"},
        {"moces.policies.prefix.danid.OcesIiDanidEnvProd", "1.2.208.169.1.1.1.2"},
        {"voces.policies.prefix.danid.OcesIiDanidEnvProd", "1.2.208.169.1.1.1.3"},
        {"foces.policies.prefix.danid.OcesIiDanidEnvProd", "1.2.208.169.1.1.1.4"},

        {"poces.policies.prefix.danid.OcesIiDanidEnvPreprod", "1.3.6.1.4.1.31313.2.4.6.1"},
        {"moces.policies.prefix.danid.OcesIiDanidEnvPreprod", "1.3.6.1.4.1.31313.2.4.6.2"},
        {"voces.policies.prefix.danid.OcesIiDanidEnvPreprod", "1.3.6.1.4.1.31313.2.4.6.3"},
        {"foces.policies.prefix.danid.OcesIiDanidEnvPreprod", "1.3.6.1.4.1.31313.2.4.6.4"},

        {"poces.policies.prefix.danid.OcesIiDanidEnvExternaltest", "1.3.6.1.4.1.31313.2.4.5.1"},
        {"moces.policies.prefix.danid.OcesIiDanidEnvExternaltest", "1.3.6.1.4.1.31313.2.4.5.2"},
        {"voces.policies.prefix.danid.OcesIiDanidEnvExternaltest", "1.3.6.1.4.1.31313.2.4.5.3"},
        {"foces.policies.prefix.danid.OcesIiDanidEnvExternaltest", "1.3.6.1.4.1.31313.2.4.5.4"},

        {"poces.policies.prefix.danid.OcesIiDanidEnvInternaltest", "1.3.6.1.4.1.31313.2.4.3.1"},
        {"moces.policies.prefix.danid.OcesIiDanidEnvInternaltest", "1.3.6.1.4.1.31313.2.4.3.2"},
        {"voces.policies.prefix.danid.OcesIiDanidEnvInternaltest", "1.3.6.1.4.1.31313.2.4.3.3"},
        {"foces.policies.prefix.danid.OcesIiDanidEnvInternaltest", "1.3.6.1.4.1.31313.2.4.3.4"},

        {"poces.policies.prefix.danid.OcesIiDanidEnvIgtest", "1.3.6.1.4.1.31313.2.4.1.1"},
        {"moces.policies.prefix.danid.OcesIiDanidEnvIgtest", "1.3.6.1.4.1.31313.2.4.1.2"},
        {"voces.policies.prefix.danid.OcesIiDanidEnvIgtest", "1.3.6.1.4.1.31313.2.4.1.3"},
        {"foces.policies.prefix.danid.OcesIiDanidEnvIgtest", "1.3.6.1.4.1.31313.2.4.1.4"},

        {"poces.policies.prefix.danid.OcesIiDanidEnvOperationstest", "1.3.6.1.4.1.31313.2.4.4.1"},
        {"moces.policies.prefix.danid.OcesIiDanidEnvOperationstest", "1.3.6.1.4.1.31313.2.4.4.2"},
        {"voces.policies.prefix.danid.OcesIiDanidEnvOperationstest", "1.3.6.1.4.1.31313.2.4.4.3"},
        {"foces.policies.prefix.danid.OcesIiDanidEnvOperationstest", "1.3.6.1.4.1.31313.2.4.4.4"},

        {"poces.policies.prefix.danid.OcesIiDanidEnvDevelopment", "1.2.208.169.1.1.1.1"},
        {"moces.policies.prefix.danid.OcesIiDanidEnvDevelopment", "TODO"},
        {"voces.policies.prefix.danid.OcesIiDanidEnvDevelopment", "TODO"},
        {"foces.policies.prefix.danid.OcesIiDanidEnvDevelopment", "TODO"},

        {"poces.policies.prefix.danid.CampusIDanidEnvProd", "TODO"},
        {"moces.policies.prefix.danid.CampusIDanidEnvProd", "TODO"},
        {"voces.policies.prefix.danid.CampusIDanidEnvProd", "TODO"},
        {"foces.policies.prefix.danid.CampusIDanidEnvProd", "TODO"},
      };

        public static string Get(string name)
        {
            return _properties[name];
        }

        /// <summary>
        /// Determines whether or not the given configuration property is defined or not.
        /// </summary>
        public static bool IsDefined(string name)
        {
            return _properties.ContainsKey(name);
        }
    }
}
