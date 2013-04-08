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
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace org.openoces.ooapi.validation
{
    public class CrlDistributionPointsExtractor
    {
        const int UniformResourceIdentifier = 6;
        const int DirectoryName = 4;

        public static CrlDistributionPoints ExtractCrlDistributionPoints(X509Certificate2 certificate)
        {
            var distributionPointsExtension = ExtractCrlDistributionPointsExtension(certificate);

            var fullCrlDistributionPoint = ExtractFullCrlDistributionPoint(distributionPointsExtension);
            var partitionedCrlDistributionPoint = ExtractPartitionedCrlDistributionPoint(distributionPointsExtension);

            return new CrlDistributionPoints(fullCrlDistributionPoint, partitionedCrlDistributionPoint);
        }

        static CrlDistPoint ExtractCrlDistributionPointsExtension(X509Certificate2 certificate)
        {
            var bouncyCastleCertificate = new X509CertificateParser().ReadCertificate(certificate.RawData);
            var extension = bouncyCastleCertificate.GetExtensionValue(new DerObjectIdentifier(ObjectIdentifiers.CrlDistributionPointsExtension));
            var stream = new Asn1InputStream(extension.GetOctetStream());

            return CrlDistPoint.GetInstance(stream.ReadObject());
        }

        static string ExtractFullCrlDistributionPoint(CrlDistPoint distributionPointsExtension)
        {
            var crlDistributionPointGeneralName =
                (DerIA5String) ExtractGeneralName(distributionPointsExtension, UniformResourceIdentifier);
            return crlDistributionPointGeneralName != null ? crlDistributionPointGeneralName.GetString() : null;
        }

        static string ExtractPartitionedCrlDistributionPoint(CrlDistPoint distributionPointsExtension)
        {
            var directoryNames = ExtractGeneralName(distributionPointsExtension, DirectoryName);
            return ExtractPartitionedCrlDistributionPoint(directoryNames);
        }

        static string ExtractPartitionedCrlDistributionPoint(IAsn1Convertible directoryName)
        {
            var ds = (DerSequence) directoryName.ToAsn1Object();

            var partitionedCrlDistributionPoint = "";
            foreach (Asn1Set dset in ds)
            {
                partitionedCrlDistributionPoint = BuildPartitionedCrlDistributionPoint(partitionedCrlDistributionPoint, dset);
            }
            return partitionedCrlDistributionPoint;
        }

        static string BuildPartitionedCrlDistributionPoint(string partitionedCrlDistributionPoint, Asn1Set dset)
        {
            foreach (DerSequence relativeDn in dset)
            {
                var relativeDnOid = ((DerObjectIdentifier)relativeDn[0]).Id;
                var relativeDnName = (string)X509Name.RFC2253Symbols[new DerObjectIdentifier(relativeDnOid)];
                var relativeDnValue = ((DerStringBase)relativeDn[1]).GetString();

                var comma = partitionedCrlDistributionPoint.Length > 0 ? "," : "";
                partitionedCrlDistributionPoint = relativeDnName + "=" + relativeDnValue + comma + partitionedCrlDistributionPoint;
            }
            return partitionedCrlDistributionPoint;
        }

        static Asn1Encodable ExtractGeneralName(CrlDistPoint distributionPointsExtension, int tagNumber)
        {
            foreach (var distributionPoint in distributionPointsExtension.GetDistributionPoints())
            {
                DistributionPointName dpn = distributionPoint.DistributionPointName;
                if (dpn.PointType == DistributionPointName.FullName)
                {
                    foreach (var generalName in GeneralNames.GetInstance(dpn.Name).GetNames())
                    {
                        if (generalName.TagNo == tagNumber)
                        {
                            return generalName.Name;
                        }
                    }
                }
            }
            return null;
        }
    }
}
