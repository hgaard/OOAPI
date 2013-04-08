using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using org.openoces.ooapi.certificate;

namespace org.openoces.ooapi.validation
{
    public interface ICaCrlRevokedChecker : IRevocationChecker
    {
        bool IsRevoked(Ca ca);
    }
}
