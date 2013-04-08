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

namespace org.openoces.ooapi.validation
{
    internal class CrlCache
    {
        readonly Dictionary<String, CrlCacheElement> _crls = new Dictionary<string, CrlCacheElement>();
        readonly int _timeout;

        /// <param name="timeout">The timeout in minutes of cached elements</param>
        public CrlCache(int timeout)
        {
            _timeout = timeout;
        }

        public Crl GetCrl(string key, IDownloadableCrlJob job)
        {
            lock (_crls)
            {
                if (!IsValid(key))
                {
                    _crls[key] = new CrlCacheElement(job);
                }
                return _crls[key].Value;
            }
        }

        bool IsValid(string key)
        {
            CrlCacheElement cacheElement;
            if (_crls.TryGetValue(key, out cacheElement) && cacheElement.Value.IsValid)
            {
                var expirationTime = cacheElement.CreationTime.AddMinutes(_timeout);
                return expirationTime > DateTime.Now;
            }
            return false;
        }
    }

    class CrlCacheElement
    {
        readonly IDownloadableCrlJob _job;
        Crl _crl;
        public DateTime CreationTime { get; private set; }

        internal CrlCacheElement(IDownloadableCrlJob job)
        {
            _job = job;
            CreationTime = DateTime.Now;
        }

        internal Crl Value
        {
            get
            {
                lock (this)
                {
                    if (_crl == null)
                    {
                        _crl = _job.Download();
                    }
                    return _crl;
                }
            }
        }
    }
}
