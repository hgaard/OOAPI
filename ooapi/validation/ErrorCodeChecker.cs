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
    public class ErrorCodeChecker
    {
        static readonly List<string> ErrorCodes = new List<string> { "APP001","APP002","APP003","APP004","APP005","SRV001","SRV002","SRV003","SRV004","SRV005","SRV006","CAN001","CAN002",
			"AUTH001","AUTH003","AUTH004","AUTH005","AUTH006","AUTH007","AUTH008","AUTH009","LOCK001","LOCK002","LOCK003","OCES001","OCES002","OCES003","OCES004","OCES005","OCES006"};

        readonly string _text;

        public ErrorCodeChecker(string text)
        {
            if (text == null)
            {
                throw new ArgumentException("text cannot be null");
            }
            _text = text.Trim();
        }

        public bool HasError()
        {
            return ExtractError() != null;
        }

        public string ExtractError()
        {
            return ErrorCodes.Contains(_text.ToUpper()) ? _text.ToUpper() : null;
        }
    }
}

