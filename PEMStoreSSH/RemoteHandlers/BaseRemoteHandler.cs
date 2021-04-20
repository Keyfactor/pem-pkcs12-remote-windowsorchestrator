// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CSS.Common.Logging;

namespace PEMStoreSSH.RemoteHandlers
{
    abstract class BaseRemoteHandler : LoggingClientBase, IRemoteHandler
    {
        internal const int PASSWORD_LENGTH_MAX = 100;
        internal const string PASSWORD_MASK_VALUE = "[PASSWORD]";

        public string Server { get; set; }

        public abstract string RunCommand(string commandText, object[] parameters, bool withSudo, string[] passwordsToMaskInLog);

        public abstract bool DoesFileExist(string path);

        public abstract void UploadCertificateFile(string path, byte[] certBytes);

        public abstract byte[] DownloadCertificateFile(string path, bool hasBinaryContent);

        public abstract void RemoveCertificateFile(string path);

        public abstract void CreateEmptyStoreFile(string path);

    }
}
