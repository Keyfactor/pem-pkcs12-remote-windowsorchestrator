// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using PEMStoreSSH.RemoteHandlers;

namespace PEMStoreSSH
{
    interface ICertificateFormatHandler
    {
        bool HasPrivateKey(byte[] certificateBytes, byte[] privateKeyBytes);
        X509Certificate2Collection RetrieveCertificates(byte[] binaryCertificates, string storePassword);
        List<SSHFileInfo> CreateCertificatePacket(string certToAdd, string alias, string pfxPassword, string storePassword, bool hasSeparatePrivateKey);
        void AddCertificateToStore(List<SSHFileInfo> files, string storePath, string privateKeyPath, IRemoteHandler ssh, PEMStore.ServerTypeEnum serverType, bool overwrite, bool hasPrivateKey, bool isSingleCertificateStore);
        void RemoveCertificate(PEMStore.ServerTypeEnum serverType, string storePath, string privateKeyPath, IRemoteHandler ssh, string alias, bool hasPrivateKey);
        bool IsValidStore(string path, PEMStore.ServerTypeEnum serverType, IRemoteHandler ssh);
        bool HasBinaryContent { get; }
    }
}
