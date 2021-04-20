// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Org.BouncyCastle.Pkcs;

using PEMStoreSSH.RemoteHandlers;

namespace PEMStoreSSH
{
    class PKCS12Handler : ICertificateFormatHandler
    {
        public bool HasBinaryContent { get { return true; } }

        public bool HasPrivateKey(byte[] certificateBytes, byte[] privateKeyBytes)
        {
            return true;
        }

        public X509Certificate2Collection RetrieveCertificates(byte[] binaryCertificates, string storePassword)
        {
            try
            {
                X509Certificate2Collection certCollection = new X509Certificate2Collection();

                if (binaryCertificates.Length > 0)
                {
                    certCollection.Import(binaryCertificates, storePassword, X509KeyStorageFlags.Exportable);

                    X509Certificate2 certWithKey = null;
                    foreach (X509Certificate2 cert in certCollection)
                    {
                        if (cert.HasPrivateKey)
                        {
                            certWithKey = cert;
                            break;
                        }
                    }

                    if (certWithKey != null)
                    {
                        certCollection.Remove(certWithKey);
                        certCollection.Insert(0, certWithKey);
                    }
                }

                return certCollection;
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to retrieve certificate chain.", ex);
            }
        }

        public List<SSHFileInfo> CreateCertificatePacket(string certToAdd, string alias, string pfxPassword, string storePassword, bool hasSeparatePrivateKey)
        {
            List<SSHFileInfo> fileInfo = new List<SSHFileInfo>();
            Pkcs12Store store;

            using (MemoryStream inStream = new MemoryStream(Convert.FromBase64String(certToAdd)))
            {
                store = new Pkcs12Store(inStream, pfxPassword.ToCharArray());
            }

            using (MemoryStream outStream = new MemoryStream())
            {
                store.Save(outStream, string.IsNullOrEmpty(storePassword) ? pfxPassword.ToCharArray() : storePassword.ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
                fileInfo.Add(new SSHFileInfo()
                {
                    FileType = SSHFileInfo.FileTypeEnum.Certificate,
                    FileContentBytes = outStream.ToArray(),
                    Alias = alias
                });
            }

            return fileInfo;
        }

        public void AddCertificateToStore(List<SSHFileInfo> files, string storePath, string privateKeyPath, IRemoteHandler ssh, PEMStore.ServerTypeEnum serverType, bool hasPrivateKey, bool overwrite, bool isSingleCertificateStore)
        {
            foreach (SSHFileInfo file in files)
                ssh.UploadCertificateFile(file.FileType == SSHFileInfo.FileTypeEnum.Certificate ? storePath : privateKeyPath,
                    string.IsNullOrEmpty(file.FileContents) ? file.FileContentBytes : Encoding.ASCII.GetBytes(file.FileContents));
        }

        public void RemoveCertificate(PEMStore.ServerTypeEnum serverType, string storePath, string privateKeyPath, IRemoteHandler ssh, string alias, bool hasPrivateKey)
        {
            ssh.RunCommand($"echo -n '' > {storePath}", null, ApplicationSettings.UseSudo, null);
        }

        public bool IsValidStore(string path, PEMStore.ServerTypeEnum serverType, IRemoteHandler ssh)
        {
            return true;
        }
    }
}
