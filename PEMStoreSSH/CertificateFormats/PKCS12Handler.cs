// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using CSS.PKI.X509;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

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

                if (binaryCertificates.Length > 50)
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

            X509Certificate2 x509Cert = new X509Certificate2(Convert.FromBase64String(certToAdd), pfxPassword);
            string aliasToUse = string.IsNullOrEmpty(alias) ? x509Cert.Thumbprint : alias;

            Pkcs12Store tempStore = new Pkcs12Store();
            using (MemoryStream inStream = new MemoryStream(Convert.FromBase64String(certToAdd)))
            {
                if (string.IsNullOrEmpty(pfxPassword))
                {
                    CertificateConverter converter = CertificateConverterFactory.FromDER(Encoding.ASCII.GetBytes(certToAdd));
                    Org.BouncyCastle.X509.X509Certificate bcCert = converter.ToBouncyCastleCertificate();
                    X509CertificateEntry entry = new X509CertificateEntry(bcCert);
                    tempStore.SetCertificateEntry(aliasToUse, entry);
                }
                else
                {
                    tempStore = new Pkcs12Store(inStream, pfxPassword.ToCharArray());
                }
            }

            string tempAlias = string.Empty;
            foreach (string name in tempStore.Aliases)
            {
                tempAlias = name;
                break;
            }

            Pkcs12Store store = new Pkcs12Store();

            store.SetCertificateEntry(aliasToUse, tempStore.GetCertificate(tempAlias));
            if (!string.IsNullOrEmpty(pfxPassword))
            {
                store.SetKeyEntry(aliasToUse, tempStore.GetKey(tempAlias), tempStore.GetCertificateChain(tempAlias));
            }

            using (MemoryStream outStream = new MemoryStream())
            {
                store.Save(outStream, string.IsNullOrEmpty(storePassword) ? new char[0] : storePassword.ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
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
