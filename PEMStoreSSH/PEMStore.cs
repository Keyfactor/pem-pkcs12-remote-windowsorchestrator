// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

using PEMStoreSSH.RemoteHandlers;
using Keyfactor.Extensions.Pam.Utilities;

namespace PEMStoreSSH
{
    internal class PEMStore
    {
        private const string NO_EXTENSION = "noext";
        private const string FULL_SCAN = "fullscan";

        static Mutex mutex = new Mutex(false, "ModifyStore");

        public enum FormatTypeEnum
        {
            PEM,
            PKCS12
        }

        internal enum ServerTypeEnum
        {
            Linux,
            Windows
        }

        private string Server { get; set; }
        private string ServerId { get; set; }
        private string ServerPassword { get; set; }
        private string StorePath { get; set; }
        private string StorePassword { get; set; }
        private string PrivateKeyPath { get; set; }
        private ICertificateFormatHandler CertificateHandler { get; set; }
        private IRemoteHandler SSH { get; set; }
        public ServerTypeEnum ServerType { get; set; }
        public bool IsSingleCertificateStore { get; set; }


        internal PEMStore(string server, string serverId, string serverPassword, string storeFileAndPath, string storePassword, FormatTypeEnum formatType, string privateKeyPath)
        {
            Server = server;
            StorePath = storeFileAndPath;
            ServerId = serverId;
            ServerPassword = PamUtility.ResolvePassword(serverPassword);
            StorePassword = storePassword;
            PrivateKeyPath = privateKeyPath;
            CertificateHandler = GetCertificateHandler(formatType);
            ServerType = StorePath.Substring(0, 1) == "/" ? ServerTypeEnum.Linux : ServerTypeEnum.Windows;

            if (ServerType == ServerTypeEnum.Linux)
                SSH = new SSHHandler(Server, ServerId, ServerPassword);
            else
                SSH = new WinRMHandler(Server, ServerId, ServerPassword);
        }

        internal PEMStore(string server, string serverId, string serverPassword, ServerTypeEnum serverType, FormatTypeEnum formatType)
        {
            Server = server;
            ServerId = serverId;
            ServerPassword = PamUtility.ResolvePassword(serverPassword);
            ServerType = serverType;
            CertificateHandler = GetCertificateHandler(formatType);

            if (ServerType == ServerTypeEnum.Linux)
                SSH = new SSHHandler(Server, ServerId, ServerPassword);
            else
                SSH = new WinRMHandler(Server, ServerId, ServerPassword);
        }

        internal bool DoesStoreExist(string path)
        {
            return SSH.DoesFileExist(path);
        }

        internal List<string> FindStores(string[] paths, string[] extensions, string[] files)
        {
            return ServerType == ServerTypeEnum.Linux ? FindStoresLinux(paths, extensions, files) : FindStoresWindows(paths, extensions, files);
        }

        internal X509Certificate2Collection GetCertificates(string storePassword, out bool containsPrivateKey)
        {
            try
            {
                containsPrivateKey = false;

                byte[] certContents = SSH.DownloadCertificateFile(StorePath, CertificateHandler.HasBinaryContent);

                X509Certificate2Collection certs = CertificateHandler.RetrieveCertificates(certContents, storePassword);
                if (certs.Count >= 1)
                {
                    byte[] privateKeyContentBytes = null;
                    if (!string.IsNullOrEmpty(PrivateKeyPath))
                        privateKeyContentBytes = SSH.DownloadCertificateFile(PrivateKeyPath, CertificateHandler.HasBinaryContent);

                    containsPrivateKey = CertificateHandler.HasPrivateKey(certContents, privateKeyContentBytes);
                }

                return certs;
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to retrieve certificates for store path={StorePath}.", ex);
            }
        }

        internal void RemoveCertificate(string alias)
        {
            try
            {
                mutex.WaitOne();
                CertificateHandler.RemoveCertificate(ServerType, StorePath, PrivateKeyPath, SSH, alias, String.IsNullOrEmpty(PrivateKeyPath));
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to remove certificate from store {StorePath}.", ex);
            }
            finally
            {
                mutex.ReleaseMutex();
            }

            if (!string.IsNullOrEmpty(PrivateKeyPath))
            {
                try
                {
                    mutex.WaitOne();
                    SSH.RemoveCertificateFile(PrivateKeyPath);
                    SSH.CreateEmptyStoreFile(PrivateKeyPath);
                }
                catch (Exception ex)
                {
                    throw new PEMException($"Error attempting to remove private key {PrivateKeyPath}.", ex);
                }
                finally
                {
                    mutex.ReleaseMutex();
                }

            }
        }

        internal void AddCertificateToStore(string cert, string alias, string pfxPassword, string storePassword, bool overwrite, bool containsPrivateKey)
        {
            try
            {
                mutex.WaitOne();
                List<SSHFileInfo> files = CertificateHandler.CreateCertificatePacket(cert, alias, pfxPassword, storePassword, !String.IsNullOrEmpty(PrivateKeyPath));
                CertificateHandler.AddCertificateToStore(files, StorePath, PrivateKeyPath, SSH, ServerType, overwrite, containsPrivateKey, IsSingleCertificateStore);
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to add certificate to store {StorePath}.", ex);
            }
            finally
            {
                mutex.ReleaseMutex();
            }
        }

        internal bool IsValidStore(string path)
        {
            return CertificateHandler.IsValidStore(path, ServerType, SSH);
        }

        internal void CreateEmptyStoreFile(string path)
        {
            SSH.CreateEmptyStoreFile(path);
        }

        private List<string> FindStoresLinux(string[] paths, string[] extensions, string[] fileNames)
        {

            try
            {
                string concatPaths = string.Join(" ", paths);
                string command = $"find {concatPaths} ";

                foreach (string extension in extensions)
                {
                    foreach (string fileName in fileNames)
                    {
                        command += (command.IndexOf("-iname") == -1 ? string.Empty : "-or ");
                        command += $"-iname '{fileName.Trim()}";
                        if (extension.ToLower() == NO_EXTENSION)
                            command += $"' ! -iname '*.*' ";
                        else
                            command += $".{extension.Trim()}' ";
                    }
                }

                string result = string.Empty;
                if (extensions.Any(p => p.ToLower() != NO_EXTENSION))
                    result = SSH.RunCommand(command, null, ApplicationSettings.UseSudo, null);

                return (result.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries)).ToList();
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to find certificate stores for path={string.Join(" ", paths)}.", ex);
            }
        }

        private List<string> FindStoresWindows(string[] paths, string[] extensions, string[] fileNames)
        {
            List<string> results = new List<string>();
            StringBuilder concatFileNames = new StringBuilder();

            if (paths[0] == FULL_SCAN)
            {
                string command = @"Get-WmiObject Win32_Logicaldisk -Filter ""DriveType = '3'"" | % {$_.DeviceId}";
                string result = SSH.RunCommand(command, null, false, null);
                paths = result.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < paths.Length; i++)
                    paths[i] += @"\";
            }

            foreach (string path in paths)
            {
                foreach (string extension in extensions)
                {
                    foreach (string fileName in fileNames)
                        concatFileNames.Append($",{fileName}.{extension}");
                }

                string command = $@"(Get-ChildItem -Path ""{FormatPath(path)}"" -Recurse -Include {concatFileNames.ToString().Substring(1)}).fullname";
                string result = SSH.RunCommand(command, null, false, null);
                results.AddRange(result.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).ToList());
            }

            return results;
        }

        private ICertificateFormatHandler GetCertificateHandler(FormatTypeEnum formatType)
        {
            switch (formatType)
            {
                case FormatTypeEnum.PEM:
                    return new PEMHandler();
                case FormatTypeEnum.PKCS12:
                    return new PKCS12Handler();
                default:
                    throw new Exception("Invalid certificate format:");
            }
        }

        private string FormatPath(string path)
        {
            return path + (path.Substring(path.Length - 1) == @"\" ? string.Empty : @"\");
        }
    }

    class PEMException : ApplicationException
    {
        public PEMException(string message) : base(message)
        { }

        public PEMException(string message, Exception ex) : base(message, ex)
        { }
    }
}