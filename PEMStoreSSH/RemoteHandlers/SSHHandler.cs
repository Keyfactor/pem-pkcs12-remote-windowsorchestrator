// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Renci.SshNet;

namespace PEMStoreSSH.RemoteHandlers
{
    class SSHHandler : BaseRemoteHandler
    {
        private ConnectionInfo Connection { get; set; }

        internal SSHHandler(string server, string serverLogin, string serverPassword)
        {
            if (string.IsNullOrEmpty(server))
                throw new PEMException("Blank or missing server name for server orchestration.");
            if (string.IsNullOrEmpty(serverLogin))
                throw new PEMException("Blank or missing username for server SSH login.");
            if (string.IsNullOrEmpty(serverPassword))
                throw new PEMException("Blank or missing password or SSH key for server SSH login.");


            Server = server;

            List<AuthenticationMethod> authenticationMethods = new List<AuthenticationMethod>();
            if (serverPassword.Length < PASSWORD_LENGTH_MAX)
                authenticationMethods.Add(new PasswordAuthenticationMethod(serverLogin, serverPassword));
            else
                authenticationMethods.Add(new PrivateKeyAuthenticationMethod(serverLogin, new PrivateKeyFile[] { new PrivateKeyFile(new MemoryStream(Encoding.ASCII.GetBytes(ReplaceSpacesWithLF(serverPassword)))) }));

            Connection = new ConnectionInfo(server, serverLogin, authenticationMethods.ToArray());
        }

        public override string RunCommand(string commandText, object[] arguments, bool withSudo, string[] passwordsToMaskInLog)
        {
            Logger.Debug($"RunCommand: {Server}");

            string sudo = $"echo -e '\n' | sudo -S ";
            using (SshClient client = new SshClient(Connection))
            {
                try
                {
                    client.Connect();

                    if (withSudo)
                        commandText = sudo + commandText;

                    string displayCommand = commandText;
                    if (passwordsToMaskInLog != null)
                    {
                        foreach (string password in passwordsToMaskInLog)
                            displayCommand = displayCommand.Replace(password, PASSWORD_MASK_VALUE);
                    }

                    using (SshCommand command = client.CreateCommand($"{commandText}"))
                    {
                        Logger.Debug($"RunCommand: {displayCommand}");
                        command.Execute();
                        Logger.Debug($"SSH Results: {displayCommand}::: {command.Result}::: {command.Error}");
                        return command.Result;
                    }
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        public override bool DoesFileExist(string path)
        {
            Logger.Debug($"DoesFileExist: {path}");

            using (SftpClient client = new SftpClient(Connection))
            {
                try
                {
                    client.Connect();
                    string existsPath = FormatFTPPath(path);
                    bool exists = client.Exists(existsPath);

                    return exists;
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        public override void UploadCertificateFile(string path, byte[] certBytes)
        {
            Logger.Debug($"UploadCertificateFile: {path}");

            string uploadPath = path;
            string altPathOnly = string.Empty;
            string altFileNameOnly = string.Empty;

            if (ApplicationSettings.UseSeparateUploadFilePath)
            {
                SplitStorePathFile(path, out altPathOnly, out altFileNameOnly);
                uploadPath = ApplicationSettings.SeparateUploadFilePath + altFileNameOnly;
            }

            using (SftpClient client = new SftpClient(Connection))
            {
                try
                {
                    client.Connect();

                    using (MemoryStream stream = new MemoryStream(certBytes))
                    {
                        client.UploadFile(stream, FormatFTPPath(uploadPath));
                    }

                    if (ApplicationSettings.UseSeparateUploadFilePath)
                        RunCommand($"mv {uploadPath} {path}", null, ApplicationSettings.UseSudo, null);
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        public override byte[] DownloadCertificateFile(string path, bool hasBinaryContent)
        {
            Logger.Debug($"DownloadCertificateFile: {path}");

            string downloadPath = path;
            string altPathOnly = string.Empty;
            string altFileNameOnly = string.Empty;

            if (ApplicationSettings.UseSeparateUploadFilePath)
            {
                SplitStorePathFile(path, out altPathOnly, out altFileNameOnly);
                downloadPath = ApplicationSettings.SeparateUploadFilePath + altFileNameOnly;
            }

            using (SftpClient client = new SftpClient(Connection))
            {
                try
                {
                    client.Connect();

                    if (ApplicationSettings.UseSeparateUploadFilePath)
                        RunCommand($"cp {path} {downloadPath}", null, ApplicationSettings.UseSudo, null);

                    using (MemoryStream stream = new MemoryStream())
                    {
                        client.DownloadFile(FormatFTPPath(downloadPath), stream);
                        if (ApplicationSettings.UseSeparateUploadFilePath)
                            RunCommand($"rm {downloadPath}", null, ApplicationSettings.UseSudo, null);
                        return stream.ToArray();
                    }
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        public override void RemoveCertificateFile(string path)
        {
            Logger.Debug($"RemoveCertificateFile: {path}");

            using (SftpClient client = new SftpClient(Connection))
            {
                try
                {
                    client.Connect();
                    client.DeleteFile(FormatFTPPath(path));
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        public override void CreateEmptyStoreFile(string path)
        {
            RunCommand($"touch {path}", null, false, null);
            //using sudo will create as root. set useSudo to false 
            //to ensure ownership is with the credentials configued in the platform
        }

        private string ReplaceSpacesWithLF(string privateKey)
        {
            return privateKey.Replace(" RSA PRIVATE ", "^^^").Replace(" ", System.Environment.NewLine).Replace("^^^", " RSA PRIVATE ");
        }

        private string FormatFTPPath(string path)
        {
            return path.Substring(0, 1) == @"/" ? path : @"/" + path.Replace("\\", "/");
        }

        private void SplitStorePathFile(string pathFileName, out string path, out string fileName)
        {
            try
            {
                int separatorIndex = pathFileName.LastIndexOf(pathFileName.Substring(0, 1) == "/" ? @"/" : @"\");
                fileName = pathFileName.Substring(separatorIndex + 1);
                path = pathFileName.Substring(0, separatorIndex + 1);
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to parse certficate store/key path={pathFileName}.", ex);
            }
        }
    }
}
