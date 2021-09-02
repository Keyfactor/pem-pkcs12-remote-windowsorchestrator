// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace PEMStoreSSH.RemoteHandlers
{
    class WinRMHandler : BaseRemoteHandler
    {
        internal WinRMHandler(string server, string serverLogin, string serverPassword)
        {
            if (string.IsNullOrEmpty(server))
                throw new PEMException("Blank or missing server name for server orchestration.");

            Server = server;
        }

        public override string RunCommand(string commandText, object[] parameters, bool withSudo, string[] passwordsToMaskInLog)
        {
            Logger.Debug($"RunCommand: {Server}");

            try
            {
                WSManConnectionInfo connectionInfo = new WSManConnectionInfo(new System.Uri($"{Server}/wsman"));
                if (ApplicationSettings.UseNegotiateAuth)
                {
                    connectionInfo.AuthenticationMechanism = AuthenticationMechanism.Negotiate;
                }
                Logger.Trace($"WinRM Authentication Mechanism: {Enum.GetName(typeof(AuthenticationMechanism), connectionInfo.AuthenticationMechanism)}");

                using (Runspace runspace = RunspaceFactory.CreateRunspace(connectionInfo))
                {
                    runspace.Open();
                    using (PowerShell ps = PowerShell.Create())
                    {
                        ps.Runspace = runspace;

                        if (commandText.ToLower().IndexOf("keytool") > -1)
                            commandText = "echo '' | " + commandText;
                        ps.AddScript(commandText);

                        string displayCommand = commandText;
                        if (passwordsToMaskInLog != null)
                        {
                            foreach (string password in passwordsToMaskInLog)
                                displayCommand = displayCommand.Replace(password, PASSWORD_MASK_VALUE);
                        }

                        if (parameters != null)
                        {
                            foreach (object parameter in parameters)
                                ps.AddArgument(parameter);
                        }

                        Logger.Debug($"RunCommand: {displayCommand}");
                        System.Collections.ObjectModel.Collection<PSObject> psResult = ps.Invoke(parameters);
                        string result = string.Empty;

                        if (ps.HadErrors)
                        {
                            string errors = string.Empty;
                            System.Collections.ObjectModel.Collection<ErrorRecord> errorRecords = ps.Streams.Error.ReadAll();
                            foreach (ErrorRecord errorRecord in errorRecords)
                                errors += (errorRecord.ToString() + "   ");

                            throw new ApplicationException(errors);
                        }
                        else
                        {
                            result = FormatResult(psResult);
                            Logger.Debug($"WinRM Results: {displayCommand}::: {result}");
                        }


                        return result;
                    }
                }
            }

            catch (Exception ex)
            {
                Logger.Debug("Exception during RunCommand...{ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                throw ex;
            }
        }

        public override bool DoesFileExist(string path)
        {
            Logger.Debug($"DoesFileExist: {path}");

            return Convert.ToBoolean(RunCommand($@"Test-Path -path ""{path}""", null, false, null));
        }

        public override void UploadCertificateFile(string path, byte[] certBytes)
        {
            Logger.Debug($"UploadCertificateFile: {path}");

            string scriptBlock = $@"
                                    param($contents)
                                
                                    Set-Content ""{path}"" -Encoding Byte -Value $contents
                                ";

            object[] arguments = new object[] { certBytes };

            RunCommand(scriptBlock, arguments, false, null);
        }

        public override byte[] DownloadCertificateFile(string path, bool hasBinaryContent)
        {
            Logger.Debug($"DownloadCertificateFile: {path}");

            if (hasBinaryContent)
                return RunCommandBinary($@"Get-Content -Path ""{path}"" -Encoding Byte -Raw");
            else
                return Encoding.ASCII.GetBytes(RunCommand($@"Get-Content -Path ""{path}""", null, false, null));
        }

        public override void RemoveCertificateFile(string path)
        {
            Logger.Debug($"RemoveCertificateFile: {path}");

            RunCommand($@"rm ""{path}""", null, false, null);
        }
        
        public override void CreateEmptyStoreFile(string path)
        {
            RunCommand($@"Out-File -FilePath ""{path}""", null, false, null);
        }


        private byte[] RunCommandBinary(string commandText)
        {
            Logger.Debug($"RunCommandBinary: {Server}");
            byte[] rtnBytes = new byte[0];

            try
            {
                using (Runspace runspace = RunspaceFactory.CreateRunspace(new WSManConnectionInfo(new System.Uri($"{Server}/wsman"))))
                {
                    runspace.Open();
                    using (PowerShell ps = PowerShell.Create())
                    {
                        ps.Runspace = runspace;
                        ps.AddScript(commandText);

                        Logger.Debug($"RunCommandBinary: {commandText}");
                        System.Collections.ObjectModel.Collection<PSObject> psResult = ps.Invoke();

                        if (ps.HadErrors)
                        {
                            string errors = string.Empty;
                            System.Collections.ObjectModel.Collection<ErrorRecord> errorRecords = ps.Streams.Error.ReadAll();
                            foreach (ErrorRecord errorRecord in errorRecords)
                                errors += (errorRecord.ToString() + "   ");

                            throw new ApplicationException(errors);
                        }
                        else
                        {
                            if (psResult.Count > 0)
                                rtnBytes = (byte[])psResult[0].BaseObject;
                            Logger.Debug($"WinRM Results: {commandText}::: binary results.");
                        }
                    }
                }

                return rtnBytes;
            }

            catch (Exception ex)
            {
                Logger.Debug("Exception during RunCommandBinary...{ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                throw ex;
            }
        }

        private string FormatResult(ICollection<PSObject> results)
        {
            StringBuilder rtn = new StringBuilder();

            foreach (PSObject resultLine in results)
            {
                if (resultLine != null)
                    rtn.Append(resultLine.ToString() + System.Environment.NewLine);
            }

            return rtn.ToString();
        }

        private string ReplaceSpacesWithLF(string privateKey)
        {
            return privateKey.Replace(" RSA PRIVATE ", "^^^").Replace(" ", System.Environment.NewLine).Replace("^^^", " RSA PRIVATE ");
        }

        private string FormatFTPPath(string path)
        {
            return path.Substring(0, 1) == @"/" ? path : @"/" + path.Replace("\\", "/");
        }
    }
}
