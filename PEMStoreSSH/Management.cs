// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;

using Keyfactor.Platform.Extensions.Agents;
using Keyfactor.Platform.Extensions.Agents.Enums;
using Keyfactor.Platform.Extensions.Agents.Delegates;
using Keyfactor.Platform.Extensions.Agents.Interfaces;

using CSS.Common.Logging;

using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;

namespace PEMStoreSSH
{
    public class Management: LoggingClientBase, IAgentJobExtension
    {
        public string GetJobClass()
        {
            return "Management";
        }

        public string GetStoreType()
        {
            return "PEM-SSH";
        }

        public AnyJobCompleteInfo processJob(AnyJobConfigInfo config, SubmitInventoryUpdate submitInventory, SubmitEnrollmentRequest submitEnrollmentRequest, SubmitDiscoveryResults sdr)
        {
            Logger.Debug($"Begin Management...");

            bool hasPassword = !string.IsNullOrEmpty(config.Job.PfxPassword);
            
            dynamic properties = JsonConvert.DeserializeObject(config.Store.Properties.ToString());
            bool hasSeparatePrivateKey = properties.separatePrivateKey == null || string.IsNullOrEmpty(properties.separatePrivateKey.Value) ? false : Boolean.Parse(properties.separatePrivateKey.Value);
            string privateKeyPath = hasSeparatePrivateKey ? (properties.pathToPrivateKey == null || string.IsNullOrEmpty(properties.pathToPrivateKey.Value) ? null : properties.pathToPrivateKey.Value) : string.Empty;
            
            if (properties.type == null || string.IsNullOrEmpty(properties.type.Value))
                throw new PEMException("Mising certificate store Type.  Please ensure store is defined as either PEM or PKCS12.");
            if (hasSeparatePrivateKey && string.IsNullOrEmpty(privateKeyPath))
                throw new PEMException("Certificate store is set has having a separate private key but no private key path is specified in the store definition.");
            
            PEMStore pemStore = new PEMStore(config.Store.ClientMachine, config.Server.Username, config.Server.Password, config.Store.StorePath, config.Store.StorePassword, Enum.Parse(typeof(PEMStore.FormatTypeEnum), properties.type.Value, true), 
            privateKeyPath);

            if (properties.isSingleCertificateStore != null && !string.IsNullOrEmpty(properties.isSingleCertificateStore.Value))
                pemStore.IsSingleCertificateStore = Boolean.Parse(properties.isSingleCertificateStore.Value);

            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                switch (config.Job.OperationType)
                {
                    case AnyJobOperationType.Add:
                        bool storeExists = pemStore.DoesStoreExist(config.Store.StorePath);

                        if (ApplicationSettings.CreateStoreOnAddIfMissing && !storeExists)
                        {
                            pemStore.CreateEmptyStoreFile(config.Store.StorePath);
                            if (hasSeparatePrivateKey && privateKeyPath != null)
                                pemStore.CreateEmptyStoreFile(privateKeyPath);
                        }

                        if (!ApplicationSettings.CreateStoreOnAddIfMissing && !storeExists)
                            throw new PEMException($"Certificate store {config.Store.StorePath} does not exist.");

                        pemStore.AddCertificateToStore(config.Job.EntryContents, config.Job.Alias, config.Job.PfxPassword, config.Store.StorePassword, config.Job.Overwrite, hasPassword);

                        break;

                    case AnyJobOperationType.Remove:
                        if (!pemStore.DoesStoreExist(config.Store.StorePath))
                            throw new PEMException($"Certificate store {config.Store.StorePath} does not exist.");

                        pemStore.RemoveCertificate(config.Job.Alias);

                        break;

                    case AnyJobOperationType.Create:
                        if (pemStore.DoesStoreExist(config.Store.StorePath))
                            throw new PEMException($"Certificate store {config.Store.StorePath} already exists and cannot be created.");

                        pemStore.CreateEmptyStoreFile(config.Store.StorePath);
                        if (hasSeparatePrivateKey && privateKeyPath != null)
                            pemStore.CreateEmptyStoreFile(privateKeyPath);

                        break;

                    default:
                        return new AnyJobCompleteInfo() { Status = 4, Message = $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}: Unsupported operation: {config.Job.OperationType.ToString()}" };
                }
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }

            return new AnyJobCompleteInfo() { Status = 2, Message = "Successful" };
        }
    }
}