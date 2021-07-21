// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json;

using Keyfactor.Platform.Extensions.Agents;
using Keyfactor.Platform.Extensions.Agents.Enums;
using Keyfactor.Platform.Extensions.Agents.Delegates;
using Keyfactor.Platform.Extensions.Agents.Interfaces;

using CSS.Common.Logging;


namespace PEMStoreSSH
{
    public class Inventory: LoggingClientBase, IAgentJobExtension
    {
        public string GetJobClass()
        {
            return "Inventory";
        }

        public string GetStoreType()
        {
            return "PEM-SSH";
        }

        public AnyJobCompleteInfo processJob(AnyJobConfigInfo config, SubmitInventoryUpdate submitInventory, SubmitEnrollmentRequest submitEnrollmentRequest, SubmitDiscoveryResults sdr)
        {
            Logger.Debug($"Begin Inventory.......");

            List<AgentCertStoreInventoryItem> inventoryItems = new List<AgentCertStoreInventoryItem>();
            X509Certificate2Collection certificates = new X509Certificate2Collection();
            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                dynamic properties = JsonConvert.DeserializeObject(config.Store.Properties.ToString());
                Logger.Debug($"Properties: {properties}");
                bool hasSeparatePrivateKey = properties.separatePrivateKey == null || string.IsNullOrEmpty(properties.separatePrivateKey.Value) ? false : Boolean.Parse(properties.separatePrivateKey.Value);
                string privateKeyPath = hasSeparatePrivateKey ? (properties.pathToPrivateKey == null || string.IsNullOrEmpty(properties.pathToPrivateKey.Value) ? null : properties.pathToPrivateKey.Value) : string.Empty;
                Logger.Debug($"Path to Key: {privateKeyPath}");
                if (properties.type == null ||  string.IsNullOrEmpty(properties.type.Value))
                    throw new PEMException("Mising certificate store Type.  Please ensure store is defined as either PEM or PKCS12.");
                if (hasSeparatePrivateKey && string.IsNullOrEmpty(privateKeyPath))
                    throw new PEMException("Certificate store is set has having a separate private key but no private key path is specified in the store definition.");


                PEMStore pemStore = new PEMStore(config.Store.ClientMachine, config.Server.Username, config.Server.Password, config.Store.StorePath, config.Store.StorePassword, Enum.Parse(typeof(PEMStore.FormatTypeEnum), properties.type.Value), privateKeyPath);

                bool containsPrivateKey;
                certificates = pemStore.GetCertificates(config.Store.StorePassword, out containsPrivateKey);
                bool isAChain = containsPrivateKey && certificates.Count > 1;

                if (isAChain)
                {
                    List<string> certList = new List<string>();
                    foreach(X509Certificate2 certificate in certificates)
                        certList.Add(Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));

                    inventoryItems.Add(new AgentCertStoreInventoryItem()
                    {
                        ItemStatus = AgentInventoryItemStatus.Unknown,
                        Alias = string.IsNullOrEmpty(certificates[0].FriendlyName) ? certificates[0].Thumbprint : certificates[0].FriendlyName,
                        PrivateKeyEntry = containsPrivateKey,
                        UseChainLevel = isAChain,
                        Certificates = certList.ToArray()
                    });
                }
                else
                {
                    foreach (X509Certificate2 certificate in certificates)
                    {
                        inventoryItems.Add(new AgentCertStoreInventoryItem()
                        {
                            ItemStatus = AgentInventoryItemStatus.Unknown,
                            Alias = string.IsNullOrEmpty(certificates[0].FriendlyName) ? certificates[0].Thumbprint : certificates[0].FriendlyName,
                            PrivateKeyEntry = containsPrivateKey,
                            UseChainLevel = isAChain,
                            Certificates = new string[] { Convert.ToBase64String(certificate.Export(X509ContentType.Cert)) }
                        });
                    }
                }

            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }

            try
            {
                submitInventory.Invoke(inventoryItems);
                return new AnyJobCompleteInfo() { Status = certificates.Count == 0 ? 3 : 2, Message = certificates.Count == 0 ? 
                    $"No certificates found in store {config.Store.StorePath} on server {config.Store.ClientMachine}" : "Successful" };
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }
        }
    }
}