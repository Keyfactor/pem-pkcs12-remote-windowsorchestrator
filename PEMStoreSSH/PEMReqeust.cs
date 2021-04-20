using System;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;

using Keyfactor.Platform.Extensions.Agents;

namespace PEMStoreSSH
{
    public partial class Management
    {
        private class PEMReqeust
        {

            private string _pfxPassword = String.Empty;
            public bool IsPfxFile { get; }
            public X509Certificate2 Certificate { get; }
            public string StorePath { get; }
            public string StorePassword { get; }
            public string KeyPath { get; }
            public bool HasSeparatePrivateKey { get; }
            
            public PEMReqeust(AnyJobConfigInfo config)
            {

                StorePath = config.Store.StorePath;
                StorePassword = config.Store.StorePassword;
                _pfxPassword = config.Job.PfxPassword;

                IsPfxFile = String.IsNullOrEmpty(config.Job.PfxPassword) ? false : true;

                if (IsPfxFile)
                {
                    Certificate = new X509Certificate2(Convert.FromBase64String(config.Job.EntryContents), _pfxPassword, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                }
                else
                {
                    Certificate = new X509Certificate2(Convert.FromBase64String(config.Job.EntryContents));
                }

                dynamic properties = JsonConvert.DeserializeObject(config.Store.Properties.ToString());
                HasSeparatePrivateKey = properties.separatePrivateKey == null || string.IsNullOrEmpty(properties.separatePrivateKey.Value) ? false : Boolean.Parse(properties.separatePrivateKey.Value);
                KeyPath= HasSeparatePrivateKey ? (properties.pathToPrivateKey == null || string.IsNullOrEmpty(properties.pathToPrivateKey.Value) ? null : properties.pathToPrivateKey.Value) : string.Empty;

            }   
        }
    }
}