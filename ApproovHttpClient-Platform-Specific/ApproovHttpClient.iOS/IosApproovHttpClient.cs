// MIT License
//
// Copyright (c) 2016-present, Critical Blue Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
// ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.IO;
using static ApproovSDK.iOS.Bind.Approov;
using Foundation;
using Security;
using System.Net.Http;
using ApproovSDK.iOS.Bind;

namespace Approov
{
    public class IosApproovHttpClient : ApproovHttpClient
    {
        /* Supported certificates by Approov: ECC256, ECC384, RSA2048 and RSA4096 */
        private static readonly int kSupportedCertCount = 4;
        /* SPKI headers for each key type and size */
        private static readonly byte[] rsa2048SPKIHeader = {
               0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
               0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
               0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
               };
        private static readonly byte[] rsa4096SPKIHeader = {
               0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09,
               0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
               0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
               };
        private static readonly byte[] ecdsaSecp256r1SPKIHeader = {
               0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
               0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
               0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
               0x42, 0x00
               };
        private static readonly byte[] ecdsaSecp384r1SPKIHeader = {
               0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
               0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
               0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
               };
        public IosApproovHttpClient() : this(new HttpClientHandler()) { }

        public IosApproovHttpClient(HttpMessageHandler handler) : base(handler)
        {
            // 1. Initialize Approov SDK
            if (!isApproovSDKInitialized)
            {
                string initialConfigString = ReadInitialApproovConfig();
                if (initialConfigString == null)
                {
                    throw new ApproovSDKException(TAG + "Error loading initial configuration string.");
                }
                string dynamicConfigString = ReadDynamicApproovConfig();
                bool statusInit = Initialize(initialConfigString, dynamicConfigString, null, out NSError error);
                isApproovSDKInitialized = statusInit;
                if (isApproovSDKInitialized)
                {
                    Console.WriteLine(TAG + "SDK initialized");
                }
                else
                    throw new ApproovSDKException(TAG + "Initialization failed: " + error.LocalizedDescription);
                // if we didn't have a dynamic configuration (after the first launch on the app) then
                // we fetch the latest and write it to local storage now
                if (dynamicConfigString == null)
                {
                    StoreApproovDynamicConfig(FetchConfig());
                }

            }
        }

        /**
        * Reads any previously-saved dynamic configuration for the Approov SDK. May return 'null' if a
        * dynamic configuration has not yet been saved by calling StoreApproovDynamicConfig().
        */
        string ReadDynamicApproovConfig()
        {
            NSString dynamicConfig = (NSString)NSUserDefaults.StandardUserDefaults.ValueForKey((NSString)ApproovDynamicKey);
            Console.WriteLine(TAG + "Dynamic configuration loaded");
            return dynamicConfig;
        }

        /*
        *  Reads the initial configuration file for the Approov SDK
        *  The file defined as kApproovInitialKey.kConfigFileExtension
        *  is read from the app bundle main directory
        */
        string ReadInitialApproovConfig()
        {
            string content = null;
            try
            {
                // Read the contents of our asset
                string filePath = NSBundle.MainBundle.PathForResource(ApproovInitialKey, ConfigFileExtension);
                if (filePath == null) return null;
                content = File.ReadAllText(filePath);
            }
            catch (Exception e)
            {
                Console.WriteLine(TAG + "Exception attempting to read initial config file. " + e.Message);
            }
            return content;
        }


        /**
         * Stores an application's dynamic configuration string in non-volatile storage.
         * The default implementation stores the string in shared preferences, and setting
         * the config string to null is equivalent to removing the config.
        */
        void StoreApproovDynamicConfig(string newConfig)
        {
            NSUserDefaults.StandardUserDefaults.SetString(newConfig, (NSString)ApproovDynamicKey);
            Console.WriteLine(TAG + "Dynamic configuration updated ");
        }

        /*
        *  Allows token prefetch operation to be performed as early as possible. This
        *  permits a token to be available while an application might be loading resources
        *  or is awaiting user input. Since the initial token fetch is the most
        *  expensive the prefetch seems reasonable.
        */
        public void PrefetchApproovToken()
        {
            if (isApproovSDKInitialized)
            {
                _ = HandleTokenFetchAsync();
            }
        }

        private async Task HandleTokenFetchAsync()
        {
            _ = await Task.Run(() => FetchApproovTokenAndWait("approov.io"));
        }

        /*
         *  Convenience function fetching the Approov token
         *
         */
        protected override void FetchApproovToken(string url, HttpRequestMessage message = null)
        {
            // Check if Bind Header is set to a non empty String
            lock (bindingHeaderLock)
            {
                if (BindingHeader != null)
                {
                    var headersToCheck = message == null ? DefaultRequestHeaders : message.Headers;
                    if (headersToCheck.Contains(BindingHeader))
                    {
                        // Returns all header values for a specified header stored in the HttpHeaders collection.
                        var headerValues = headersToCheck.GetValues(BindingHeader);
                        var enumerator = headerValues.GetEnumerator();
                        int i = 0;
                        string headerValue = null;
                        while (enumerator.MoveNext())
                        {
                            i++;
                            headerValue = enumerator.Current;
                        }
                        // Check that we have only one value
                        if (i != 1)
                        {
                            throw new ApproovSDKException(TAG + "Only one value can be used as binding header, detected " + i);
                        }
                        SetDataHashInToken(headerValue);
                    }
                    else
                    {
                        throw new ApproovSDKException(TAG + "Missing token binding header: " + BindingHeader);
                    }
                }
            }// lock

            // Invoke fetch token sync
            var approovResult = FetchApproovTokenAndWait(url);

            // Log result
            Console.WriteLine(TAG + "Approov token for host " + url + " : " + approovResult.LoggableToken());

            // Update dynamic config
            if (approovResult.IsConfigChanged())
            {
                StoreApproovDynamicConfig(FetchConfig());
            }

            // Check the status of the Approov token fetch
            if (approovResult.Status() == ApproovTokenFetchStatus.Success)
            {
                // we successfully obtained a token so add it to the header for the HttpClient or HttpRequestMessage
                if (message == null)
                {
                    DefaultRequestHeaders.Add(ApproovTokenHeader, ApproovTokenPrefix + approovResult.Token());
                }
                else
                {
                    if (message.Headers.Contains(ApproovTokenHeader))
                    {
                        message.Headers.Remove(ApproovTokenHeader);
                    }
                    message.Headers.Add(ApproovTokenHeader, ApproovTokenPrefix + approovResult.Token());
                }
            }
            else if ((approovResult.Status() == ApproovTokenFetchStatus.NoNetwork) ||
                   (approovResult.Status() == ApproovTokenFetchStatus.PoorNetwork) ||
                   (approovResult.Status() == ApproovTokenFetchStatus.MITMDetected))
            {
                // Must not proceed with network request and inform user a retry is needed
                throw new ApproovSDKException(TAG + "Retry attempt needed. " + approovResult.LoggableToken(), true);
            }
            else if ((approovResult.Status() == ApproovTokenFetchStatus.UnknownURL) ||
                 (approovResult.Status() == ApproovTokenFetchStatus.UnprotectedURL) ||
                 (approovResult.Status() == ApproovTokenFetchStatus.NoApproovService))
            {
                Console.WriteLine(TAG + "Will continue without Approov-Token");
            }
            else
            {
                throw new ApproovSDKException("Unknown approov token fetch result " + approovResult.Status());
            }

        }

        /*  Extract a public key from certificate and append to a header to all key types
            *  Returns nil if the key type in the certificate can not be recognized/extracted
            *  else base64 sha256 hashes of all combinations currently supported
            */
        string[] PublicKeyWithHeader(X509Certificate2 cert)
        {
            /* The return value */
            string[] allKeyWithHeaders = new string[kSupportedCertCount];
            int currentKeys = 0;
            /* We need to use ios native code to allow ECC public key extraction which is
             * not implemented in C#/Xamarin
             */
            byte[] rawData = cert.GetRawCertData();
            if (rawData == null)
            {
                return null;
            }
            SecCertificate secCertificate = new SecCertificate(rawData);

            // Get public key and its byte representation for later copy
            SecKey publicKey = secCertificate.GetPublicKey();
            byte[] publicKeyBytes = publicKey.GetExternalRepresentation().ToArray();

            /* Append combinations header + public key */
            // ECC P256
            byte[] keyECCP256WithHeader = new byte[ecdsaSecp256r1SPKIHeader.Length + publicKeyBytes.Length];
            ecdsaSecp256r1SPKIHeader.CopyTo(keyECCP256WithHeader, 0);
            publicKeyBytes.CopyTo(keyECCP256WithHeader, ecdsaSecp256r1SPKIHeader.Length);
            allKeyWithHeaders[currentKeys++] = base64Sha2StringFromBytes(keyECCP256WithHeader);
            // RSA2048
            byte[] keyRSA2048WithHeader = new byte[rsa2048SPKIHeader.Length + publicKeyBytes.Length];
            rsa2048SPKIHeader.CopyTo(keyRSA2048WithHeader, 0);
            publicKeyBytes.CopyTo(keyRSA2048WithHeader, rsa2048SPKIHeader.Length);
            allKeyWithHeaders[currentKeys++] = base64Sha2StringFromBytes(keyRSA2048WithHeader);
            // ECC P384
            byte[] keyECCP384WithHeader = new byte[ecdsaSecp384r1SPKIHeader.Length + publicKeyBytes.Length];
            ecdsaSecp384r1SPKIHeader.CopyTo(keyECCP384WithHeader, 0);
            publicKeyBytes.CopyTo(keyECCP384WithHeader, ecdsaSecp384r1SPKIHeader.Length);
            allKeyWithHeaders[currentKeys++] = base64Sha2StringFromBytes(keyECCP384WithHeader);
            // RSA4096
            byte[] keyRSA4096WithHeader = new byte[rsa4096SPKIHeader.Length + publicKeyBytes.Length];
            rsa4096SPKIHeader.CopyTo(keyRSA4096WithHeader, 0);
            publicKeyBytes.CopyTo(keyRSA4096WithHeader, rsa4096SPKIHeader.Length);
            allKeyWithHeaders[currentKeys++] = base64Sha2StringFromBytes(keyRSA4096WithHeader);

            return allKeyWithHeaders;
        }

        /* Computes sha256 of byte array and returns it in base64 format */
        string base64Sha2StringFromBytes(byte[] data)
        {
            SHA256 hash = SHA256.Create();
            byte[] hashBytes = hash.ComputeHash(data);
            string publicKeyBase64 = Convert.ToBase64String(hashBytes);
            return publicKeyBase64;
        }

        /*  TLS handshake inspection callback
         *
         */
        protected override Boolean ServerCallback(HttpRequestMessage sender, X509Certificate2 cert, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {

            if (sslPolicyErrors != SslPolicyErrors.None)
                return false;
            // Bug, see https://forums.xamarin.com/discussion/180066/httpclienthandler-servercertificatecustomvalidationcallback-receives-empty-certchain
            if (chain.ChainElements.Count == 0)
            {
                /*  BUG: See https://github.com/dotnet/runtime/issues/24527
                 *  This can fail if the public key is in ECC format 
                 */
                try
                {
                    chain.Build(certificate: cert);
                }
                catch (Exception e)
                {
                    Console.WriteLine(TAG + "Exception " + e.GetType().ToString() + " during chain.Build()");
                }

            }


            // 1. Get Approov pins
            NSDictionary<NSString, NSArray<NSString>> allPins = GetPins(kShaTypeString);
            if (allPins == null)
            {
                throw new ApproovSDKException(TAG + "Unable to obtain pins from SDK");
            }

            // 2. Get hostname => sender.RequestUri
            NSArray<NSString> allPinsForHost;
            NSString hostname = (NSString)sender.RequestUri.Host;
            if (!allPins.ContainsKey(hostname))
            {
                // 4. Host is not being pinned and we have succesfully checked certificate
                return true;
            }
            else
            {
                // 3. Check if host is being pinned and has no pins set
                bool status = allPins.TryGetValue(hostname, out allPinsForHost);
                if (!status)
                {
                    throw new ApproovSDKException(TAG + "Unable to obtain pin set from SDK for host " + hostname);
                }
                if (allPinsForHost.Count == 0)
                {
                    // Any pins for host allowed
                    return true;
                }
            }
            /* 5. Attempt to match PK pin to one in Approov SDK 
             *    We either iterate over the chain of certificates (if we managed to build one)
             *    or over the leaf certificate since Xamarin does not support ECC public keys
             */
            string[] pkiBytes;

            if (chain.ChainElements.Count > 0)
            {
                pkiBytes = new string[chain.ChainElements.Count * kSupportedCertCount];
                int usedCapacity = 0;
                // Get public keys with header from each element in chain
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    string[] certChainPKI = PublicKeyWithHeader(element.Certificate);
                    if (certChainPKI == null)
                    {
                        pkiBytes = null;
                        break;
                    }
                    certChainPKI.CopyTo(pkiBytes, usedCapacity);
                    usedCapacity += certChainPKI.Length;
                }
            }
            else
            {
                // We only use the leaf certificate
                pkiBytes = PublicKeyWithHeader(cert);
            }

            if (pkiBytes == null)
            {
                SHA256 certHash = SHA256.Create();
                byte[] certHashBytes = certHash.ComputeHash(cert.RawData);
                string certHashBase64 = Convert.ToBase64String(certHashBytes);
                throw new ApproovSDKException(TAG + " Failed to extract Public Key from certificate for host " + hostname + ". Cert hash: " + certHashBase64);
            }
            // 5.1 Iterate over available keys attempting to match one
            foreach (string pkiWithHeader in pkiBytes)
            {
                // Iterate over the list of pins and test each one
                foreach (string entry in allPinsForHost)
                {
                    if (entry.Equals(pkiWithHeader))
                    {
                        return true;
                    }
                }
            }
            // 5. No pins match
            return false;
        }


    } // ApproovHttpClient

}
