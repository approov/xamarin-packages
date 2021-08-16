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
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.IO;
using Android.Content;
using Android.Content.Res;
using System.Collections.Generic;
using static Com.Criticalblue.Approovsdk.Approov;

namespace Approov
{
    public class AndroidApproovHttpClient : ApproovHttpClient
    {
        public AndroidApproovHttpClient() : this(new HttpClientHandler()) { }

        public AndroidApproovHttpClient(HttpMessageHandler handler) : base(handler)
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
                try
                {
                    Initialize(Android.App.Application.Context, initialConfigString, dynamicConfigString, null);
                    isApproovSDKInitialized = true;
                    Console.WriteLine(TAG + "SDK initialized");
                    // if we didn't have a dynamic configuration (after the first launch on the app) then
                    // we fetch the latest and write it to local storage now
                    if (dynamicConfigString == null)
                    {
                        StoreApproovDynamicConfig(FetchConfig());
                    }
                }
                catch (Exception e)
                {
                    throw new ApproovSDKException(TAG + "Initialization failed: " + e.Message);
                }
            }
        }

        /**
        * Reads any previously-saved dynamic configuration for the Approov SDK. May return 'null' if a
        * dynamic configuration has not yet been saved by calling StoreApproovDynamicConfig().
        */
        string ReadDynamicApproovConfig()
        {
            ISharedPreferences prefs = Android.App.Application.Context.GetSharedPreferences(ApproovPreferencesKey, 0);
            Console.WriteLine(TAG + "Dynamic configuration loaded");
            return prefs.GetString(ApproovDynamicKey, null);
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
                AssetManager assets = Android.App.Application.Context.Assets;
                using StreamReader sr = new StreamReader(assets.Open(ApproovInitialKey + ConfigFileExtension));
                content = sr.ReadToEnd();
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
            Console.WriteLine(TAG + "Dynamic configuration updated ");
            ISharedPreferences prefs = Android.App.Application.Context.GetSharedPreferences(ApproovPreferencesKey, 0);
            ISharedPreferencesEditor editor = prefs.Edit();
            editor.PutString(ApproovDynamicKey, newConfig);
            editor.Apply();
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

            // Hold the fetch status in a variable
            var aFetchStatus = approovResult.Status;

            // Log result
            Console.WriteLine(TAG + "Approov token for host " + url + " : " + approovResult.LoggableToken);

            // Update dynamic config
            if (approovResult.IsConfigChanged)
            {
                StoreApproovDynamicConfig(FetchConfig());
            }

            // Check the status of the Approov token fetch
            if (aFetchStatus == TokenFetchStatus.Success)
            {
                // we successfully obtained a token so add it to the header for the HttpClient or HttpRequestMessage
                if (message == null)
                {
                    DefaultRequestHeaders.Add(ApproovTokenHeader, ApproovTokenPrefix + approovResult.Token);
                }
                else
                {
                    if (message.Headers.Contains(ApproovTokenHeader))
                    {
                        message.Headers.Remove(ApproovTokenHeader);
                    }
                    message.Headers.Add(ApproovTokenHeader, ApproovTokenPrefix + approovResult.Token);
                }
            }
            else if ((aFetchStatus == TokenFetchStatus.NoNetwork) ||
                   (aFetchStatus == TokenFetchStatus.PoorNetwork) ||
                   (aFetchStatus == TokenFetchStatus.MitmDetected))
            {
                // Must not proceed with network request and inform user a retry is needed
                throw new ApproovSDKException(TAG + "Retry attempt needed. " + approovResult.LoggableToken, true);
            }
            else if ((aFetchStatus == TokenFetchStatus.UnknownUrl) ||
                 (aFetchStatus == TokenFetchStatus.UnprotectedUrl) ||
                 (aFetchStatus == TokenFetchStatus.NoApproovService))
            {
                Console.WriteLine(TAG + "Will continue without Approov-Token");
            }
            else
            {
                throw new ApproovSDKException("Unknown approov token fetch result " + aFetchStatus);
            }

        }

        /* TLS hanshake callback */

        /*  Extract a public key from certificate and append to a header specific to the key type
         *  Returns nil if the key type in the certificate can not be recognized/extracted
         */
        byte[] PublicKeyWithHeader(X509Certificate2 cert)
        {
            /* We need to use java native code to allow ECC public key extraction which is
             * not implemented in C#/Xamarin
             */
            byte[] rawData = cert.GetRawCertData();
            Java.Security.Cert.CertificateFactory certFactory = Java.Security.Cert.CertificateFactory.GetInstance("X.509");
            System.IO.Stream inputBytes = new System.IO.MemoryStream(rawData);
            try
            {
                var javaCert = certFactory.GenerateCertificate(inputBytes);
                Java.Security.IPublicKey publicKey = javaCert.PublicKey;

                byte[] encoded = publicKey.GetEncoded();
                if (encoded == null)
                {
                    // Return null and let caller throw an exception with hostname
                    return null;
                }
                return encoded;
            }
            catch (Java.Security.Cert.CertificateException e)
            {
                Console.WriteLine(TAG + "Unable to generate certificate: " + e.Message);
                return null;
            }

        }

        /*  TLS handshake inspection callback
         *
         */
        protected override Boolean ServerCallback(HttpRequestMessage sender, X509Certificate2 cert, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {

            if (sslPolicyErrors != SslPolicyErrors.None)
                return false;
            if (chain.ChainElements.Count == 0)
                throw new ApproovSDKException(TAG + "Empty certificate chain from callback function.");
            // 1. Get Approov pins
            IDictionary<string, IList<string>> allPins = GetPins(kShaTypeString);
            if (allPins == null)
            {
                throw new ApproovSDKException(TAG + "Unable to obtain pins from SDK");
            }

            // 2. Get hostname => sender.RequestUri
            IList<string> allPinsForHost;
            string hostname = sender.RequestUri.Host;
            if (!allPins.ContainsKey(hostname))
            {
                // 4. Host is not being pinned and we have succesfully checked certificate chain
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
            // 5. Iterate over certificate chain and attempt to match PK pin to one in Approov SDK
            foreach (X509ChainElement element in chain.ChainElements)
            {
                var certificate = element.Certificate;

                byte[] pkiBytes = PublicKeyWithHeader(certificate);
                if (pkiBytes == null)
                {
                    SHA256 certHash = SHA256.Create();
                    byte[] certHashBytes = certHash.ComputeHash(certificate.RawData);
                    string certHashBase64 = Convert.ToBase64String(certHashBytes);
                    throw new ApproovSDKException(TAG + " Failed to extract Public Key from certificate for host " + hostname + ". Cert hash: " + certHashBase64);
                }
                SHA256 hash = SHA256.Create();
                byte[] hashBytes = hash.ComputeHash(pkiBytes);
                string publicKeyBase64 = Convert.ToBase64String(hashBytes);

                // Iterate over the list of pins and test each one
                foreach (string entry in allPinsForHost)
                {
                    if (entry.Equals(publicKeyBase64))
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
