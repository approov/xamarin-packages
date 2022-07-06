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
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

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
        private static string configUsed = null;
        /* Creates new iOS Approov HttpClient
         * @param   approov config string
         */
        public IosApproovHttpClient(string config) : this(new HttpClientHandler(), config) { }

        /* Creates new iOS Approov HttpClient
         * @param   custom message handler
         * @param   approov config string
         */
        public IosApproovHttpClient(HttpMessageHandler handler, string config) : base(handler)
        {
            lock (InitializerLock)
            {
                // 1. Initialize Approov SDK
                if (!ApproovSDKInitialized)
                {
                    // We do not accept null config string
                    if (config == null)
                    {
                        throw new ConfigurationFailureException(TAG + "Error: null config string");
                    }
                    // Check if attempting to use a different config string
                    if ((configUsed != null) && (configUsed != config)) {
                        throw new ConfigurationFailureException(TAG + "Error: SDK already initialized");
                    }
                    // Init the SDK
                    bool statusInit = Initialize(config, "auto", null, out NSError error);
                    ApproovSDKInitialized = statusInit;
                    if (ApproovSDKInitialized)
                    {
                        Console.WriteLine(TAG + "SDK initialized");
                    }
                    else
                    {
                        throw new InitializationFailureException(TAG + "SDK Initialization failed: " + error.LocalizedDescription);
                    }
                    SetUserProperty("approov-service-xamarin");
                }
            }
        }


        /*
        *  Allows token prefetch operation to be performed as early as possible. This
        *  permits a token to be available while an application might be loading resources
        *  or is awaiting user input. Since the initial token fetch is the most
        *  expensive the prefetch seems reasonable.
        */
        public void Prefetch()
        {
            lock (InitializerLock)
            {
                if (ApproovSDKInitialized)
                {
                    _ = HandleTokenFetchAsync();
                }
            }
        }

        private async Task HandleTokenFetchAsync()
        {
            _ = await Task.Run(() => FetchApproovTokenAndWait("approov.io"));
        }

        /*
         *  Convenience function updating a set of request headers with Approov
         *  If the message paraameter is NOT null, the message headers are modified
         *  If the message parameter is null, then the default request headers are modified
         */
        protected override HttpRequestMessage UpdateRequestHeadersWithApproov(string url, HttpRequestMessage message = null)
        {
            // The return value
            HttpRequestMessage returnMessage;
            // Are we using the DefaultRequestHeaders?
            bool usingDefaultRequestHeaders = false;
            // Copy the message
            if (message != null) returnMessage = message;
            else
            {
                // If message is null, we ignore the headers since we are meant to use the DefaultRequestHeaders
                returnMessage = new HttpRequestMessage();
                returnMessage.RequestUri = new Uri(url);
                //returnMessage.Headers = null;  //<= This is impossible to do
                usingDefaultRequestHeaders = true;
            }
            // Check if the URL matches one of the exclusion regexs and just return if it does
            if (CheckURLIsExcluded(url)) {
                Console.WriteLine(TAG + "FetchApproovToken excluded url " + url);
                return returnMessage;
            }
            // The Request Headers to check/modify. Note we can point this to the DefaultRequestHeaders or message.Headers later
            var headersToCheck = message == null ? DefaultRequestHeaders : returnMessage.Headers;
            // Check if Bind Header is set to a non empty String
            lock (BindingHeaderLock)
            {
                if (BindingHeader != null)
                {
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
                            throw new ConfigurationFailureException(TAG + "Only one value can be used as binding header, detected " + i);
                        }
                        SetDataHashInToken(headerValue);
                        // TODO: should we log?
                        Console.WriteLine(TAG + "bindheader set: " + headerValue);
                    } else if (!usingDefaultRequestHeaders)
                    {
                        // We are iterating over the message headers and found no match; we must check the DefaultRequestHeaders
                        // Returns all header values for a specified header stored in the HttpHeaders collection.
                        var headerValues = DefaultRequestHeaders.GetValues(BindingHeader);
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
                            throw new ConfigurationFailureException(TAG + "Only one value can be used as binding header, detected " + i);
                        }
                        SetDataHashInToken(headerValue);
                        // TODO: should we log?
                        Console.WriteLine(TAG + "bindheader set: " + headerValue);
                    }
                    else
                    {
                        throw new ConfigurationFailureException(TAG + "Missing token binding header: " + BindingHeader);
                    }
                }
            }// lock

            // Invoke fetch token sync
            var approovResult = FetchApproovTokenAndWait(url);

            // Log result
            Console.WriteLine(TAG + "Approov token for " + url + " : " + approovResult.LoggableToken());

            // Check the status of the Approov token fetch
            if (approovResult.Status() == ApproovTokenFetchStatus.Success)
            {
                // we successfully obtained a token so add it to the header for the HttpClient or HttpRequestMessage
                // Check if the request headers already contains an ApproovTokenHeader (from previous request, etc)
                // TODO: SHould I always clear the DefaultHeaders anyway?
                if (headersToCheck.Contains(ApproovTokenHeader))
                {
                    if (!headersToCheck.Remove(ApproovTokenHeader)) {
                        // We could not remove the original header
                        throw new ApproovSDKException(TAG + "Failed removing header: " + ApproovTokenHeader);
                    }
                }
                headersToCheck.Add(ApproovTokenHeader, ApproovTokenPrefix + approovResult.Token());
            }
            else if ((approovResult.Status() == ApproovTokenFetchStatus.NoNetwork) ||
                   (approovResult.Status() == ApproovTokenFetchStatus.PoorNetwork) ||
                   (approovResult.Status() == ApproovTokenFetchStatus.MITMDetected))
            {
                /* We are unable to get the secure string due to network conditions so the request can
                *  be retried by the user later
                *  We are unable to get the secure string due to network conditions, so - unless this is
                *  overridden - we must not proceed. The request can be retried by the user later.
                */
                if (!ProceedOnNetworkFail)
                {
                    // Must not proceed with network request and inform user a retry is needed
                    throw new NetworkingErrorException(TAG + "Retry attempt needed. " + approovResult.LoggableToken(), true);
                }
            }
            else if ((approovResult.Status() == ApproovTokenFetchStatus.UnknownURL) ||
                 (approovResult.Status() == ApproovTokenFetchStatus.UnprotectedURL) ||
                 (approovResult.Status() == ApproovTokenFetchStatus.NoApproovService))
            {
                Console.WriteLine(TAG + "Will continue without Approov-Token");
            }
            else
            {
                throw new PermanentException("Unknown approov token fetch result " + approovResult.Status());
            }

            /* We only continue additional processing if we had a valid status from Approov, to prevent additional delays
             * by trying to fetch from Approov again and this also protects against header substitutions in domains not
             * protected by Approov and therefore are potentially subject to a MitM.
             */ 
            if ((approovResult.Status() != ApproovTokenFetchStatus.Success) &&
                (approovResult.Status() != ApproovTokenFetchStatus.UnprotectedURL))
            {
                // TODO: We have already added the token
                return returnMessage;
            }

            /* We now have to deal with any substitution headers */
            // Make a copy of original dictionary
            Dictionary<string,string> originalSubstitutionHeaders;
            lock (SubstitutionHeadersLock) {
                originalSubstitutionHeaders = new Dictionary<string, string>(SubstitutionHeaders);
            }
            // Iterate over the copied dictionary
            foreach (KeyValuePair<string, string> entry in originalSubstitutionHeaders) {
                string header = entry.Key;
                string prefix = entry.Value; // can be null
                // Check if prefix for a given header is not null
                if (prefix == null) prefix = "";
                string value = null;
                if (headersToCheck.TryGetValues(header, out IEnumerable<string> values))
                {
                    value = values.First();
                }
                // The request headers do NOT contain the header needing replaced
                // NOTE: we must check the default request headers also, since the might contain the header
                if (value == null) {
                    // Try to find the header in the DafultRequestHeaders (if not searched)
                    if (usingDefaultRequestHeaders) continue; // Try to get next key:value pair
                    // point the headers to check to the DefaultRequestHeaders and search again
                    headersToCheck = DefaultRequestHeaders;
                    if (headersToCheck.TryGetValues(header, out IEnumerable<string> alsoValues))
                    {
                        value = alsoValues.First();
                    }
                    if (value == null) continue;    // None of the available headers contain the value
                }  // TODO: should we throw ConfigurationFailure since headers to replace are missing?
                // Check if the request contains the header we want to replace
                if (value.StartsWith(prefix) && (value.Length > prefix.Length)) {   // TODO: why second check?
                    string stringValue = value.Substring(prefix.Length);
                    var approovResults = FetchSecureStringAndWait(stringValue, null);
                    Console.WriteLine(TAG + "Substituting header: " + header + ", " +
                        StringFromApproovTokenFetchStatus(approovResults.Status()));
                    // Process the result of the token fetch operation
                    if (approovResults.Status() == ApproovTokenFetchStatus.Success)
                    {
                        // We add the modified header to the request after removing duplicate
                        if (approovResults.SecureString() != null)
                        {
                            if (headersToCheck.Contains(header))
                            {
                                if (!headersToCheck.Remove(header))
                                {
                                    // We could not remove the original header
                                    throw new ApproovSDKException(TAG + "Failed removing header: " + header);
                                }
                            }
                            headersToCheck.Add(header, prefix + approovResults.SecureString());
                        }
                        else {
                            // Secure string is null
                            throw new ApproovSDKException(TAG + " null return from secure message fetch");
                        }
                    }
                    else if (approovResults.Status() == ApproovTokenFetchStatus.Rejected)
                    {
                        // if the request is rejected then we provide a special exception with additional information
                        string localARC = approovResults.ARC();
                        string localReasons = approovResults.RejectionReasons();
                        throw new RejectionException(TAG + "secure message rejected", arc: localARC, rejectionReasons: localReasons);
                    }
                    else if (approovResults.Status() == ApproovTokenFetchStatus.NoNetwork ||
                            approovResults.Status() == ApproovTokenFetchStatus.PoorNetwork ||
                            approovResults.Status() == ApproovTokenFetchStatus.MITMDetected)
                    {
                        /* We are unable to get the secure string due to network conditions so the request can
                        *  be retried by the user later
                        *  We are unable to get the secure string due to network conditions, so - unless this is
                        *  overridden - we must not proceed. The request can be retried by the user later.
                        */
                        if (!ProceedOnNetworkFail) {
                            // We throw
                            throw new NetworkingErrorException(TAG + "Header substitution: network issue, retry needed");
                        }
                    }
                    else if (approovResults.Status() == ApproovTokenFetchStatus.UnknownKey) {
                        // we have failed to get a secure string with a more serious permanent error
                        throw new PermanentException(TAG + "Header substitution: " +
                            StringFromApproovTokenFetchStatus(approovResults.Status()));
                    }
                } // if (value.StartsWith ...
            }
            //end
            // Reset the headersToCheck
            headersToCheck = message == null ? DefaultRequestHeaders : returnMessage.Headers;
            /* Finally, we deal with any query parameter substitutions, which may require further fetches but these
             * should be using cached results */
            // Make a copy of original substitutionQuery set
            HashSet<string> originalQueryParams;
            lock (SubstitutionQueryParamsLock)
            {
                originalQueryParams = new HashSet<string>(SubstitutionQueryParams);
            }
            foreach (string entry in originalQueryParams) {
                string urlString = url;
                // TODO: this throws so document exception?
                string pattern = entry;
                Regex regex = new Regex(pattern, RegexOptions.ECMAScript);
                // See if there is any match
                MatchCollection matchedPatterns = regex.Matches(urlString);
                // We skip Group at index 0 as this is the match (e.g. ?Api-Key=api_key_placeholder) for the whole
                // regex, but we only want to replace the query parameter value part (e.g. api_key_placeholder)
                for (int count = 0; count < matchedPatterns.Count; count++) {
                    // We must have 2 Groups, the first being the full pattern and the second one the query parameter
                    if (matchedPatterns[count].Groups.Count != 2) continue;
                    string matchedText = matchedPatterns[count].Groups[1].Value;
                    var approovResults = FetchSecureStringAndWait(matchedText, null);
                    if (approovResults.Status() == ApproovTokenFetchStatus.Success)
                    {
                        // Replace the ocureences and modify the URL
                        string newURL = urlString.Replace(matchedText, approovResults.SecureString());
                        // TODO: should we log?
                        Console.WriteLine(TAG + "replacing url with " + newURL);
                        message.RequestUri = new Uri(newURL);
                    }
                    else if (approovResults.Status() == ApproovTokenFetchStatus.Rejected) {
                        // if the request is rejected then we provide a special exception with additional information
                        string localARC = approovResults.ARC();
                        string localReasons = approovResults.RejectionReasons();
                        throw new RejectionException(TAG + "secure message rejected", arc: localARC, rejectionReasons: localReasons);
                    }
                    else if (approovResults.Status() == ApproovTokenFetchStatus.NoNetwork ||
                            approovResults.Status() == ApproovTokenFetchStatus.PoorNetwork ||
                            approovResults.Status() == ApproovTokenFetchStatus.MITMDetected) {
                        /* We are unable to get the secure string due to network conditions so the request can
                        *  be retried by the user later
                        *  We are unable to get the secure string due to network conditions, so - unless this is
                        *  overridden - we must not proceed. The request can be retried by the user later.
                        */
                        if (!ProceedOnNetworkFail)
                        {
                            // We throw
                            throw new NetworkingErrorException(TAG + "Header substitution: network issue, retry needed");
                        }
                    }
                    else if (approovResults.Status() == ApproovTokenFetchStatus.UnknownKey)
                    {
                        // we have failed to get a secure string with a more serious permanent error
                        throw new PermanentException(TAG + "Query parameter substitution error: " +
                            StringFromApproovTokenFetchStatus(approovResults.Status()));
                    }
                }
            }// foreach
            // We return the new message
            return returnMessage;
        }// UpdateRequestWithApproov


        /*
         * Fetches a secure string with the given key. If newDef is not nil then a secure string for
         * the particular app instance may be defined. In this case the new value is returned as the
         * secure string. Use of an empty string for newDef removes the string entry. Note that this
         * call may require network transaction and thus may block for some time, so should not be called
         * from the UI thread. If the attestation fails for any reason then an exception is raised. Note
         * that the returned string should NEVER be cached by your app, you should call this function when
         * it is needed. If the fetch fails for any reason an exception is thrown with description. Exceptions
         * could be due to the feature not being enabled from the CLI tools ...
         *
         * @param key is the secure string key to be looked up
         * @param newDef is any new definition for the secure string, or nil for lookup only
         * @return secure string (should not be cached by your app) or nil if it was not defined or an error ocurred
         * @throws exception with description of cause
         */
        public static string FetchSecureString(string key, string newDef) {
            string type = "lookup";
            if (newDef != null) {
                type = "definition";
            }
            // Invoke fetchSecureString
            var approovResults = FetchSecureStringAndWait(key, newDef);
            Console.WriteLine(TAG + "FetchSecureString: " + type + " " + StringFromApproovTokenFetchStatus(approovResults.Status()));
            if (approovResults.Status() == ApproovTokenFetchStatus.Disabled) {
                throw new ConfigurationFailureException(TAG + "FetchSecureString:  secure message string feature is disabled");
            } else if (approovResults.Status() == ApproovTokenFetchStatus.BadKey) {
                throw new ConfigurationFailureException(TAG + "FetchSecureString: secure string unknown key");
            }
            else if (approovResults.Status() == ApproovTokenFetchStatus.Rejected)
            {
                // if the request is rejected then we provide a special exception with additional information
                string localARC = approovResults.ARC();
                string localReasons = approovResults.RejectionReasons();
                throw new RejectionException(TAG + "FetchSecureString: secure message rejected", arc: localARC, rejectionReasons: localReasons);
            }
            else if (approovResults.Status() == ApproovTokenFetchStatus.NoNetwork ||
                    approovResults.Status() == ApproovTokenFetchStatus.PoorNetwork ||
                    approovResults.Status() == ApproovTokenFetchStatus.MITMDetected)
            {
                /* We are unable to get the secure string due to network conditions so the request can
                *  be retried by the user later
                *  We are unable to get the secure string due to network conditions, so - unless this is
                *  overridden - we must not proceed. The request can be retried by the user later.
                */
                if (!ProceedOnNetworkFail)
                {
                    // We throw
                    throw new NetworkingErrorException(TAG + "FetchSecureString: network issue, retry needed");
                }
            }
            else if ((approovResults.Status() != ApproovTokenFetchStatus.Success) &&
                    approovResults.Status() != ApproovTokenFetchStatus.UnknownKey)
            {
                // we have failed to get a secure string with a more serious permanent error
                throw new PermanentException(TAG + "FetchSecureString: " +
                    StringFromApproovTokenFetchStatus(approovResults.Status()));
            }
            return approovResults.SecureString();
        }

        /*
         * Fetches a custom JWT with the given payload. Note that this call will require network
         * transaction and thus will block for some time, so should not be called from the UI thread.
         * If the fetch fails for any reason an exception will be thrown. Exceptions could be due to
         * malformed JSON string provided ...
         *
         * @param payload is the marshaled JSON object for the claims to be included
         * @return custom JWT string or nil if an error occurred
         * @throws exception with description of cause
         */
        public static string FetchCustomJWT(string payload) {
            var approovResult = FetchCustomJWTAndWait(payload);
            Console.WriteLine(TAG + "FetchCustomJWT: " + StringFromApproovTokenFetchStatus(approovResult.Status()));
            // process the returned Approov status
            if (approovResult.Status() == ApproovTokenFetchStatus.BadPayload)
            {
                throw new PermanentException(TAG + "FetchCustomJWT: malformed JSON");
            }
            else if (approovResult.Status() == ApproovTokenFetchStatus.Disabled)
            {
                throw new ConfigurationFailureException(TAG + "FetchCustomJWT: feature not enabled");
            }
            else if (approovResult.Status() == ApproovTokenFetchStatus.Rejected)
            {
                string localARC = approovResult.ARC();
                string localReasons = approovResult.RejectionReasons();
                // if the request is rejected then we provide a special exception with additional information
                throw new RejectionException(TAG + "FetchCustomJWT: rejected", arc: localARC, rejectionReasons: localReasons);
            }
            else if (approovResult.Status() == ApproovTokenFetchStatus.NoNetwork ||
                  approovResult.Status() == ApproovTokenFetchStatus.PoorNetwork ||
                  approovResult.Status() == ApproovTokenFetchStatus.MITMDetected)
            {
                /* We are unable to get the secure string due to network conditions so the request can
                *  be retried by the user later
                *  We are unable to get the secure string due to network conditions, so - unless this is
                *  overridden - we must not proceed. The request can be retried by the user later.
                */
                if (!ProceedOnNetworkFail)
                {
                    // We throw
                    throw new NetworkingErrorException(TAG + "FetchCustomJWT: network issue, retry needed");
                }
            }
            else if (approovResult.Status() != ApproovTokenFetchStatus.Success) {
                throw new PermanentException(TAG + "FetchCustomJWT: " + StringFromApproovTokenFetchStatus(approovResult.Status()));
            }
            return approovResult.Token();
        }

        /*
         * Performs a precheck to determine if the app will pass attestation. This requires secure
         * strings to be enabled for the account, although no strings need to be set up. This will
         * likely require network access so may take some time to complete. It may throw an exception
         * if the precheck fails or if there is some other problem. Exceptions could be due to
         * a rejection .......
         */
        public static void Precheck() {
            var approovResult = FetchSecureStringAndWait("precheck-dummy-key", null);
            // Process the result
            if (approovResult.Status() == ApproovTokenFetchStatus.Rejected)
            {
                string localARC = approovResult.ARC();
                string localReasons = approovResult.RejectionReasons();
                throw new RejectionException(TAG + "Precheck: rejected ", arc: localARC, rejectionReasons: localReasons);
            }
            else if (approovResult.Status() == ApproovTokenFetchStatus.NoNetwork ||
                approovResult.Status() == ApproovTokenFetchStatus.PoorNetwork ||
                approovResult.Status() == ApproovTokenFetchStatus.MITMDetected)
            {
                throw new NetworkingErrorException(TAG + "Precheck: network issue, retry needed");
            }
            else if ((approovResult.Status() != ApproovTokenFetchStatus.Success) &&
                  approovResult.Status() != ApproovTokenFetchStatus.UnknownKey) {
                throw new PermanentException(TAG + "Precheck: " + StringFromApproovTokenFetchStatus(approovResult.Status()));
            }
        }

        /**
         * Gets the device ID used by Approov to identify the particular device that the SDK is running on. Note
         * that different Approov apps on the same device will return a different ID. Moreover, the ID may be
         * changed by an uninstall and reinstall of the app.
         *
         * @return String of the device ID or null in case of an error
         */
        public static string GetDeviceID() {
            string deviceID = GetDeviceID();
            Console.WriteLine(TAG + "DeviceID: " + deviceID);
            return deviceID;
        }

        /**
         * Directly sets the data hash to be included in subsequently fetched Approov tokens. If the hash is
         * different from any previously set value then this will cause the next token fetch operation to
         * fetch a new token with the correct payload data hash. The hash appears in the
         * 'pay' claim of the Approov token as a base64 encoded string of the SHA256 hash of the
         * data. Note that the data is hashed locally and never sent to the Approov cloud service.
         *
         * @param data is the data to be hashed and set in the token
         */
        public static void SetDataHashInToken(string data) {
            Console.WriteLine(TAG + "SetDataHashInToken");
            SetDataHashInToken(data);
        }


        /**
         * Gets the signature for the given message. This uses an account specific message signing key that is
         * transmitted to the SDK after a successful fetch if the facility is enabled for the account. Note
         * that if the attestation failed then the signing key provided is actually random so that the
         * signature will be incorrect. An Approov token should always be included in the message
         * being signed and sent alongside this signature to prevent replay attacks. If no signature is
         * available, because there has been no prior fetch or the feature is not enabled, then an
         * ApproovException is thrown.
         *
         * @param message is the message whose content is to be signed
         * @return String of the base64 encoded message signature
         */
        public static string GetMessageSignature(string message) {
            var signature = GetMessageSignature(message);
            Console.WriteLine(TAG + "GetMessageSignature");
            return signature;
        }

        /**
         * Performs an Approov token fetch for the given URL. This should be used in situations where it
         * is not possible to use the networking interception to add the token. This will
         * likely require network access so may take some time to complete. If the attestation fails
         * for any reason then an Exception is thrown. ... Note that
         * the returned token should NEVER be cached by your app, you should call this function when
         * it is needed.
         *
         * @param url is the URL giving the domain for the token fetch
         * @return String of the fetched token
         * @throws Exception if there was a problem
         */

        public static string FetchToken(string url) {
            var approovResult = FetchApproovTokenAndWait(url);
            Console.WriteLine(TAG + "FetchToken: " + url + " " + StringFromApproovTokenFetchStatus(approovResult.Status()));

            // Process the result
            if (approovResult.Status() == ApproovTokenFetchStatus.Success)
            {
                return approovResult.Token();
            }
            else if (approovResult.Status() == ApproovTokenFetchStatus.NoNetwork ||
              approovResult.Status() == ApproovTokenFetchStatus.PoorNetwork ||
              approovResult.Status() == ApproovTokenFetchStatus.MITMDetected)
            {
                throw new NetworkingErrorException(TAG + "FetchToken: networking error, retry needed");
            }
            else {
                throw new PermanentException(TAG + "FetchToken: " + StringFromApproovTokenFetchStatus(approovResult.Status()));
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
