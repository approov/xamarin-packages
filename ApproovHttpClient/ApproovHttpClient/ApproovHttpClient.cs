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
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Approov
{
    public class ApproovHttpClient : HttpClient
    {
        /* Approov SDK TAG used for logging and error messages */
        public static readonly string TAG = "ApproovSDK: ";
        /* Approov token default header */
        public static string ApproovTokenHeader = "Approov-Token";
        /* Approov token custom prefix: any prefix to be added such as "Bearer " */
        public static string ApproovTokenPrefix = "";
        /* Lock object for the above string variables */
        protected static readonly Object HeaderAndPrefixLock = new Object();
        /* true if the connection should proceed on network failures and not add an Approov token */
        protected static bool ProceedOnNetworkFail = false;
        /* Lock object for the above boolean variable*/
        protected static readonly Object ProceedOnNetworkFailLock = new Object();
        /* Any header to be used for binding in Approov tokens or null if not set */
        protected static string BindingHeader = null;
        /* Lock object */
        protected static readonly Object BindingHeaderLock = new Object();
        /* Status of Approov SDK initialisation */
        protected static bool ApproovSDKInitialized = false;
        /* Lock object: used during ApproovSDk init call */
        protected static readonly Object InitializerLock = new Object();
        /* Type of server certificates supported by Approov SDK */
        protected static readonly string kShaTypeString = "public-key-sha256";
        /* map of headers that should have their values substituted for secure strings, mapped to their
         required prefixes */
        protected static Dictionary<string,string> SubstitutionHeaders = new Dictionary<string,string>();
        /* Lock object for the above Set*/
        protected static readonly Object SubstitutionHeadersLock = new Object();
        /* set of URL regexs that should be excluded from any Approov protection */
        protected static HashSet<Regex> ExclusionURLRegexs = new HashSet<Regex>();
        /* Lock object for the above Set*/
        protected static readonly Object ExclusionURLRegexsLock = new Object();
        /*  Set of query parameters that may be substituted, specified by the key name */ 
        protected static HashSet<String> SubstitutionQueryParams = new HashSet<string>();
        /* Lock object for the above Set*/
        protected static readonly Object SubstitutionQueryParamsLock = new Object();

        public ApproovHttpClient() : this(new HttpClientHandler()) { }

        public ApproovHttpClient(HttpMessageHandler handler) : base(handler)
        {
            // a handler must be provided
            if (handler == null)
            {
                throw new InitializationFailureException(TAG + "ApproovHttpClient constructor: HttpMessageHandler must be provided");
            }

            // traverse the chain of handlers to find the inner HttpClientHandler
            HttpMessageHandler chainedHandler = handler;
            while (chainedHandler != null)
            {
                if (chainedHandler.GetType().IsSubclassOf(typeof(DelegatingHandler)))
                {
                    // traverse through DelegatingHandlers
                    DelegatingHandler delegatingHandler = (DelegatingHandler)chainedHandler;
                    chainedHandler = delegatingHandler.InnerHandler;
                    if (chainedHandler == null)
                    {
                        throw new InitializationFailureException(TAG + "ApproovHttpClient constructor: No inner handler found");
                    }
                }
                else if (chainedHandler.GetType().IsSubclassOf(typeof(HttpClientHandler)) || (chainedHandler.GetType() == typeof(HttpClientHandler)))
                {
                    // we've found the inner handler test if the callback has been set, then bail out
                    HttpClientHandler httpClientHandler = (HttpClientHandler)chainedHandler;
                    if ((httpClientHandler.ServerCertificateCustomValidationCallback != null) && (httpClientHandler.ServerCertificateCustomValidationCallback != ServerCallback)) 
                    {
                        throw new InitializationFailureException(TAG + "Unable to override InnerHandler custom vallidation callback");
                    }
                    // set the callback handler
                    httpClientHandler.ServerCertificateCustomValidationCallback = ServerCallback;
                    // We are done
                    chainedHandler = null;
                }
                else
                {
                    // there must be an inner HttpClientHandler that we can setup pinning for
                    throw new InitializationFailureException(TAG + "No HttpClientHandler found");
                }
            }
        }

        /* Http request methods from https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient?view=netcore-3.1 */
        /* GeyAsync versions */
        public new Task<HttpResponseMessage> GetAsync(string requestUri)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetAsync(modifiedMessage.RequestUri));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }

            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> GetAsync(string requestUri, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetAsync(modifiedMessage.RequestUri, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> GetAsync(Uri requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetAsync(modifiedMessage.RequestUri, completionOption, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption completionOption, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetAsync(modifiedMessage.RequestUri, completionOption, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> GetAsync(Uri requestUri, HttpCompletionOption completionOption)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetAsync(modifiedMessage.RequestUri, completionOption));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption completionOption)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetAsync(modifiedMessage.RequestUri, completionOption));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> GetAsync(Uri requestUri)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetAsync(modifiedMessage.RequestUri));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        /* GetByteArray versions */
        public new Task<byte[]> GetByteArrayAsync(string requestUri)
        {
            TaskCompletionSource<byte[]> tcs = new TaskCompletionSource<byte[]>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetByteArrayAsync(modifiedMessage.RequestUri));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<byte[]> GetByteArrayAsync(Uri requestUri)
        {
            TaskCompletionSource<byte[]> tcs = new TaskCompletionSource<byte[]>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetByteArrayAsync(modifiedMessage.RequestUri));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        /* GetStreamAsync versions */
        public new Task<Stream> GetStreamAsync(string requestUri)
        {
            TaskCompletionSource<Stream> tcs = new TaskCompletionSource<Stream>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetStreamAsync(modifiedMessage.RequestUri));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;

        }

        public new Task<Stream> GetStreamAsync(Uri requestUri)
        {
            TaskCompletionSource<Stream> tcs = new TaskCompletionSource<Stream>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetStreamAsync(modifiedMessage.RequestUri));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        /* GetString versions */
        public new Task<string> GetStringAsync(string requestUri)
        {
            TaskCompletionSource<string> tcs = new TaskCompletionSource<string>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetStringAsync(modifiedMessage.RequestUri));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<string> GetStringAsync(Uri requestUri)
        {
            TaskCompletionSource<string> tcs = new TaskCompletionSource<string>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri : requestUri.ToString());
                    tcs.SetResult(await base.GetStringAsync(modifiedMessage.RequestUri));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

       
        /* Post versions */
        public new Task<HttpResponseMessage> PostAsync(Uri requestUri, HttpContent content, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.PostAsync(modifiedMessage.RequestUri, content, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> PostAsync(string requestUri, HttpContent content, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.PostAsync(modifiedMessage.RequestUri, content, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> PostAsync(Uri requestUri, HttpContent content)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.PostAsync(modifiedMessage.RequestUri, content));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> PostAsync(string requestUri, HttpContent content)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.PostAsync(modifiedMessage.RequestUri, content));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        /* Put versions */
        public new Task<HttpResponseMessage> PutAsync(Uri requestUri, HttpContent content, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.PutAsync(modifiedMessage.RequestUri, content, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> PutAsync(string requestUri, HttpContent content)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.PutAsync(modifiedMessage.RequestUri, content));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> PutAsync(Uri requestUri, HttpContent content)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.PutAsync(modifiedMessage.RequestUri, content));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> PutAsync(string requestUri, HttpContent content, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.PutAsync(modifiedMessage.RequestUri, content, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        /* Send versions */
        public override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    // TODO: this seems wrong, since the actual full URI is the one included in the message!?
                    //HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + request.RequestUri : request.RequestUri.ToString(), request);
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(request.RequestUri.ToString(), request);
                    tcs.SetResult(await base.SendAsync(modifiedMessage, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, HttpCompletionOption completionOption, CancellationToken cancellationToken)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + request.RequestUri : request.RequestUri.ToString(), request);
                    tcs.SetResult(await base.SendAsync(modifiedMessage, completionOption, cancellationToken));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + request.RequestUri : request.RequestUri.ToString(), request);
                    tcs.SetResult(await base.SendAsync(modifiedMessage));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        public new Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, HttpCompletionOption completionOption)
        {
            TaskCompletionSource<HttpResponseMessage> tcs = new TaskCompletionSource<HttpResponseMessage>();
            Task.Factory.StartNew(async () =>
            {
                try
                {
                    HttpRequestMessage modifiedMessage = UpdateRequestHeadersWithApproov(BaseAddress != null ? BaseAddress.AbsoluteUri + request.RequestUri : request.RequestUri.ToString(), request);
                    tcs.SetResult(await base.SendAsync(modifiedMessage, completionOption));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        /*
         *  Convenience function fetching the Approov token. Note, that it is possible to pass a null message
         *  as parameter. In all cases, the `url` is considered as protected by Approov. If the message param
         *  is null then the headers to be modified by the ApproovService are the default ones provided by the 
         *  `HttpClient` implementation (https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultrequestheaders?view=net-6.0)
         *  The function allways returns an `HttpRequestMessage`  with a `URI` parameter potentially modified
         *  subject to string parameter substitution by Approov BUT it might not contain any (null) headers, if 
         *  it is the DefaultHeaders the ones used by the implementation.
         *  @param  string url to protect by Approov. Note the actual url might be prefixed by a base address
         *  @param  HttpRequestMessage  optional message if used, any request headers and URI replacement will 
         *          modify this message and a new one will be returned
         *  @return HttpRequestMessage  with (possibly) modified URI and (possible) modified request headers or
         *          null headers if parameter `message` was null.
         */
        protected virtual HttpRequestMessage UpdateRequestHeadersWithApproov(string url, HttpRequestMessage message = null)
        {
            throw new ApproovSDKException(TAG + "UpdateRequestHeadersWithApproov must be overriden in platform specific implementations.");
        }

        /* 
         *  Callback function evaluating TLS server trust. We must override this in the platfom independent code
         */
        protected virtual Boolean ServerCallback(HttpRequestMessage sender, X509Certificate2 cert, X509Chain chain, SslPolicyErrors sslPolicyErrors) 
        {
            return false;
        }

        /* 
         * Sets a binding header that must be present on all requests using the Approov service. A
         * header should be chosen whose value is unchanging for most requests (such as an
         * Authorization header). A hash of the header value is included in the issued Approov tokens
         * to bind them to the value. This may then be verified by the backend API integration. This
         * method should typically only be called once.
         *
         * @param header is the header to use for Approov token binding
         */
        public static void SetBindingHeader(string header)
        {
            lock (BindingHeaderLock)
            {
                BindingHeader = header;
                Console.WriteLine(TAG + "SetBindingHeader " + header);
            }
        }

        /*
         * Sets a flag indicating if the network interceptor should proceed anyway if it is
         * not possible to obtain an Approov token due to a networking failure. If this is set
         * then your backend API can receive calls without the expected Approov token header
         * being added, or without header/query parameter substitutions being made. Note that
         * this should be used with caution because it may allow a connection to be established
         * before any dynamic pins have been received via Approov, thus potentially opening the channel to a MitM.
         *
         * @param proceed is true if Approov networking fails should allow continuation
         */
        public static void SetProceedOnNetworkFailure(bool proceed) {
            lock (ProceedOnNetworkFailLock) {
                ProceedOnNetworkFail = proceed;
                Console.WriteLine(TAG + "SetProceedOnNetworkFailure " + proceed.ToString());
            }
        }

        /*
         * Gets a flag indicating if the network interceptor should proceed anyway if it is
         * not possible to obtain an Approov token due to a networking failure. If this is set
         * then your backend API can receive calls without the expected Approov token header
         * being added, or without header/query parameter substitutions being made. Note that
         * this should be used with caution because it may allow a connection to be established
         * before any dynamic pins have been received via Approov, thus potentially opening the channel to a MitM.
         *
         * @return boolean true if Approov networking fails should allow continuation
         */
        public static bool GetProceedOnNetworkFailure()
        {
            lock (ProceedOnNetworkFailLock)
            {
                return ProceedOnNetworkFail;
            }
        }

        /*  Sets the Approov Header and optional prefix. By default, those values are "Approov-Token"
         *  for the header and the prefix is an empty string. If you wish to use "Authorization Bearer .."
         *  for example, the header should be set to "Authorization " and the prefix to "Bearer"
         *  
         *  @param  header the header to use
         *  @param  prefix optional prefix, can be an empty string if not needed
         */
        public static void SetTokenHeaderAndPrefix(string header, string prefix) {
            lock (HeaderAndPrefixLock) {
                if (header != null) ApproovTokenHeader = header;
                if (prefix != null) ApproovTokenPrefix = prefix;
                Console.WriteLine(TAG + "SetTokenHeaderAndPrefix header: " + header + " prefix: " + prefix);
            }
        }

        /*  Returns true if the Approov SDk has been succesfully initialized
         *
         */
        public static bool IsApproovSDKInitialized() {
            lock (InitializerLock) {
                return ApproovSDKInitialized;
            }
        }

        /*
         * Adds the name of a header which should be subject to secure strings substitution. This
         * means that if the header is present then the value will be used as a key to look up a
         * secure string value which will be substituted into the header value instead. This allows
         * easy migration to the use of secure strings. A required prefix may be specified to deal
         * with cases such as the use of "Bearer " prefixed before values in an authorization header.
         *
         * @param header is the header to be marked for substitution
         * @param requiredPrefix is any required prefix to the value being substituted or nil if not required
         */
        public static void AddSubstitutionHeader(string header, string requiredPrefix) {
            if (IsApproovSDKInitialized()) {
                lock (SubstitutionHeadersLock) {
                    if (requiredPrefix == null)
                    {
                        SubstitutionHeaders.Add(header, "");
                    }
                    else {
                        SubstitutionHeaders.Add(header, requiredPrefix);
                    }
                    Console.WriteLine(TAG + "AddSubstitutionHeader header: " + header + " requiredPrefix: " + requiredPrefix);
                }
            }
        }

        /*
         * Removes a header previously added using addSubstitutionHeader.
         *
         * @param header is the header to be removed for substitution
         */
        public static void RemoveSubstitutionHeader(string header)
        {
            if (IsApproovSDKInitialized())
            {
                lock (SubstitutionHeadersLock)
                {
                    if (SubstitutionHeaders.ContainsKey(header))
                    {
                        SubstitutionHeaders.Remove(header);
                        Console.WriteLine(TAG + "RemoveSubstitutionHeader " + header);

                    }
                }
            }
        }

        /**
         * Adds a key name for a query parameter that should be subject to secure strings substitution.
         * This means that if the query parameter is present in a URL then the value will be used as a
         * key to look up a secure string value which will be substituted as the query parameter value
         * instead. This allows easy migration to the use of secure strings.
         *
         * @param key is the query parameter key name to be added for substitution
         */
        public static void AddSubstitutionQueryParam(string key) {
            if (IsApproovSDKInitialized()) {
                lock (SubstitutionQueryParamsLock) {
                    SubstitutionQueryParams.Add(key);
                    Console.WriteLine(TAG + "AddSubstitutionQueryParam " + key);
                }
            }
        }

        /**
         * Removes a query parameter key name previously added using addSubstitutionQueryParam.
         *
         * @param key is the query parameter key name to be removed for substitution
         */
        public static void RemoveSubstitutionQueryParam(string key)
        {
            if (IsApproovSDKInitialized())
            {
                lock (SubstitutionQueryParamsLock)
                {
                    if (SubstitutionQueryParams.Contains(key))
                    {
                        SubstitutionQueryParams.Remove(key);
                        Console.WriteLine(TAG + "RemoveSubstitutionQueryParam " + key);
                    }
                }
            }
        }

        /**
         * Adds an exclusion URL regular expression. If a URL for a request matches this regular expression
         * then it will not be subject to any Approov protection. Note that this facility must be used with
         * EXTREME CAUTION due to the impact of dynamic pinning. Pinning may be applied to all domains added
         * using Approov, and updates to the pins are received when an Approov fetch is performed. If you
         * exclude some URLs on domains that are protected with Approov, then these will be protected with
         * Approov pins but without a path to update the pins until a URL is used that is not excluded. Thus
         * you are responsible for ensuring that there is always a possibility of calling a non-excluded
         * URL, or you should make an explicit call to fetchToken if there are persistent pinning failures.
         * Conversely, use of those option may allow a connection to be established before any dynamic pins
         * have been received via Approov, thus potentially opening the channel to a MitM.
         *
         * @param urlRegex is the regular expression that will be compared against URLs to exclude them
         * @throws ArgumentException if urlRegex is malformed
         */
        public static void AddExclusionURLRegex(string urlRegex) {
            if (IsApproovSDKInitialized())
            {
                lock (ExclusionURLRegexsLock) {
                    if (urlRegex != null)
                    {
                        Regex reg = new Regex(urlRegex);
                        ExclusionURLRegexs.Add(reg);
                        Console.WriteLine(TAG + "AddExclusionURLRegex " + urlRegex);
                    }
                }
            }
        }

        /**
         * Removes an exclusion URL regular expression previously added using addExclusionURLRegex.
         *
         * @param urlRegex is the regular expression that will be compared against URLs to exclude them
         * @throws ArgumentException if urlRegex is malformed
         */
        public static void RemoveExclusionURLRegex(string urlRegex)
        {
            if (IsApproovSDKInitialized())
            {
                lock (ExclusionURLRegexsLock)
                {
                    if (urlRegex != null)
                    {
                        Regex reg = new Regex(urlRegex);
                        if (ExclusionURLRegexs.Contains(reg))
                        {
                            ExclusionURLRegexs.Remove(reg);
                            Console.WriteLine(TAG + "RemoveExclusionURLRegex " + urlRegex);
                        }
                        
                    }
                }
            }
        }

        /**
         * Checks if the url matches one of the exclusion regexs defined in exclusionURLRegexs
         *
         * @param   url is the URL for which the check is performed
         * @return  Bool true if url matches preset pattern in Dictionary
         */
        public static bool CheckURLIsExcluded(string url) {
            // obtain a copy of the exclusion URL regular expressions in a thread safe way
            int elementCount;
            Regex[] exclusionURLs;
            lock (ExclusionURLRegexsLock) {
                elementCount = ExclusionURLRegexs.Count;
                if (elementCount == 0) return false;
                exclusionURLs = new Regex[elementCount];
                ExclusionURLRegexs.CopyTo(exclusionURLs);
            }

            foreach (Regex pattern in exclusionURLs) {
                Match match = pattern.Match(url, 0, url.Length);
                if (match.Length > 0)
                {
                    Console.WriteLine(TAG + "CheckURLIsExcluded match for " + url);
                    return true;
                }
            }
            return false;
        }

        /*
        *   Approov SDK exceptions
        */
        public class ApproovSDKException : Exception
        {
            public bool ShouldRetry;
            public new string Message;
            public ApproovSDKException()
            {
                ShouldRetry = false;
                Message = "ApproovSDKException: Unknown Error.";
            }

            public ApproovSDKException(string message) : base(message)
            {
                ShouldRetry = false;
                Message = message;
            }

            public ApproovSDKException(string message, bool shouldRetry) : base(message)
            {
                ShouldRetry = shouldRetry;
                Message = message;
            }
        } // ApproovSDKException class
        // initialization failure
        public class InitializationFailureException : ApproovSDKException {
            public InitializationFailureException(string message) : base(message)
            {
                ShouldRetry = false;
                Message = message;
            }
            public InitializationFailureException(string message, bool shouldRetry) : base(message)
            {
                ShouldRetry = shouldRetry;
                Message = message;
            }
        }
        // configuration failure
        public class ConfigurationFailureException : ApproovSDKException {
            public ConfigurationFailureException(string message) : base(message)
            {
                ShouldRetry = false;
                Message = message;
            }
            public ConfigurationFailureException(string message, bool shouldRetry) : base(message)
            {
                ShouldRetry = shouldRetry;
                Message = message;
            }
        }
        // pinning error
        public class PinningErrorException : ApproovSDKException {
            public PinningErrorException(string message) : base(message)
            {
                ShouldRetry = false;
                Message = message;
            }
            public PinningErrorException(string message, bool shouldRetry) : base(message)
            {
                ShouldRetry = shouldRetry;
                Message = message;
            }
        }
        // networking error
        public class NetworkingErrorException : ApproovSDKException {
            public NetworkingErrorException(string message) : base(message)
            {
                ShouldRetry = false;
                Message = message;
            }
            public NetworkingErrorException(string message, bool shouldRetry) : base(message)
            {
                ShouldRetry = shouldRetry;
                Message = message;
            }
        }
        // permanent error
        public class PermanentException : ApproovSDKException {
            public PermanentException(string message) : base(message)
            {
                ShouldRetry = false;
                Message = message;
            }
            public PermanentException(string message, bool shouldRetry) : base(message)
            {
                ShouldRetry = shouldRetry;
                Message = message;
            }
        }
        // rejection error
        public class RejectionException : ApproovSDKException {
            public string ARC;
            public string Rejectionreasons;
            public RejectionException(string message, string arc, string rejectionReasons) {
                ShouldRetry = false;
                Message = message;
                ARC = arc;
                Rejectionreasons = rejectionReasons;
            }
        }
    }// class
}
