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
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Approov
{
    public class ApproovHttpClient : HttpClient
    {
        /* Approov SDK TAG used for logging and error messages */
        public static readonly string TAG = "ApproovSDK: ";
        /* Dynamic configuration string key in user default database */
        public static string ApproovDynamicKey { get; set; } = "approov-dynamic";
        /* Initial configuration string/filename for Approov SDK */
        public static string ApproovInitialKey { get; set; } = "approov-initial";
        /* Initial configuration file extention for Approov SDK */
        public static string ConfigFileExtension { get; set; } = ".config";
        /* Approov preferences key */
        public static string ApproovPreferencesKey { get; set; } = "APPROOV_PREFERENCES";
        /* Approov token default header */
        public static string ApproovTokenHeader { get; set; } = "Approov-Token";
        /* Approov token custom prefix: any prefix to be added such as "Bearer " */
        public static string ApproovTokenPrefix { get; set; } = "";
        /* Any header to be used for binding in Approov tokens or null if not set */
        protected static string BindingHeader = null;
        /* Status of Approov SDK initialisation */
        protected static bool isApproovSDKInitialized = false;
        /* Lock object */
        protected static readonly Object bindingHeaderLock = new Object();
        /* Type of server certificates supported by Approov SDK */
        protected static readonly string kShaTypeString = "public-key-sha256";

        public ApproovHttpClient() : this(new HttpClientHandler()) { }

        public ApproovHttpClient(HttpMessageHandler handler) : base(handler)
        {
            // a handler must be provided
            if (handler == null)
            {
                throw new ApproovSDKException(TAG + "ApproovHttpClient constructor: HttpMessageHandler must be provided");
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
                        throw new ApproovSDKException(TAG + "ApproovHttpClient constructor: No inner handler found");
                    }
                }
                else if (chainedHandler.GetType().IsSubclassOf(typeof(HttpClientHandler)) || (chainedHandler.GetType() == typeof(HttpClientHandler)))
                {
                    // we've found the inner handler test if the callback has been set, then bail out
                    HttpClientHandler httpClientHandler = (HttpClientHandler)chainedHandler;
                    if ((httpClientHandler.ServerCertificateCustomValidationCallback != null) && (httpClientHandler.ServerCertificateCustomValidationCallback != ServerCallback)) 
                    {
                        throw new ApproovSDKException(TAG + "Unable to override InnerHandler custom vallidation callback");
                    }
                    // set the callback handler
                    httpClientHandler.ServerCertificateCustomValidationCallback = ServerCallback;
                    // We are done
                    chainedHandler = null;
                }
                else
                {
                    // there must be an inner HttpClientHandler that we can setup pinning for
                    throw new ApproovSDKException(TAG + "No HttpClientHandler found");
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetAsync(requestUri));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetAsync(requestUri, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetAsync(requestUri, completionOption, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetAsync(requestUri, completionOption, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetAsync(requestUri, completionOption));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetAsync(requestUri, completionOption));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetAsync(requestUri));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetByteArrayAsync(requestUri));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetByteArrayAsync(requestUri));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetStreamAsync(requestUri));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.GetStreamAsync(requestUri));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.GetStringAsync(requestUri));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri : requestUri.ToString());
                    tcs.SetResult(await base.GetStringAsync(requestUri));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.PostAsync(requestUri, content, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.PostAsync(requestUri, content, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.PostAsync(requestUri, content));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.PostAsync(requestUri, content));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.PutAsync(requestUri, content, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.PutAsync(requestUri, content));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri.ToString());
                    tcs.SetResult(await base.PutAsync(requestUri, content));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + requestUri : requestUri);
                    tcs.SetResult(await base.PutAsync(requestUri, content, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + request.RequestUri : request.RequestUri.ToString(), request);
                    tcs.SetResult(await base.SendAsync(request, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + request.RequestUri : request.RequestUri.ToString(), request);
                    tcs.SetResult(await base.SendAsync(request, completionOption, cancellationToken));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + request.RequestUri : request.RequestUri.ToString(), request);
                    tcs.SetResult(await base.SendAsync(request));
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
                    FetchApproovToken(BaseAddress != null ? BaseAddress.AbsoluteUri + request.RequestUri : request.RequestUri.ToString(), request);
                    tcs.SetResult(await base.SendAsync(request, completionOption));
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            });
            return tcs.Task;
        }

        /*
         *  Convenience function fetching the Approov token
         */
        protected virtual void FetchApproovToken(string url, HttpRequestMessage message = null)
        {
            throw new ApproovSDKException(TAG + "FetchApproovToken must be overriden in platform specific implementations.");
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
            lock (bindingHeaderLock)
            {
                BindingHeader = header;
            }
        }

        /*
        *   Approov SDK exceptions
        */
        public class ApproovSDKException : Exception
        {
            public bool ShouldRetry { get; }
            public ApproovSDKException()
            {
                ShouldRetry = false;
            }

            public ApproovSDKException(string message) : base(message)
            {
                ShouldRetry = false;
            }

            public ApproovSDKException(string message, bool shouldRetry) : base(message)
            {
                ShouldRetry = shouldRetry;
            }
        } // ApproovSessionHandler class
    }// class
}
