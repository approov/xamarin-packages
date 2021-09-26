﻿using System;
using System.Collections.Concurrent;
using System.Linq;
using Approov;

namespace Refit
{
    class CachedRequestBuilderImplementation<T> : CachedRequestBuilderImplementation, IRequestBuilder<T>
    {
        public CachedRequestBuilderImplementation(IRequestBuilder<T> innerBuilder) : base(innerBuilder)
        {
        }
    }

    class CachedRequestBuilderImplementation : IRequestBuilder
    {
        public CachedRequestBuilderImplementation(IRequestBuilder innerBuilder)
        {
            this.innerBuilder = innerBuilder;
        }

        readonly IRequestBuilder innerBuilder;
        readonly ConcurrentDictionary<string, Func<ApproovHttpClient, object[], object>> methodDictionary = new ConcurrentDictionary<string, Func<ApproovHttpClient, object[], object>>();

        public Func<ApproovHttpClient, object[], object> BuildRestResultFuncForMethod(string methodName, Type[] parameterTypes = null, Type[] genericArgumentTypes = null)
        {
            var cacheKey = GetCacheKey(methodName, parameterTypes, genericArgumentTypes);
            var func = methodDictionary.GetOrAdd(cacheKey, _ => innerBuilder.BuildRestResultFuncForMethod(methodName, parameterTypes, genericArgumentTypes));

            return func;
        }

        string GetCacheKey(string methodName, Type[] parameterTypes, Type[] genericArgumentTypes)
        {
            var genericDefinition = GetGenericString(genericArgumentTypes);
            var argumentString = GetArgumentString(parameterTypes);

            return $"{methodName}{genericDefinition}({argumentString})";
        }

        string GetArgumentString(Type[] parameterTypes)
        {
            if (parameterTypes == null || parameterTypes.Length == 0)
            {
                return "";
            }

            return string.Join(", ", parameterTypes.Select(t => t.FullName));
        }

        string GetGenericString(Type[] genericArgumentTypes)
        {
            if (genericArgumentTypes == null || genericArgumentTypes.Length == 0)
            {
                return "";
            }

            return "<" + string.Join(", ", genericArgumentTypes.Select(t => t.FullName)) + ">";
        }
    }
}