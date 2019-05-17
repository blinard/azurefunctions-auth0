using System;
using Microsoft.AspNetCore.Http;

namespace AzureFunctions.Security.Auth0
{
    public static class HttpRequestExtensionMethods
    {
        internal const string AuthorizationHeaderKey = "Authorization";

        public static string GetAuthToken(this HttpRequest req)
        {
            if (!req.Headers.ContainsKey(AuthorizationHeaderKey))
                throw new ArgumentOutOfRangeException(AuthorizationHeaderKey);

            var authorizationValue = req.Headers[AuthorizationHeaderKey].ToString();
            if (!authorizationValue.StartsWith("Bearer "))
                throw new ArgumentOutOfRangeException(AuthorizationHeaderKey, "Authorization Header Schema");
            
            return authorizationValue.Substring(7).Trim();
        }
        
        public static bool TryGetAuthToken(this HttpRequest req, out string authToken)
        {
            authToken = string.Empty;
            
            if (!req.Headers.ContainsKey(AuthorizationHeaderKey))
                return false;

            var authorizationValue = req.Headers[AuthorizationHeaderKey].ToString();
            if (!authorizationValue.StartsWith("Bearer "))
                return false;
            
            authToken = authorizationValue.Substring(7).Trim();
            return true;
        }
    }
}