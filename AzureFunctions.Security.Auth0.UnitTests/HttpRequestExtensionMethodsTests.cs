using System;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AzureFunctions.Security.Auth0.UnitTests
{
    public class HttpRequestExtensionMethodsTests
    {
        private const string FakeAuthToken = "Fake.Auth-Token";
        private readonly MockHttpRequestBuilder reqBuilder;

        public HttpRequestExtensionMethodsTests()
        {
            reqBuilder = new MockHttpRequestBuilder();
        }

        [Fact]
        public void GetAuthToken_ThrowsExceptionIfAuthorizationHeaderNotPresent()
        {
            var req = reqBuilder
                .Build();
            
            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => req.GetAuthToken());
            Assert.Equal(HttpRequestExtensionMethods.AuthorizationHeaderKey, ex.ParamName);
        }

        [Fact]
        public void GetAuthToken_ThrowsExceptionIfAuthorizationHeaderValueDoesNotStartWithBearer()
        {
            var req = reqBuilder
                .WithHeader("Authorization", "Fake_Authorization_Header")
                .Build();
            
            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => req.GetAuthToken());
            
            Assert.Equal(HttpRequestExtensionMethods.AuthorizationHeaderKey, ex.ParamName);
            Assert.Contains("Authorization Header Schema", ex.Message);
        }

        [Fact]
        public void GetAuthToken_ReturnsTheAuthTokenFromAValidAuthorizationHeader()
        {
            var req = reqBuilder
                .WithHeader("Authorization", $"Bearer {FakeAuthToken}")
                .Build();

            var authToken = req.GetAuthToken();
            Assert.Equal(FakeAuthToken, authToken);
        }

        [Fact]
        public void TryGetAuthToken_ReturnsFalseIfAuthorizationHeaderNotPresent()
        {
            var req = reqBuilder
                .Build();
            
            var result = req.TryGetAuthToken(out var authToken);
            
            Assert.False(result);
            Assert.Empty(authToken);
        }

        [Fact]
        public void TryGetAuthToken_ReturnsFalseIfAuthorizationHeaderValueDoesNotStartWithBearer()
        {
            var req = reqBuilder
                .WithHeader("Authorization", "Fake_Authorization_Header")
                .Build();
            
            var result = req.TryGetAuthToken(out var authToken);
            
            Assert.False(result);
            Assert.Empty(authToken);
        }

        [Fact]
        public void TryGetAuthToken_ReturnsTrueAndTheAuthTokenFromAValidAuthorizationHeader()
        {
            var req = reqBuilder
                .WithHeader("Authorization", $"Bearer {FakeAuthToken}")
                .Build();

            var result = req.TryGetAuthToken(out var authToken);

            Assert.True(result);
            Assert.Equal(FakeAuthToken, authToken);
        }
    }
}