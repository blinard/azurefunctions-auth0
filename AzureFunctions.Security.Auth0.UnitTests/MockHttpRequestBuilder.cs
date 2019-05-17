using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Moq;

namespace AzureFunctions.Security.Auth0.UnitTests
{
    public class MockHttpRequestBuilder
    {
        private readonly Dictionary<string, StringValues> headers;

        public MockHttpRequestBuilder()
        {
            headers = new Dictionary<string, StringValues>();
        }

        public MockHttpRequestBuilder WithHeader(string key, string value)
        {
            headers.Add(key, new StringValues(value));
            return this;
        }

        public HttpRequest Build()
        {                        
            var mockHeaders = new Mock<IHeaderDictionary>();
            mockHeaders
                .Setup(o => o.ContainsKey(It.IsAny<string>()))
                .Returns<string>(k => headers.ContainsKey(k));
            mockHeaders
                .Setup(o => o[It.Is<string>(s => headers.ContainsKey(s))])
                .Returns<string>(k => headers[k]);

            var mockReq = new Mock<HttpRequest>();
            mockReq
                .SetupGet(o => o.Headers)
                .Returns(mockHeaders.Object);

            return mockReq.Object;
        }
    }
}