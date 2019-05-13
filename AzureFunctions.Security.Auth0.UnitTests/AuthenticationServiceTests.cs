using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Polly;
using Xunit;

namespace AzureFunctions.Security.Auth0.UnitTests
{
    public class AuthenticationServiceTests
    {
        private const string FakeInputToken = "FakeInputToken";

        private readonly Auth0ApiSettings _apiSettings;
        private readonly Mock<IConfigurationManager<OpenIdConnectConfiguration>> _mockConfigurationManager;
        private readonly IAsyncPolicy<ClaimsPrincipal> _validationRequestPolicy;
        private readonly Mock<ISecurityTokenValidator> _mockTokenValidator;
        private readonly Mock<OpenIdConnectConfiguration> _mockOpenIdConfiguration;
        private SecurityToken _validatedToken;

        public AuthenticationServiceTests()
        {
            _apiSettings = new Auth0ApiSettings() { Audience = "TestAudience", Issuer = "TestIssuer" };
            _validationRequestPolicy = Policy.NoOpAsync().AsAsyncPolicy<ClaimsPrincipal>();
            _mockConfigurationManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
            _mockTokenValidator = new Mock<ISecurityTokenValidator>();
            _mockOpenIdConfiguration = new Mock<OpenIdConnectConfiguration>();

            _mockConfigurationManager
                .Setup(o => o.GetConfigurationAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(_mockOpenIdConfiguration.Object);

            _mockTokenValidator
                .Setup(o => o.ValidateToken(It.IsAny<string>(), It.IsAny<TokenValidationParameters>(), out _validatedToken))
                .Returns(new ClaimsPrincipal());
        }

        public AuthenticationService BuildAuthServiceInternal(TokenValidationParameters validationParams = null, IAsyncPolicy<ClaimsPrincipal> validationRequestPolicyOverride = null)
        {
            return new AuthenticationService(_apiSettings, _mockConfigurationManager.Object, validationParams, validationRequestPolicyOverride ?? _validationRequestPolicy, _mockTokenValidator.Object);
        }

        public AuthenticationService BuildAuthServicePublic(TokenValidationParameters validationParams = null)
        {
            return new AuthenticationService(_apiSettings, _mockConfigurationManager.Object, validationParams);
        }

        [Fact]
        public async void ValidateTokenAsync_PassesTokenThroughToValidator()
        {
            var authService = BuildAuthServiceInternal();

            await authService.ValidateTokenAsync(FakeInputToken);

            _mockTokenValidator.Verify(
                o => o.ValidateToken(It.Is<string>(s => s == FakeInputToken), It.IsAny<TokenValidationParameters>(), out _validatedToken), 
                Times.Once
                );
        }

        [Fact]
        public void ValidateTokenAsync_UsesJwtSecurityTokenHandlerForValidation()
        {
            var authService = BuildAuthServicePublic();

            Assert.IsType<JwtSecurityTokenHandler>(authService._tokenValidator);
        }

        [Fact]
        public async void ValidateTokenAsync_UsesSigningKeysFromAuthConfigurationForTokenValidation()
        {
            var openIdConfig = new OpenIdConnectConfiguration(GetConfigResponse());
            _mockConfigurationManager
                .Setup(o => o.GetConfigurationAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(openIdConfig);

            var authService = BuildAuthServiceInternal();
            await authService.ValidateTokenAsync(FakeInputToken);

            _mockTokenValidator.Verify(
                o => o.ValidateToken(
                    It.IsAny<string>(), 
                    It.Is<TokenValidationParameters>(p => p.IssuerSigningKeys == openIdConfig.SigningKeys), 
                    out _validatedToken
                    ), 
                Times.Once
                );
        }

        [Fact]
        public async void ValidateTokenAsync_AllowsOverridesToTheTokenValidationParameters()
        {
            var validationParams = new TokenValidationParameters()
            {
                RequireSignedTokens = false,
                ValidAudience = "OverriddenAudience"
            };
            var authService = BuildAuthServiceInternal(validationParams);

            await authService.ValidateTokenAsync(FakeInputToken);

            _mockTokenValidator.Verify(
                o => o.ValidateToken(
                    It.IsAny<string>(), 
                    It.Is<TokenValidationParameters>(p => p.ValidAudience == validationParams.ValidAudience && p.RequireSignedTokens == validationParams.RequireSignedTokens), 
                    out _validatedToken
                    ), 
                Times.Once
                );
        }

        [Fact]
        public async void ValidateTokenAsync_DoesNotHonorSigningKeyOverridesThroughTokenValidationParams()
        {
            var fakeSigningKeys = new List<SecurityKey>() { new RsaSecurityKey(RSA.Create()) };
            var validationParams = new TokenValidationParameters()
            {
                RequireSignedTokens = false,
                ValidAudience = "OverriddenAudience",
                IssuerSigningKeys = fakeSigningKeys
            };

            _mockConfigurationManager
                .Setup(o => o.GetConfigurationAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new OpenIdConnectConfiguration(GetConfigResponse()));

            var authService = BuildAuthServiceInternal(validationParams);

            await authService.ValidateTokenAsync(FakeInputToken);

            _mockTokenValidator.Verify(
                o => o.ValidateToken(
                    It.IsAny<string>(), 
                    It.Is<TokenValidationParameters>(p => p.ValidAudience == validationParams.ValidAudience && p.RequireSignedTokens == validationParams.RequireSignedTokens && p.IssuerSigningKeys != fakeSigningKeys), 
                    out _validatedToken
                    ), 
                Times.Once
                );
        }

        [Fact]
        public async void ValidateTokenAsync_HandlesSigningKeyChangeAppropriately()
        {
            _mockTokenValidator
                .Setup(o => o.ValidateToken(It.IsAny<string>(), It.IsAny<TokenValidationParameters>(), out _validatedToken))
                .Throws<SecurityTokenSignatureKeyNotFoundException>();
            
            _mockConfigurationManager
                .Setup(o => o.RequestRefresh());

            var authService = new AuthenticationService(_apiSettings, _mockConfigurationManager.Object, null, null, _mockTokenValidator.Object);
            try
            {
                await authService.ValidateTokenAsync(FakeInputToken);
            }
            catch(SecurityTokenSignatureKeyNotFoundException)
            {
                //NOTE: _mockTokenValidator throws this exception twice (first triggers retry, second bubbles up).
            }

            _mockConfigurationManager.Verify(o => o.RequestRefresh(), Times.Once);
            _mockTokenValidator
                .Verify(o => o.ValidateToken(It.IsAny<string>(), It.IsAny<TokenValidationParameters>(), out _validatedToken), Times.Exactly(2));
        }

        public string GetConfigResponse()
        {
            return 
            "{\"issuer\":\"https://betterbookmarks.auth0.com/\",\"authorization_endpoint\":\"https://betterbookmarks.auth0.com/authorize\",\"token_endpoint\":\"https://betterbookmarks.auth0.com/oauth/token\",\"userinfo_endpoint\":\"https://betterbookmarks.auth0.com/userinfo\",\"mfa_challenge_endpoint\":\"https://betterbookmarks.auth0.com/mfa/challenge\",\"jwks_uri\":\"https://betterbookmarks.auth0.com/.well-known/jwks.json\",\"registration_endpoint\":\"https://betterbookmarks.auth0.com/oidc/register\",\"revocation_endpoint\":\"https://betterbookmarks.auth0.com/oauth/revoke\",\"scopes_supported\":[\"openid\",\"profile\",\"offline_access\",\"name\",\"given_name\",\"family_name\",\"nickname\",\"email\",\"email_verified\",\"picture\",\"created_at\",\"identities\",\"phone\",\"address\"],\"response_types_supported\":[\"code\",\"token\",\"id_token\",\"code token\",\"code id_token\",\"token id_token\",\"code token id_token\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"HS256\",\"RS256\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"claims_supported\":[\"aud\",\"auth_time\",\"created_at\",\"email\",\"email_verified\",\"exp\",\"family_name\",\"given_name\",\"iat\",\"identities\",\"iss\",\"name\",\"nickname\",\"phone_number\",\"picture\",\"sub\"],\"request_uri_parameter_supported\":false}";
        }
    }
}