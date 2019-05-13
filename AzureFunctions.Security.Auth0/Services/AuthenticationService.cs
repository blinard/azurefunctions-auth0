using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Polly;

[assembly: InternalsVisibleTo("AzureFunctions.Security.Auth0.UnitTests")]
namespace AzureFunctions.Security.Auth0
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly Auth0ApiSettings _apiSettings;
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configManager;
        internal readonly IAsyncPolicy<ClaimsPrincipal> _validationRequestPolicy;
        private readonly TokenValidationParameters _validationParamOverrides;
        internal readonly ISecurityTokenValidator _tokenValidator;

        public AuthenticationService(Auth0ApiSettings apiSettings, IConfigurationManager<OpenIdConnectConfiguration> configManager) : this(apiSettings, configManager, null, null, null) { }

        public AuthenticationService(Auth0ApiSettings apiSettings, IConfigurationManager<OpenIdConnectConfiguration> configManager, TokenValidationParameters validationParamOverrides) : this(apiSettings, configManager, validationParamOverrides, null, null) { }

        internal AuthenticationService(Auth0ApiSettings apiSettings, IConfigurationManager<OpenIdConnectConfiguration> configManager, TokenValidationParameters validationParamOverrides, IAsyncPolicy<ClaimsPrincipal> validationRequestPolicy, ISecurityTokenValidator tokenValidator)
        {
            _apiSettings = apiSettings;
            _configManager = configManager;
            _validationRequestPolicy = validationRequestPolicy;
            _validationParamOverrides = validationParamOverrides;
            _tokenValidator = tokenValidator ?? new JwtSecurityTokenHandler();

            if (_validationRequestPolicy == null) 
            {
                _validationRequestPolicy = Policy
                    .Handle<SecurityTokenSignatureKeyNotFoundException>()
                    .RetryAsync(1, (ex, retryCount) => 
                    {
                        _configManager.RequestRefresh();
                    })
                    .AsAsyncPolicy<ClaimsPrincipal>();
            }
        }

        public async Task<ClaimsPrincipal> ValidateTokenAsync(string token)
        {
            return await _validationRequestPolicy
                .ExecuteAsync(async () =>
                {
                    var authConfig = await _configManager.GetConfigurationAsync(CancellationToken.None);
                    var validationParams = BuildTokenValidationParameters(authConfig);

                    return _tokenValidator.ValidateToken(token, validationParams, out var validatedToken);
                });
        }

        private TokenValidationParameters BuildTokenValidationParameters(OpenIdConnectConfiguration authConfig)
        {
            var defaultParams = new TokenValidationParameters()
            {
                RequireSignedTokens = true,
                ValidAudience = _apiSettings.Audience,
                ValidateAudience = true,
                ValidIssuer = _apiSettings.Issuer,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true
            };

            var resultParams = _validationParamOverrides ?? defaultParams;
            resultParams.IssuerSigningKeys = authConfig.SigningKeys;
            return resultParams;
        }
    }
}