using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AzureFunctions.Security.Auth0
{
    public abstract class ConfigurationManagerFactory
    {
        public static IConfigurationManager<OpenIdConnectConfiguration> GetConfigurationManager(Auth0ApiSettings apiSettings)
        {
            var documentRetriever = new HttpDocumentRetriever { RequireHttps = apiSettings.Issuer.StartsWith("https://") };

            return new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{apiSettings.Issuer}.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                documentRetriever
            );
        }
    }
}