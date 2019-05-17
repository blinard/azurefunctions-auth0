# azurefunctions-auth0

Usage:

```
static Auth0ApiSettings apiSettings = new Auth0ApiSettings()
                                    {
                                        Issuer = appSettings.AuthIssuer,
                                        Audience = appSettings.AuthAudience
                                    };

static IConfigurationManager<>
```

Credit:

https://liftcodeplay.com/2017/11/25/validating-auth0-jwt-tokens-in-azure-functions-aka-how-to-use-auth0-with-azure-functions/

https://blog.wille-zone.de/post/secure-azure-functions-with-jwt-token/

