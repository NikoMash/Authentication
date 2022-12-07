using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;


public class DummyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public DummyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock
        ) : base(options, logger, encoder, clock)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Vi undersøge lige om anonym adgang er tilladt
        var endpoint = Context.GetEndpoint();
        if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
        {
            // Hvis anonym adgang er tilladt, skal vi ikke lave authentication
            return Task.FromResult(AuthenticateResult.NoResult());
        }
        byte[] saltBytes = new byte[128 / 8];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetNonZeroBytes(saltBytes);
        } 

        string salt = Convert.ToBase64String(saltBytes); 

        //hash og salt af forventede passwords fra headeren 
        string adminPassword = "password123";
        string hashedAdminPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: adminPassword,
            salt: Convert.FromBase64String(salt),
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        string cakePassword = "cake123";
        string hashedCakePassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: cakePassword,
            salt: Convert.FromBase64String(salt),
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        // Vi fisker en header ud hvor key er "Authorization"
        var authHeader = Request.Headers["Authorization"].ToString();

        var password = authHeader.Substring("Password ".Length).Trim();
            string hashedIncoming = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: Convert.FromBase64String(salt),
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

        // Vi tjekker efterfølgende på om "Authorization" findes, og på om dens value starter med "Password".
        if (authHeader != null && authHeader.StartsWith("Password", StringComparison.OrdinalIgnoreCase))
        {                
            // Nu tjekkes om password er korrekt
            if (hashedIncoming == hashedAdminPassword)
            {
                // Vi opretter et "claim"
                var claims = new[] { new Claim("Role", "Admin") };
                var identity = new ClaimsIdentity(claims);
                var claimsPrincipal = new ClaimsPrincipal(identity);

                // Claim returneres og giver nu adgang til endpoints der i deres 
                // policty har "Role = Admin".
                return Task.FromResult(AuthenticateResult.Success(
                    new AuthenticationTicket(claimsPrincipal, "DummyAuthentication")));
            }  
        }

        if (authHeader != null && authHeader.StartsWith("Password", StringComparison.OrdinalIgnoreCase))
        {
            // Nu tjekkes om password er korrekt
            if (hashedIncoming == hashedCakePassword)
            {
                // Vi opretter et "claim"
                var claims = new[] { new Claim("Role", "CakeLover") };
                var identity = new ClaimsIdentity(claims);
                var claimsPrincipal = new ClaimsPrincipal(identity);

                // Claim returneres og giver nu adgang til endpoints der i deres 
                // policty har "Role = Admin".
                return Task.FromResult(AuthenticateResult.Success(
                    new AuthenticationTicket(claimsPrincipal, "DummyAuthentication")));
            }  
        }
 
        Response.StatusCode = 401;
        return Task.FromResult(AuthenticateResult.Fail("Invalid Password"));  
    }
}