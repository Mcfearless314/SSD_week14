using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using SSD_week14.Models;

namespace SSD_week14.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly IConfiguration _configuration;

    public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public IActionResult Index()
    {
        var accessToken = HttpContext.Session.GetString("access_token");
        if (string.IsNullOrEmpty(accessToken))
        {
            return RedirectToAction("Login");
        }

        var userInfo = HttpContext.Session.GetString("user_info");
        ViewData["UserInfo"] = userInfo;
        
        return View();
    }

    public record AuthorizationResponse(string state, string code);

    public IActionResult Login()
    {
        var clientId = _configuration["OAuth:ClientId"];
        var redirectUri = "http://localhost:5002/Home/Callback";
        var authorizationEndpoint = "http://localhost:8080/realms/master/protocol/openid-connect/auth";

        var state = GenerateRngString();
        var codeVerifier = GenerateRngString();
        var codeChallenge = CodeChallengeVerifier(codeVerifier);

        HttpContext.Session.SetString($"code_verifier:{state}", codeVerifier);

        var parameters = new Dictionary<string, string?>
        {
            { "client_id", clientId },
            { "scope", "openid email profile" },
            { "response_type", "code" },
            { "redirect_uri", redirectUri },
            { "prompt", "login" },
            { "state", state },
            { "code_challenge_method", "S256" },
            { "code_challenge", codeChallenge }
        };

        var authorizationUri = QueryHelpers.AddQueryString(authorizationEndpoint, parameters);
        return Redirect(authorizationUri);
    }

    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index");
    }

    public async Task<IActionResult> Callback(AuthorizationResponse query)
    {
        var (state, code) = query;

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
        {
            _logger.LogWarning("Missing authorization code or state");
            return BadRequest("Missing authorization code or state");
        }

        var codeVerifier = HttpContext.Session.GetString($"code_verifier:{state}");
        if (string.IsNullOrEmpty(codeVerifier))
        {
            _logger.LogWarning("Missing code verifier from session");
            return BadRequest("Missing code verifier from session");
        }

        var tokenEndpoint = "http://localhost:8080/realms/master/protocol/openid-connect/token";
        var clientId = "miran_client";
        var clientSecret = _configuration["OAuth:ClientSecret"];
        var redirectUri = "http://localhost:5002/Home/Callback";

        var parameters = new Dictionary<string, string?>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", redirectUri },
            { "code_verifier", codeVerifier },
            { "client_id", clientId },
            { "client_secret", clientSecret }
        };

        try
        {
            using var httpClient = new HttpClient();
            var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(parameters));
            var payload = await response.Content.ReadFromJsonAsync<TokenResponse>();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError($"Error exchanging code: {response.StatusCode}\n{payload}");
                return Content($"Error exchanging code: {response.StatusCode}\n\n{payload}");
            }

            var tokenValidation = await ValidateIdToken(payload.id_token);

            if (!tokenValidation)
            {
                _logger.LogWarning("Invalid ID Token");
                return Content("Invalid ID Token!");
            }

            HttpContext.Session.SetString("access_token", payload.access_token);
            HttpContext.Session.SetString("id_token", payload.id_token);
            HttpContext.Session.SetString("refresh_token", payload.refresh_token);

            var userInfo = await GetUserInfo(payload.access_token);
            HttpContext.Session.SetString("user_info", userInfo);

            return Content($"User info:\n\n{userInfo}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing callback");
            return StatusCode(500, "Internal server error");
        }
    }

    public async Task<bool> ValidateIdToken(string idToken)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(idToken);
            var keycloakJwkUri = "http://localhost:8080/realms/master/protocol/openid-connect/certs";

            var response = await new HttpClient().GetAsync(keycloakJwkUri);
            var keys = await response.Content.ReadAsStringAsync();

            var jsonWebKeySet = JsonWebKeySet.Create(keys);
            var signingKeys = jsonWebKeySet.Keys;
            jsonWebKeySet.SkipUnresolvedJsonWebKeys = false;

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateIssuer = true,
                ValidIssuer = jwtToken.Issuer,
                ValidateAudience = true,
                ValidAudience = "miran_client",
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            handler.ValidateToken(idToken, validationParameters, out var validatedToken);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token validation failed");
            return false;
        }
    }

    public async Task<string> GetUserInfo(string accessToken)
    {
        try
        {
            var userinfoEndpoint = "http://localhost:8080/realms/master/protocol/openid-connect/userinfo";

            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.GetAsync(userinfoEndpoint);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError($"Error fetching user info: {response.StatusCode}");
                return $"Error fetching user info: {response.StatusCode}";
            }

            return await response.Content.ReadAsStringAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching user info");
            return "Error fetching user info";
        }
    }

    private string GenerateRngString()
    {
        try
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[32];
                rng.GetBytes(bytes);
                return Base64UrlTextEncoder.Encode(bytes);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating random string");
            throw;
        }
    }

    private string CodeChallengeVerifier(string codeVerifier)
    {
        try
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(codeVerifier);
                var hash = sha256.ComputeHash(bytes);
                return Base64UrlTextEncoder.Encode(hash);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating code challenge verifier");
            throw;
        }
    }
}