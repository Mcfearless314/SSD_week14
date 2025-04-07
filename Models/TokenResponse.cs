namespace SSD_week14.Models;

public class TokenResponse
{
    public string access_token { get; init; }
    public int expires_in { get; init; }
    public string id_token { get; init; }
    public string scope { get; init; }
    public string token_type { get; init; }
    public string refresh_token { get; init; }
}