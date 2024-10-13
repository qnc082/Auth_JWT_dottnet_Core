namespace Auth.Models.Entities
{
    public class TokenInfo
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string RefreshToken { get; set; }
        public DateTimeOffset RefreshTokenExpiry { get; set; }
    }
}
