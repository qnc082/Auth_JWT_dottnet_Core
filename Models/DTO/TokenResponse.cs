namespace Auth.Models.DTO
{
    public class TokenResponse
    {
        public string TokenString { get; set; }
        public DateTimeOffset ValidTo { get; set; }
    }
}
