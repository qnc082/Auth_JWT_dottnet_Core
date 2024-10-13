namespace Auth.Models.DTO
{
    public class LoginResponse : Status
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public string Expiration { get; set; }
        public string Name { get; set; }
        public string UserName { get; set; }
    }
}
