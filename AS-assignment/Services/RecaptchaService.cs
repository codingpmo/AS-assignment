using System.Net.Http.Json;
using System.Text.Json;

namespace AceJobAgency.Services
{
    public class RecaptchaService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<RecaptchaService> _logger;

        public RecaptchaService(IHttpClientFactory httpClientFactory, IConfiguration configuration, ILogger<RecaptchaService> logger)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<bool> VerifyTokenAsync(string token)
        {
            try
            {
                var secretKey = _configuration["RecaptchaSettings:SecretKey"];
                
                if (string.IsNullOrEmpty(secretKey))
                {
                    _logger.LogError("reCAPTCHA SecretKey is not configured");
                    return false;
                }

                var client = _httpClientFactory.CreateClient();

                var request = new Dictionary<string, string>
                {
                    { "secret", secretKey },
                    { "response", token }
                };

                _logger.LogInformation("Sending reCAPTCHA verification request to Google");

                var response = await client.PostAsync(
                    "https://www.google.com/recaptcha/api/siteverify",
                    new FormUrlEncodedContent(request));

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError($"reCAPTCHA API returned status code: {response.StatusCode}");
                    return false;
                }

                var jsonContent = await response.Content.ReadAsStringAsync();
                _logger.LogInformation($"reCAPTCHA API Response: {jsonContent}");

                var result = JsonSerializer.Deserialize<RecaptchaResponse>(jsonContent, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                
                if (result == null)
                {
                    _logger.LogError("Failed to deserialize reCAPTCHA response");
                    return false;
                }

                _logger.LogInformation($"reCAPTCHA Success: {result.Success}, Score: {result.Score}");

                // v3 returns a score between 0 and 1 (1 = legitimate, 0 = bot)
                // Adjust threshold as needed (0.5 is reasonable)
                bool isValid = result.Success && result.Score >= 0.5;
                return isValid;
            }
            catch (Exception ex)
            {
                _logger.LogError($"reCAPTCHA verification exception: {ex.Message}");
                return false;
            }
        }
    }

    public class RecaptchaResponse
    {
        public bool Success { get; set; }
        public double Score { get; set; }
        public string Action { get; set; }
        public DateTime ChallengeTimestamp { get; set; }
        public string Hostname { get; set; }
        public string[] ErrorCodes { get; set; }
    }
}