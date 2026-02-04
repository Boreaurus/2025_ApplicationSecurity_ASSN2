using System.Text.Json;

namespace ApplicationSecurityAssignment2.Services
{
    public class RecaptchaService
    {
        private readonly HttpClient _http;
        private readonly IConfiguration _config;

        public RecaptchaService(HttpClient http, IConfiguration config)
        {
            _http = http;
            _config = config;
        }

        public async Task<(bool ok, double score, string[] errors)> VerifyAsync(string token, string? expectedAction, string? remoteIp = null)
        {
            var secret = _config["Recaptcha:SecretKey"];
            if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(token))
                return (false, 0, new[] { "missing-secret-or-token" });

            var form = new Dictionary<string, string>
            {
                ["secret"] = secret,
                ["response"] = token
            };
            if (!string.IsNullOrWhiteSpace(remoteIp))
                form["remoteip"] = remoteIp;

            using var resp = await _http.PostAsync(
                "https://www.google.com/recaptcha/api/siteverify",
                new FormUrlEncodedContent(form));

            resp.EnsureSuccessStatusCode();

            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc = await JsonDocument.ParseAsync(stream);

            var root = doc.RootElement;
            var success = root.GetProperty("success").GetBoolean();
            var score = root.TryGetProperty("score", out var s) ? s.GetDouble() : 0.0;
            var action = root.TryGetProperty("action", out var a) ? a.GetString() : null;

            var errors = root.TryGetProperty("error-codes", out var e) && e.ValueKind == JsonValueKind.Array
                ? e.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x != "").ToArray()
                : Array.Empty<string>();

            if (!success) return (false, score, errors);

            if (!string.IsNullOrWhiteSpace(expectedAction) &&
                !string.Equals(action, expectedAction, StringComparison.OrdinalIgnoreCase))
                return (false, score, new[] { "action-mismatch" });

            return (true, score, errors);
        }
    }
}
