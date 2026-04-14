using System;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RvSpy.Client
{
    /// <summary>
    /// Main entry point for talking to the RvSpy auth server.
    /// You can call this from WPF, WinForms, console, or native apps via C++/CLI.
    /// </summary>
    public sealed class RvSpyClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private bool _disposeClient;

        public string ApplicationId { get; }
        public string ApplicationSecret { get; }

        public Uri BaseUri => _httpClient.BaseAddress;

        /// <summary>
        /// Create a new client instance.
        /// </summary>
        /// <param name="baseUrl">Base URL of your RvSpy auth server (e.g. https://auth.example.com/).</param>
        /// <param name="applicationId">Public application identifier.</param>
        /// <param name="applicationSecret">Private application secret used to sign requests.</param>
        /// <param name="httpClient">Optional HttpClient instance. If null, a new one will be created and disposed with the client.</param>
        public RvSpyClient(
            string baseUrl,
            string applicationId,
            string applicationSecret,
            HttpClient httpClient = null)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))
                throw new ArgumentException("Base URL must not be empty.", nameof(baseUrl));
            if (string.IsNullOrWhiteSpace(applicationId))
                throw new ArgumentException("ApplicationId must not be empty.", nameof(applicationId));
            if (string.IsNullOrWhiteSpace(applicationSecret))
                throw new ArgumentException("ApplicationSecret must not be empty.", nameof(applicationSecret));

            _disposeClient = httpClient is null;
            _httpClient = httpClient ?? new HttpClient();
            _httpClient.BaseAddress = new Uri(baseUrl, UriKind.Absolute);

            ApplicationId = applicationId;
            ApplicationSecret = applicationSecret;
        }

        /// <summary>
        /// Try to log a user in with username/password.
        /// Right now this is a placeholder that expects your backend to expose POST /api/login.
        /// </summary>
        public async Task<RvSpyLoginResult> LoginAsync(
            string username,
            string password,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentException("Username must not be empty.", nameof(username));
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password must not be empty.", nameof(password));

            var payload = new
            {
                appId = ApplicationId,
                appSecret = ApplicationSecret,
                username,
                password
            };

            using var content = new StringContent(
                JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json");

            using var response = await _httpClient.PostAsync("api/login", content, cancellationToken)
                .ConfigureAwait(false);

            var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return new RvSpyLoginResult(
                    success: false,
                    token: null,
                    errorCode: (int)response.StatusCode,
                    errorMessage: body);
            }

            var result = JsonSerializer.Deserialize<RvSpyLoginResult>(body, JsonSerializerOptions.Default);
            return result ?? new RvSpyLoginResult(false, null, -1, "Invalid response from server.");
        }

        public void Dispose()
        {
            if (_disposeClient)
            {
                _httpClient.Dispose();
                _disposeClient = false;
            }
        }
    }

    /// <summary>
    /// Simple DTO for the login response.
    /// You can adjust this shape later to match your backend.
    /// </summary>
    public sealed class RvSpyLoginResult
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public int ErrorCode { get; set; }
        public string ErrorMessage { get; set; }

        public RvSpyLoginResult()
        {
        }

        public RvSpyLoginResult(bool success, string token, int errorCode, string errorMessage)
        {
            Success = success;
            Token = token;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
        }
    }
}
