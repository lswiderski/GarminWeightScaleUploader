using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using GarminConnectClient.Lib.Dto;
using GarminConnectClient.Lib.Enum;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using OAuth;


namespace GarminConnectClient.Lib.Services
{
    /// <inheritdoc />
    /// <summary>
    /// Client implementation.
    /// Inspired by https://github.com/La0/garmin-uploader
    /// </summary>
    /// <seealso cref="T:GarminConnectClient.Lib.Services.IClient" />
    public class Client : IClient
    {
        private const string LOCALE = "en_US";

        private const string CONNECT_DNS = "connect.garmin.com";
        private const string CONNECT_URL = "https://" + CONNECT_DNS;
        private const string CONNECT_URL_MODERN = CONNECT_URL + "/";
        private const string CONNECT_URL_SIGNIN = CONNECT_URL + "/signin/";
        private const string SSO_DNS = "sso.garmin.com";
        private const string SSO_URL = "https://" + SSO_DNS;
        private const string SSO_URL_SSO = SSO_URL + "/sso";
        private const string SSO_URL_SSO_SIGNIN = SSO_URL_SSO + "/signin";
        private const string CONNECT_URL_PROFILE = CONNECT_URL_MODERN + "proxy/userprofile-service/socialProfile/";
        private const string CONNECT_MODERN_HOSTNAME = "https://connect.garmin.com/modern/auth/hostname";
        private const string CSS_URL = CONNECT_URL + "/gauth-custom-v1.2-min.css";
        private const string PRIVACY_STATEMENT_URL = "https://www.garmin.com/en-US/privacy/connect/";
        private const string URL_UPLOAD = CONNECT_URL + "/upload-service/upload";
        private const string URL_ACTIVITY_BASE = CONNECT_URL + "/activity-service/activity";

        private const string UrlActivityTypes =
            "https://connect.garmin.com/proxy/activity-service/activity/activityTypes";

        private const string UrlEventTypes =
            "https://connect.garmin.com/proxy/activity-service/activity/eventTypes";

        private const string UrlActivitiesBase =
            "https://connect.garmin.com/activitylist-service/activities/search/activities";

        private const string UrlActivityDownloadFile =
            "https://connect.garmin.com/modern/proxy/download-service/export/{0}/activity/{1}";

        private const string UrlActivityDownloadDefaultFile =
            "https://connect.garmin.com/modern/proxy/download-service/files/activity/{0}";

        private const ActivityFileTypeEnum DefaultFile = ActivityFileTypeEnum.Fit;

        private const string CONSUMER_KEY = "fc3e99d2-118c-44b8-8ae3-03370dde24c0";
        private const string CONSUMER_SECRET = "E08WAR897WEy2knn7aFBrvegVAf0AFdWBBF";
        private const string USER_AGENT = "com.garmin.android.apps.connectmobile";
        private const string SSO = "https://sso.garmin.com/sso";
        private const string SSO_EMBED = $"{SSO}/embed";
        private static readonly Dictionary<string, string> SSO_EMBED_PARAMS = new()
        {
            {"id", "gauth-widget"},
            {"embedWidget", "true"},
            {"gauthHost", SSO},
        };
        private static readonly Dictionary<string, string> SIGNIN_PARAMS = new()
        {
            {"id", "gauth-widget"},
            {"embedWidget", "true"},
            {"gauthHost", SSO_EMBED},
            {"service", SSO_EMBED},
            {"source", SSO_EMBED},
            {"redirectAfterAccountLoginUrl", SSO_EMBED},
            {"redirectAfterAccountCreationUrl", SSO_EMBED},
        };

        private static readonly CookieContainer _cookieContainer = new();
        private static readonly HttpClientHandler _clientHandler = new()
        {
            AllowAutoRedirect = true,
            UseCookies = true,
            CookieContainer = _cookieContainer
        };
        private static HttpClient httpClient = new(_clientHandler)
        {
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher,
        };

        private static readonly Tuple<string, string> BaseHeader = new("NK", "NT");


        /// <summary>
        /// The configuration
        /// </summary>
        private readonly IConfiguration _configuration;

        /// <summary>
        /// The logger
        /// </summary>
        // ReSharper disable once NotAccessedField.Local
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="Client"/> class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        /// <param name="logger">The logger.</param>
        public Client(IConfiguration configuration, ILogger logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        /// <inheritdoc />
        /// <summary>
        /// Authenticates this instance.
        /// </summary>
        /// <returns>
        /// Tuple of Cookies and HTTP handler
        /// </returns>
        /// <exception cref="T:System.Exception">
        /// SSO hostname is missing
        /// or
        /// Could not match service ticket.
        /// </exception>
        /// 

        public async Task<OAuth2Token> GetOAuth2Token(string accessToken, string tokenSecret)
        {
            
            OAuthRequest oauthClient2 = OAuthRequest.ForProtectedResource("POST", CONSUMER_KEY, CONSUMER_SECRET, accessToken, tokenSecret);

            oauthClient2.RequestUrl = $"https://connectapi.garmin.com/oauth-service/oauth/exchange/user/2.0";
            string auth2 = oauthClient2.GetAuthorizationHeader();

            HttpWebRequest request2 = (HttpWebRequest)WebRequest.Create(oauthClient2.RequestUrl);

            request2.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            request2.Headers.Add("Authorization", auth2);
            request2.Headers.Add("User-Agent", USER_AGENT);
            request2.Method = "POST";
            
            var oauthContent2 = "";
            OAuth2Token token = null;
            using (var oAuthResponse = (HttpWebResponse)request2.GetResponse())
            {

                using (var responseStream = oAuthResponse.GetResponseStream())
                using (var reader = new StreamReader(responseStream))
                    oauthContent2 = reader.ReadToEnd();
                token = DeserializeData<OAuth2Token>(oauthContent2);

            }

            return token;
        }
        public async Task<(string accessToken, string tokenSecret)> GetOAuth1Token(string ticket)
        {
            OAuthRequest oauthClient = OAuthRequest.ForRequestToken(CONSUMER_KEY, CONSUMER_SECRET);
            oauthClient.RequestUrl = $"https://connectapi.garmin.com/oauth-service/oauth/preauthorized?ticket={WebUtility.UrlEncode(ticket)}&login-url=https://sso.garmin.com/sso/embed&accepts-mfa-tokens=true";
            string auth = oauthClient.GetAuthorizationHeader();

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(oauthClient.RequestUrl);
            request.Headers.Add("user-agent", USER_AGENT);
            request.Headers.Add("Authorization", auth);
            var oauthContent = "";
            using (var oAuthResponse = (HttpWebResponse)request.GetResponse())
            {
                var encoding = Encoding.GetEncoding(oAuthResponse.CharacterSet);

                using (var responseStream = oAuthResponse.GetResponseStream())
                using (var reader = new StreamReader(responseStream, encoding))
                    oauthContent = reader.ReadToEnd();
            }


            var oauth_token = HttpUtility.ParseQueryString(oauthContent)[0];
            var oauth_token_secret = HttpUtility.ParseQueryString(oauthContent)[1];

            return (oauth_token, oauth_token_secret);
        }

        public async Task<(CookieContainer, HttpClientHandler)> Authenticate(string userName, string password)
        {
            httpClient.DefaultRequestHeaders.Clear();
            httpClient.DefaultRequestHeaders.Add("user-agent", USER_AGENT);
            var data = await httpClient.GetStringAsync(CONNECT_MODERN_HOSTNAME);

            var ssoHostname = JObject.Parse(data)["host"] == null
                ? throw new Exception("SSO hostname is missing")
                : JObject.Parse(data)["host"].ToString();

            //set cookies
            var embedParams = string.Join("&", SSO_EMBED_PARAMS.Select(e => $"{e.Key}={WebUtility.UrlEncode(e.Value)}"));
            var url = $"{SSO_EMBED}?{embedParams}";
            var res = await httpClient.GetAsync(url);
            
            var signinParams = string.Join("&", SIGNIN_PARAMS.Select(e => $"{e.Key}={WebUtility.UrlEncode(e.Value)}"));
            
            url = $"{SSO}/signin?{signinParams}";
            res = await httpClient.GetAsync(url);
            ValidateResponseMessage(res, "No login form.");
            
            data = await res.Content.ReadAsStringAsync();
            var csrfToken = "";
            try
            {
                csrfToken = GetValueByPattern(data, @"name=""_csrf""\s+value=""(.+?)""", 2, 1);
            }
            catch (Exception e)
            {
                _logger.LogError("Exception finding token by pattern: ", e);
                _logger.LogError("data:\n", data);
                throw;
            }
            
            httpClient.DefaultRequestHeaders.Add("origin", SSO_URL);
            httpClient.DefaultRequestHeaders.Add("referer", $"{SSO}/signin");
            
            httpClient.DefaultRequestHeaders.Add(BaseHeader.Item1, BaseHeader.Item2);
            
            
            var formContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("embed", "true"),
                new KeyValuePair<string, string>("username", userName),
                new KeyValuePair<string, string>("password", password),
                new KeyValuePair<string, string>("_csrf", csrfToken)
            });
            
            
            res = await httpClient.PostAsync(url, formContent);
            data = await res.Content.ReadAsStringAsync();
            
            
            var ticket = "";
            try
            {
                ticket = GetValueByPattern(data, @"embed\?ticket=([^""]+)""", 2, 1);
            }
            catch (Exception e)
            {
                _logger.LogError("Exception finding ticket by pattern: ", e);
                _logger.LogError("data:\n", data);
                throw;
            }


            //get oauth1
            var oauth1Token = await this.GetOAuth1Token(ticket);

            if(oauth1Token == default || string.IsNullOrEmpty(oauth1Token.accessToken) || string.IsNullOrEmpty(oauth1Token.tokenSecret))
            {
                throw new Exception("oAuth1 failed");
            }
            //get oauth2 token
            var oAuth2Token = await this.GetOAuth2Token(oauth1Token.accessToken, oauth1Token.tokenSecret);

            if(oAuth2Token == null)
            {
                throw new Exception("oAuth2 failed");
            }

            httpClient.DefaultRequestHeaders.Add("Di-Backend", "connectapi.garmin.com");
            httpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", oAuth2Token.Access_Token);
            res = await httpClient.GetAsync($"https://connect.garmin.com/weight-service/weight/range/2023-08-15/2023-09-26");
            data = await res.Content.ReadAsStringAsync();

            ValidateModernTicketUrlResponseMessage(res, $"Weight get failed: {res.StatusCode}.");

            return (_cookieContainer, _clientHandler);

        }

        /// <summary>
        /// Gets the value by pattern.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="pattern">The pattern.</param>
        /// <param name="expectedCountOfGroups">The expected count of groups.</param>
        /// <param name="groupPosition">The group position.</param>
        /// <returns>Value of particular match group.</returns>
        /// <exception cref="Exception">Could not match expected pattern {pattern}</exception>
        private static string GetValueByPattern(string data, string pattern, int expectedCountOfGroups, int groupPosition)
        {
            var regex = new Regex(pattern);
            var match = regex.Match(data);
            if (!match.Success || match.Groups.Count != expectedCountOfGroups)
            {
                throw new Exception($"Could not match expected pattern {pattern}.");
            }
            return match.Groups[groupPosition].Value;
        }

        /// <summary>
        /// Validates the cookie presence.
        /// </summary>
        /// <param name="container">The container.</param>
        /// <param name="cookieName">Name of the cookie.</param>
        /// <exception cref="Exception">Missing cookie {cookieName}</exception>
        private static void ValidateCookiePresence(CookieContainer container, string cookieName)
        {
            var cookies = container.GetCookies(new Uri(CONNECT_URL_MODERN)).Cast<Cookie>().ToList();
            if (!cookies.Any(e => string.Equals(cookieName, e.Name, StringComparison.InvariantCultureIgnoreCase)))
            {
                throw new Exception($"Missing cookie {cookieName}");
            }
        }

        // ReSharper disable once ParameterOnlyUsedForPreconditionCheck.Local
        private static void ValidateResponseMessage(HttpResponseMessage responseMessage, string errorMessage)
        {
            if (!responseMessage.IsSuccessStatusCode)
            {
                throw new Exception(errorMessage);
            }
        }

        private static void ValidateModernTicketUrlResponseMessage(HttpResponseMessage responseMessage, string error)
        {
            if (!responseMessage.IsSuccessStatusCode && !responseMessage.StatusCode.Equals(HttpStatusCode.OK))
            {
                throw new Exception(error);
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// Downloads the activity file.
        /// </summary>
        /// <param name="activityId">The activity identifier.</param>
        /// <param name="fileFormat">The file format.</param>
        /// <returns>
        /// Stream
        /// </returns>
        public async Task<Stream> DownloadActivityFile(long activityId, ActivityFileTypeEnum fileFormat)
        {
            var url = fileFormat == DefaultFile
                ? string.Format(UrlActivityDownloadDefaultFile, activityId)
                : string.Format(UrlActivityDownloadFile, fileFormat.ToString().ToLower(), activityId);

            Stream streamCopy = new MemoryStream();
            var res = await httpClient.GetAsync(url);

            await (await res.Content.ReadAsStreamAsync()).CopyToAsync(streamCopy);
            return streamCopy;
        }

        /// <inheritdoc />
        /// <summary>
        /// Uploads the activity.
        /// </summary>
        /// <param name="fileName">Name of the file.</param>
        /// <param name="fileFormat">The file format.</param>
        /// <returns>
        /// Tuple of result and activity id
        /// </returns>
        /// <exception cref="T:System.Exception">
        /// Failed to upload {fileName}
        /// or
        /// or
        /// Unknown error: {response.ToString()}
        /// </exception>
        public async Task<(bool Success, long ActivityId)> UploadActivity(string fileName, FileFormat fileFormat)
        {
            var extension = fileFormat.FormatKey;
            var url = $"{URL_UPLOAD}/.{extension}";

            var form = new MultipartFormDataContent(
                $"------WebKitFormBoundary{DateTime.UtcNow.ToString(CultureInfo.InvariantCulture)}");

            using var stream = new FileStream(fileName, FileMode.Open);
            using var content = new StreamContent(stream);

            content.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "file",
                FileName = Path.GetFileName(fileName),
                Size = stream.Length
            };

            form.Add(content, "file", Path.GetFileName(fileName));
            // WriteToFile(stream);
            var res = await httpClient.PostAsync(url, form);
            // HTTP Status can either be OK or Conflict
            if (!new HashSet<HttpStatusCode>
                                {HttpStatusCode.OK, HttpStatusCode.Created, HttpStatusCode.Conflict}
                .Contains(res.StatusCode))
            {
                if (res.StatusCode == HttpStatusCode.PreconditionFailed)
                {
                    throw new Exception($"Failed to upload {fileName}");
                }
            }

            var responseData = await res.Content.ReadAsStringAsync();
            var response = JObject.Parse(responseData)["detailedImportResult"];
            var successes = response["successes"];
            if (successes.HasValues)
            {
                _ = long.TryParse(successes[0]["internalId"].ToString(), out long internalId);
                return (true, internalId);
            }

            var failures = response["failures"];
            if (!failures.HasValues)
            {
                throw new Exception($"Unknown error: {response}");
            }

            var messages = failures[0]["messages"];
            var code = int.Parse(messages[0]["code"].ToString());
            if (code == (int)HttpStatusCode.Accepted)
            {
                // Activity already exists
                _ = long.TryParse(successes[0]["internalId"].ToString(), out long internalId);
                return (false, internalId);
            }

            throw new Exception(messages.ToString());
        }

        public void WriteToFile(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);

            using (var fs = new FileStream("/file", FileMode.OpenOrCreate))
            {
                stream.CopyTo(fs);
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// Sets the name of the activity.
        /// </summary>
        /// <param name="activityId">The activity identifier.</param>
        /// <param name="activityName">Name of the activity.</param>
        /// <returns>
        /// The task
        /// </returns>
        public async Task SetActivityName(long activityId, string activityName)
        {
            var url = $"{URL_ACTIVITY_BASE}/{activityId}";
            httpClient.DefaultRequestHeaders.Add("X-HTTP-Method-Override", "PUT");

            var data = new
            {
                activityId,
                activityName
            };

            var res = await httpClient.PostAsync(url,
                new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json"));

            if (!res.IsSuccessStatusCode)
            {
                throw new Exception($"Activity name not set: {await res.Content.ReadAsStringAsync()}");
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// Loads the activity types.
        /// </summary>
        /// <returns>
        /// List of activities
        /// </returns>
        public async Task<List<ActivityType>> LoadActivityTypes()
        {
            return await ExecuteUrlGetRequest<List<ActivityType>>(UrlActivityTypes,
                "Error while getting activity types");
        }

        /// <summary>
        /// Loads the event types.
        /// </summary>
        /// <returns></returns>
        public async Task<List<ActivityType>> LoadEventTypes()
        {
            return await ExecuteUrlGetRequest<List<ActivityType>>(UrlEventTypes,
                "Error while getting event types");
        }

        /// <inheritdoc />
        /// <summary>
        /// Sets the type of the activity.
        /// </summary>
        /// <param name="activityId">The activity identifier.</param>
        /// <param name="activityType">Type of the activity.</param>
        /// <returns>
        /// The task
        /// </returns>
        public async Task SetActivityType(long activityId, ActivityType activityType)
        {
            var url = $"{URL_ACTIVITY_BASE}/{activityId}";

            httpClient.DefaultRequestHeaders.Add("X-HTTP-Method-Override", "PUT");

            var data = new
            {
                activityId,
                activityTypeDTO = activityType
            };

            var res = await httpClient.PostAsync(url,
                new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json"));

            if (!res.IsSuccessStatusCode)
            {
                throw new Exception($"Activity type not set: {await res.Content.ReadAsStringAsync()}");
            }
        }

        /// <summary>
        /// Sets the type of the event.
        /// </summary>
        /// <param name="activityId">The activity identifier.</param>
        /// <param name="eventType">Type of the event.</param>
        /// <returns></returns>
        public async Task SetEventType(long activityId, ActivityType eventType)
        {
            var url = $"{URL_ACTIVITY_BASE}/{activityId}";

            httpClient.DefaultRequestHeaders.Add("X-HTTP-Method-Override", "PUT");

            var data = new
            {
                activityId,
                eventTypeDTO = eventType
            };

            var res = await httpClient.PostAsync(url,
                new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json"));

            if (!res.IsSuccessStatusCode)
            {
                throw new Exception($"Event type not set: {await res.Content.ReadAsStringAsync()}");
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// Sets the activity description.
        /// </summary>
        /// <param name="activityId">The activity identifier.</param>
        /// <param name="description">The description.</param>
        /// <returns>
        /// The task
        /// </returns>
        public async Task SetActivityDescription(long activityId, string description)
        {
            var url = $"{URL_ACTIVITY_BASE}/{activityId}";

            httpClient.DefaultRequestHeaders.Add("X-HTTP-Method-Override", "PUT");

            var data = new
            {
                activityId,
                description
            };

            var res = await httpClient.PostAsync(url,
                new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json"));

            if (!res.IsSuccessStatusCode)
            {
                throw new Exception($"Activity description not set: {await res.Content.ReadAsStringAsync()}");
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// Loads the activity.
        /// </summary>
        /// <param name="activityId">The activity identifier.</param>
        /// <returns>
        /// Activity
        /// </returns>
        public async Task<Activity> LoadActivity(long activityId)
        {
            var url = $"{URL_ACTIVITY_BASE}/{activityId}";

            return await ExecuteUrlGetRequest<Activity>(url, "Error while getting activity");
        }

        /// <summary>
        /// Gets the unix timestamp.
        /// </summary>
        /// <param name="date">The date.</param>
        /// <returns></returns>
        private static int GetUnixTimestamp(DateTime date)
        {
            return (int)date.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
        }

        /// <summary>
        /// Creates the activities URL.
        /// </summary>
        /// <param name="limit">The limit.</param>
        /// <param name="start">The start.</param>
        /// <param name="date">The date.</param>
        /// <returns></returns>
        private static string CreateActivitiesUrl(int limit, int start, DateTime date)
        {
            return $"{UrlActivitiesBase}?limit={limit}&start={start}&_={GetUnixTimestamp(date)}";
        }

        /// <inheritdoc />
        /// <summary>
        /// Loads the activities.
        /// </summary>
        /// <param name="limit">The limit.</param>
        /// <param name="start">The start.</param>
        /// <param name="from">From.</param>
        /// <returns>
        /// List of activities
        /// </returns>
        public async Task<List<Activity>> LoadActivities(int limit, int start, DateTime from)
        {
            var url = CreateActivitiesUrl(limit, start, from);

            return await ExecuteUrlGetRequest<List<Activity>>(url, "Error while getting activities");
        }

        private static T DeserializeData<T>(string data) where T : class
        {
            return typeof(T) == typeof(string) ? data as T : JsonConvert.DeserializeObject<T>(data);
        }

        /// <summary>
        /// Executes the URL get request.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="url">The URL.</param>
        /// <param name="errorMessage">The error message.</param>
        /// <returns></returns>
        private async Task<T> ExecuteUrlGetRequest<T>(string url, string errorMessage) where T : class
        {
            var res = await httpClient.GetAsync(url);
            var data = await res.Content.ReadAsStringAsync();
            if (!res.IsSuccessStatusCode)
            {
                throw new Exception($"{errorMessage}: {data}");
            }

            return DeserializeData<T>(data);
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="Client" /> class.
        /// </summary>
        ~Client()
        {
            if (httpClient == null)
            {
                return;
            }

            httpClient.Dispose();
            httpClient = null;
        }
    }
}
