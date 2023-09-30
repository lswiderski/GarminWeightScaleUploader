using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GarminConnectClient.Lib.Dto
{
    public class OAuth2Token
    {
        [JsonProperty("scope")]
        public string Scope { get; set; }

        [JsonProperty("jti")]
        public string Jti { get; set; }

        [JsonProperty("access_token")]
        public string Access_Token { get; set; }

        [JsonProperty("token_type")]
        public string Token_Type { get; set; }

        [JsonProperty("refresh_token")]
        public string Refresh_Token { get; set; }

        [JsonProperty("expires_in")]
        public long Expires_In { get; set; }

        [JsonProperty("refresh_token_expires_in")]
        public long Refresh_Token_Expires_In { get; set; }
    }
}
