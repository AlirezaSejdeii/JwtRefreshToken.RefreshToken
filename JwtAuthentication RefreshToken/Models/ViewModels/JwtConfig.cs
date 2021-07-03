using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtAuthentication.Models.ViewModels
{
    public class JwtConfig
    {
        public string Secret { get; set; }
        public string EncryptionKey { get; set; }
        public int ExpiryTimeFrame { get; set; }
    }
}
