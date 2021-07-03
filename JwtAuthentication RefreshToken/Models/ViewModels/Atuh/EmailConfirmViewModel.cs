using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtAuthentication.Models.ViewModels.Atuh
{
    public class EmailConfirmViewModel
    {
        public string email { get; set; }
        public string token { get; set; }
    }
}
