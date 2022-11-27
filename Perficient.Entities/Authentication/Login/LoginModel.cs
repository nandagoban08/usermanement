using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Perficient.Entities.Authentication.Login
{
    public class LoginModel
    {
        [Required(ErrorMessage = "UserEmail is required")]
        public string? UserEmail { get; set; }

         [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
    }
}
