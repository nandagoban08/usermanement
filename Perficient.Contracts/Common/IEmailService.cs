

using Perficient.Entities;

namespace Perficient.Contracts.Common
{ 
    public interface IEmailService
    {
        void SendEmail(EmailMessage message);
        bool CheckEmailDomain(string userEmail, string domainPattern);
    }
}