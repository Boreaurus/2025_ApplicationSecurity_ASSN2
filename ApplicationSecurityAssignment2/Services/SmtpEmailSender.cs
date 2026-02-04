using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace ApplicationSecurityAssignment2.Services
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IConfiguration _config;
        private readonly ILogger<SmtpEmailSender> _logger;

        public SmtpEmailSender(IConfiguration config, ILogger<SmtpEmailSender> logger)
        {
            _config = config;
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var host = _config["Smtp:Host"];
            var portStr = _config["Smtp:Port"];
            var username = _config["Smtp:Username"];
            var password = _config["Smtp:Password"];
            var from = _config["Smtp:From"];
            var enableSslStr = _config["Smtp:EnableSsl"];

            if (string.IsNullOrWhiteSpace(host) ||
                string.IsNullOrWhiteSpace(portStr) ||
                string.IsNullOrWhiteSpace(username) ||
                string.IsNullOrWhiteSpace(password) ||
                string.IsNullOrWhiteSpace(from))
            {
                throw new InvalidOperationException("SMTP configuration is missing. Check Smtp:Host/Port/Username/Password/From.");
            }

            if (!int.TryParse(portStr, out var port))
                throw new InvalidOperationException("Smtp:Port must be a valid integer.");

            var enableSsl = true;
            if (!string.IsNullOrWhiteSpace(enableSslStr) && bool.TryParse(enableSslStr, out var parsedSsl))
                enableSsl = parsedSsl;

            try
            {
                using var client = new SmtpClient(host, port)
                {
                    EnableSsl = enableSsl,
                    Credentials = new NetworkCredential(username, password),
                    DeliveryMethod = SmtpDeliveryMethod.Network
                };

                using var message = new MailMessage
                {
                    From = new MailAddress(from),
                    Subject = subject,
                    Body = htmlMessage,
                    IsBodyHtml = true
                };

                message.To.Add(email);

                await client.SendMailAsync(message);
                _logger.LogInformation("SMTP email sent to {Email} with subject {Subject}", email, subject);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send SMTP email to {Email}", email);
                throw;
            }
        }
    }
}
