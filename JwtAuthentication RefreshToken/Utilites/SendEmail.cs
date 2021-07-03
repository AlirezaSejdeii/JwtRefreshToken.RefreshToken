using MailKit.Net.Smtp;
using MimeKit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;

namespace Utilites
{
    public static class SendEmail
    {
        /// <summary>
        /// The Method For sending email to your user by your local gmail account.
        /// 
        /// before using this. go to your google account and active then
        /// https://myaccount.google.com/u/1/lesssecureapps
        /// </summary>
        /// <param name="subject">Your emial subject. show bold on email</param>
        /// <param name="body">Your email body. can be html and inline css code</param>
        /// <param name="to">Target email</param>
        /// <param name="GiveName">The name of Given name. show when email open</param>
        public static void send(string subject, string body, string to, string GiveName)
        {
            // Instantiate mimemessag
            var message = new MimeMessage();

            // From Address -- 
            message.From.Add(new MailboxAddress("YOUR BRAND NAME", "YOUR EMAIL ADDRESS"));

            // To Address --
            message.To.Add(new MailboxAddress(GiveName, to));

            // Subject  --- 
            message.Subject = subject;

            // Body -- 
            //can change TextFormat
            message.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = body
            };
            // Configure and send email
            using (var client = new MailKit.Net.Smtp.SmtpClient())
            {
                client.Connect("smtp.gmail.com", 587, false);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
            //authentication setting
                client.Authenticate("YOUR EMAIL PASSWOED", "YOUR PASSWOED");
                client.Send(message);
                client.Disconnect(true);
            }

        }
    }
}
