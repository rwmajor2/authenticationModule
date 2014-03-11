using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Web;
using log4net;


namespace AuthenticationModule
{
    class authenticate : IHttpModule
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(authenticate).Name);

        public void Dispose()
        {
            //throw new NotImplementedException();
        }

        public void Init(HttpApplication context)
        {
            context.AuthenticateRequest += new EventHandler(context_AuthenticateRequest);
            //context.EndRequest += new EventHandler(context_AuthenticateRequest);
        }

        void context_AuthenticateRequest(object sender, EventArgs e)
        {
            HttpApplication app = (HttpApplication)sender;
            HttpContext context = app.Context;
            log.Debug("***** " + app.Request.Url.OriginalString);
            if (context.Request.IsSecureConnection)
            {
                try
                {
                    X509Certificate2 cert = new X509Certificate2(context.Request.ClientCertificate.Certificate);
                    String CN = context.Request.ClientCertificate.Subject;
                    log.Debug("***** Subject CN >> " + CN);
                    if ((CN == null) || (CN.Length == 0))
                    {
                        log.Debug("     ***** Issuer " + context.Request.ClientCertificate.Issuer);
                        log.Debug("     ***** IsValid " + context.Request.ClientCertificate.IsValid);
                        log.Debug("     ***** Count " + context.Request.ClientCertificate.Count);
                        log.Debug("     ***** IsPresent " + context.Request.ClientCertificate.IsPresent);
                    }
                    if (cert != null)
                    {
                        string DN = cert.Subject;
                        string fnlUser = "";
                        foreach (X509Extension x in cert.Extensions)
                        {
                            if (x.Oid.FriendlyName.ToUpper() == "SUBJECT ALTERNATIVE NAME")
                            {
                                string stringSubjectAltName = x.Format(true).ToUpper();
                                log.Debug("     ***** Full Subject Alternative Name >> " + CN);
                                int namepos = stringSubjectAltName.LastIndexOf("NAME=");
                                string subSAN = stringSubjectAltName.Substring(namepos + 5);
                                int firstspace = subSAN.IndexOf(" ");

                                if (firstspace >= 0)
                                {
                                    fnlUser = subSAN.Substring(0, firstspace).Trim();
                                }
                                else
                                {
                                    fnlUser = subSAN.Trim();
                                }
                            }
                        }
                        if (fnlUser.Length > 0)
                        {
                            log.Debug("     *****               User authenticated >> " + fnlUser);
                            //context.User = new GenericPrincipal(new GenericIdentity(fnlUser), new string[] { "Test" });
                        }
                        else
                        {
                            log.Debug("     ***** User unathenticated due to fnlUser.length <= 0");
                            context.Response.StatusCode = 403;
                            context.Response.End();
                        }
                    }
                    else
                    {
                        log.Debug("     ***** No certificate passed with this request...");
                        context.Response.StatusCode = 403;
                        context.Response.End();
                    }
                }
                catch
                {
                    log.Debug("     ***** An error occurred...");
                    context.Response.StatusCode = 403;
                    context.Response.End();
                }
            }
            else // just kick out any non secure connections
            {
                log.Debug("     ***** Returning a 403 because unsecure connection");
                context.Response.StatusCode = 403;
                context.Response.End();
            }
        }
    }
}
