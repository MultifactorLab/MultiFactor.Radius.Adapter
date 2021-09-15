//Copyright(c) 2020-2021 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Services.Ldap;
using Serilog;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    /// <summary>
    /// Service to interact with AD LDS service
    /// </summary>
    public class AdLdsService : ILdapService
    {
        private Configuration _configuration;
        private ILogger _logger;

        public AdLdsService(Configuration configuration, ILogger logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Verify User Name, Password and User Status against AD LDS
        /// </summary>
        public bool VerifyCredentialAndMembership(string userName, string password, PendingRequest request)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException(nameof(userName));
            }
            if (string.IsNullOrEmpty(password))
            {
                _logger.Error($"Empty password provided for user '{userName}'");
                return false;
            }

            var ldapUrl = _configuration.LdapUrl;
            var user = LdapIdentity.ParseUser(userName);
            var logonName = FormatBindDn(user, ldapUrl);

            try
            {
                _logger.Debug($"Verifying user '{logonName}' credential and status at {ldapUrl}");

                using (var connection = new LdapConnection(ldapUrl.Authority))
                {
                    connection.Credential = new NetworkCredential(logonName, password);
                    connection.SessionOptions.RootDseCache = true;
                    connection.AuthType = AuthType.Basic;

                    if (ldapUrl.Scheme.ToLower() == "ldaps")
                    {
                        connection.SessionOptions.SecureSocketLayer = true;
                    }

                    connection.Bind();

                    _logger.Information($"User '{user.Name}' credential and status verified successfully at {ldapUrl}");

                    return true;
                }
            }
            catch (LdapException lex)
            {
                if (lex.ServerErrorMessage != null)
                {
                    var dataReason = ExtractErrorReason(lex.ServerErrorMessage);

                    if (dataReason != null)
                    {
                        _logger.Warning($"Verification user '{user.Name}' at {ldapUrl} failed: {dataReason}");
                        return false;
                    }
                }

                _logger.Error(lex, $"Verification user '{user.Name}' at {ldapUrl} failed: {lex.Message}");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Verification user '{user.Name}' at {ldapUrl} failed: {ex.Message}");
            }

            return false;
        }

        protected string FormatBindDn(LdapIdentity user, Uri ldapUrl)
        {
            if (user.Type == IdentityType.UserPrincipalName)
            {
                return user.Name;
            }

            if (ldapUrl.AbsolutePath != null && ldapUrl.AbsolutePath != "/")
            {
                return $"CN={user.Name},{ldapUrl.AbsolutePath.Substring(1)}";
            }

            return "CN=" + user.Name;
        }

        private SearchResponse Query(LdapConnection connection, string baseDn, string filter, SearchScope scope, params string[] attributes)
        {
            var searchRequest = new SearchRequest
                (baseDn,
                 filter,
                 scope,
                 attributes);

            var response = (SearchResponse)connection.SendRequest(searchRequest);
            return response;
        }

        private string ExtractErrorReason(string errorMessage)
        {
            var pattern = @"data ([0-9a-e]{3})";
            var match = Regex.Match(errorMessage, pattern);

            if (match.Success && match.Groups.Count == 2)
            {
                var data = match.Groups[1].Value;

                switch (data)
                {
                    case "525":
                        return "user not found";
                    case "52e":
                        return "invalid credentials";
                    case "533":
                        return "account disabled";
                }
            }

            return null;
        }
    }
}