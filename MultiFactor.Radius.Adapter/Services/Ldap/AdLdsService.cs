//Copyright(c) 2020-2021 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Server;
using Serilog;
using System;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Text.RegularExpressions;
namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    /// <summary>
    /// Service to interact with AD LDS service
    /// </summary>
    public class AdLdsService
    {
        private readonly LdapConnectionFactory _connectionFactory;
        private ILogger _logger;

        public AdLdsService(LdapConnectionFactory connectionFactory, ILogger logger)
        {
            _connectionFactory = connectionFactory;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Verify User Name, Password and User Status against AD LDS
        /// </summary>
        public bool VerifyCredentialAndMembership(PendingRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.UserName))
            {
                _logger.Error($"Empty username provided for user");
                return false;
            }
            
            if (string.IsNullOrEmpty(request.Passphrase.Password))
            {
                _logger.Error("Empty password provided for user '{User}'", request.UserName);
                return false;
            }

            var ldapUrl = request.Configuration.LdapUrl;
            var user = LdapIdentity.ParseUser(request.UserName);
            var logonName = FormatBindDn(user, ldapUrl);

            try
            {
                _logger.Debug($"Verifying user '{logonName}' credential and status at {ldapUrl}");

                using (var connection = _connectionFactory.CreateForAdlds(ldapUrl, logonName, request.Passphrase.Password, request.Configuration.LdapBindTimeout))
                {
                    var isLdaps = ldapUrl.Scheme.ToLower() == "ldaps";
                    _logger.Debug("Start bind to {Scheme}://{Server} as '{User}'", isLdaps ? "LDAPS" : "LDAP", ldapUrl.Authority, logonName);
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