﻿//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory.MembershipVerification;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.Ldap.LdapMetadata;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing
{
    /// <summary>
    /// Authenticate request at Remote Radius Server with user-name and password
    /// </summary>
    public class RadiusFirstAuthFactorProcessor : IFirstAuthFactorProcessor
    {
        private readonly IRadiusPacketParser _packetParser;
        private readonly ActiveDirectoryMembershipVerifier _membershipVerifier;
        private readonly ForestMetadataCache _metadataCache;
        private readonly LdapConnectionFactory _connectionFactory;
        private readonly ILogger _logger;

        public RadiusFirstAuthFactorProcessor(IRadiusPacketParser packetParser,
            ActiveDirectoryMembershipVerifier membershipVerifier,
            ForestMetadataCache metadataCache,
            LdapConnectionFactory connectionFactory,
            ILogger logger)
        {
            _packetParser = packetParser ?? throw new ArgumentNullException(nameof(packetParser));
            _membershipVerifier = membershipVerifier ?? throw new ArgumentNullException(nameof(membershipVerifier));
            _metadataCache = metadataCache ?? throw new ArgumentNullException(nameof(metadataCache));
            _connectionFactory = connectionFactory;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public AuthenticationSource AuthenticationSource => AuthenticationSource.Radius;

        public async Task<PacketCode> ProcessFirstAuthFactorAsync(PendingRequest request)
        {
            var radiusResponse = await ProcessRadiusAuthentication(request, request.Configuration);
            if (radiusResponse != PacketCode.AccessAccept)
            {
                return radiusResponse;
            }

            if (request.Configuration.CheckMembership)
            {
                // check membership without AD authentication
                var result = _membershipVerifier.VerifyMembership(request);
                var handler = new MembershipVerificationResultHandler(result);

                handler.EnrichRequest(request);
                return handler.GetDecision();
            }

            if (request.Configuration.UseIdentityAttribute)
            {
                var attrs = LoadRequiredAttributes(request, request.Configuration.TwoFAIdentityAttribyte);
                if (!attrs.ContainsKey(request.Configuration.TwoFAIdentityAttribyte))
                {
                    _logger.Warning("Attribute '{TwoFAIdentityAttribyte}' was not loaded", request.Configuration.TwoFAIdentityAttribyte);
                    return PacketCode.AccessReject;
                }

                var existedAttributes = new LdapAttributes(request.Profile.LdapAttrs);
                existedAttributes.Replace(request.Configuration.TwoFAIdentityAttribyte, new[] { attrs[request.Configuration.TwoFAIdentityAttribyte].FirstOrDefault() });
                request.Profile.UpdateAttributes(existedAttributes);
            }

            return PacketCode.AccessAccept;
        }

        public async Task<PacketCode> ProcessRadiusAuthentication(PendingRequest request, ClientConfiguration clientConfig)
        {
            try
            {
                //sending request to Remote Radius Server
                using (var client = new RadiusClient(clientConfig.ServiceClientEndpoint, _logger))
                {
                    _logger.Debug($"Sending {{code:l}} message with id={{id}} to Remote Radius Server {clientConfig.NpsServerEndpoint}", request.RequestPacket.Header.Code.ToString(), request.RequestPacket.Header.Identifier);

                    var packetCopy = (IRadiusPacket)request.RequestPacket.Clone();
                    if (request.Passphrase.Password != null)
                    {
                        packetCopy.Attributes["User-Password"] = new List<object> { request.Passphrase.Password };
                    }
                    var requestBytes = _packetParser.GetBytes(packetCopy);

                    var response = await client.SendPacketAsync(request.RequestPacket.Header.Identifier, requestBytes, clientConfig.NpsServerEndpoint, TimeSpan.FromSeconds(5));

                    if (response == null)
                    {
                        _logger.Warning("Remote Radius Server did not respond on message with id={id}", request.RequestPacket.Header.Identifier);
                        return PacketCode.DisconnectNak;
                    }
                                  
                    var responsePacket = _packetParser.Parse(response, request.RequestPacket.Header.SharedSecret, request.RequestPacket.Header.Authenticator);
                    _logger.Debug("Received {code:l} message with id={id} from Remote Radius Server", responsePacket.Header.Code.ToString(), responsePacket.Header.Identifier);

                    if (responsePacket.Header.Code == PacketCode.AccessAccept)
                    {
                        var userName = request.UserName;
                        _logger.Information($"User '{{user:l}}' credential and status verified successfully at {clientConfig.NpsServerEndpoint}", userName);
                    }

                    request.ResponsePacket = responsePacket;
                    return responsePacket.Header.Code; //Code received from NPS                 
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Radius authentication error");
            }

            return PacketCode.AccessReject; //reject by default
        }

        private Dictionary<string, string[]> LoadRequiredAttributes(PendingRequest request, params string[] attrs)
        {
            var userName = request.UserName;
            if (string.IsNullOrEmpty(userName))
            {
                throw new Exception($"Can't find User-Name in message id={request.RequestPacket.Header.Identifier} from {request.RemoteEndpoint.Address}:{request.RemoteEndpoint.Port}");
            }

            var attributes = new Dictionary<string, string[]>();
            foreach (var domain in request.Configuration.SplittedActiveDirectoryDomains)
            {
                if (attributes.Any()) break;

                var domainIdentity = LdapIdentity.FqdnToDn(domain);

                try
                {
                    var user = LdapIdentityFactory.CreateUserIdentity(request.Configuration, userName);

                    _logger.Debug($"Loading attributes for user '{{user:l}}' at {domainIdentity}", user.Name);
                    using (var connection = _connectionFactory.CreateAsCurrentProcessUser(domain))
                    {
                        connection.Bind();
                        var schema = _metadataCache.Get(
                            request.Configuration.Name,
                            domainIdentity,
                            () => new ForestSchemaLoader(request.Configuration, connection, _logger).Load(domainIdentity));

                        attributes = new ProfileLoader(schema, _logger).LoadAttributes(connection, domainIdentity, user, attrs);
                    }
                }
                catch (UserDomainNotPermittedException ex)
                {
                    _logger.Warning(ex.Message);
                }
                catch (UserNameFormatException ex)
                {
                    _logger.Warning(ex.Message);
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, $"Loading attributes of user '{{user:l}}' at {domainIdentity} failed", userName);
                    _logger.Information("Run MultiFactor.Raduis.Adapter as user with domain read permissions (basically any domain user)");
                }
            }

            return attributes;
        }
    }
}