//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Configuration.Features.PreAuthnModeFeature;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing;
using MultiFactor.Radius.Adapter.Services.Ldap;
using MultiFactor.Radius.Adapter.Services.MultiFactorApi;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Server
{
    /// <summary>
    /// Main processor
    /// </summary>
    public class RadiusRouter
    {
        public event EventHandler<PendingRequest> RequestProcessed;
        public event EventHandler<PendingRequest> RequestWillNotBeProcessed;
        private readonly ConcurrentDictionary<string, PendingRequest> _stateChallengePendingRequests = new ConcurrentDictionary<string, PendingRequest>();
        private readonly MultiFactorApiClient _multifactorApiClient;
        private readonly PasswordChangeHandler _passwordChangeHandler;
        private readonly FirstAuthFactorProcessorProvider _firstAuthFactorProcessorProvider;
        private readonly DateTime _startedAt = DateTime.Now;
        private readonly ILogger _logger;

        public RadiusRouter(
            MultiFactorApiClient multifactorApiClient,
            PasswordChangeHandler passwordChangeHandler,
            FirstAuthFactorProcessorProvider firstAuthFactorProcessorProvider,
            ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _multifactorApiClient = multifactorApiClient ?? throw new ArgumentNullException(nameof(multifactorApiClient));
            _passwordChangeHandler = passwordChangeHandler ?? throw new ArgumentNullException(nameof(passwordChangeHandler));
            _firstAuthFactorProcessorProvider = firstAuthFactorProcessorProvider ?? throw new ArgumentNullException(nameof(firstAuthFactorProcessorProvider));
        }

        public async Task HandleRequest(PendingRequest request)
        {
            try
            {
                if (request.RequestPacket.Id.Code == PacketCode.StatusServer)
                {
                    //status
                    var uptime = (DateTime.Now - _startedAt);
                    request.ReplyMessage = $"Server up {uptime.Days} days {uptime:hh\\:mm\\:ss}";
                    request.ResponseCode = PacketCode.AccessAccept;
                    CreateAndSendRadiusResponse(request);
                    return;
                }

                if (request.RequestPacket.Id.Code != PacketCode.AccessRequest)
                {
                    _logger.Warning("Unprocessable packet type: {code}", request.RequestPacket.Id.Code);
                    return;
                }

                var hs = new HashSet<string>();

                ProcessUserNameTransformRules(request);

                var passwordChangeStatusCode = _passwordChangeHandler.TryContinuePasswordChallenge(request);
                if (passwordChangeStatusCode != PacketCode.AccessAccept)
                {
                    request.ResponseCode = passwordChangeStatusCode;
                    CreateAndSendRadiusResponse(request);
                    return;
                }

                if (request.RequestPacket.State != null) //Access-Challenge response 
                {
                    var receivedState = request.RequestPacket.State;

                    if (_stateChallengePendingRequests.ContainsKey(receivedState))
                    {
                        //second request with Multifactor challenge
                        request.ResponseCode = await ProcessChallenge(request, receivedState);
                        request.State = receivedState;  //state for Access-Challenge message if otp is wrong (3 times allowed)

                        CreateAndSendRadiusResponse(request);
                        return; //stop authentication process after otp code verification
                    }
                }

                IFirstAuthFactorProcessor firstAuthFactorProcessor = null;
                var firstFactorAuthenticationResultCode = PacketCode.AccessReject;

                if (request.Configuration.PreAuthnMode.Mode != PreAuthnMode.None)
                {
                    firstAuthFactorProcessor = _firstAuthFactorProcessorProvider.GetProcessor(AuthenticationSource.None);
                    firstFactorAuthenticationResultCode = await firstAuthFactorProcessor.ProcessFirstAuthFactorAsync(request);
                    if (firstFactorAuthenticationResultCode != PacketCode.AccessAccept)
                    {
                        _logger.Error("Failed to validate user profile. Unable to ask the user for a second factor");
                        CreateAndSendRadiusResponse(request);
                        return;
                    }

                    if (request.Bypass2Fa)
                    {
                        _logger.Information("Bypass second factor for user '{user:l}' from {host:l}:{port}",
                            request.UserName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                    }
                    else
                    {
                        switch (request.Configuration.PreAuthnMode.Mode)
                        {
                            case PreAuthnMode.Otp:
                                if (request.Passphrase.Otp == null)
                                {
                                    request.ResponseCode = PacketCode.AccessReject;
                                    RequestProcessed?.Invoke(this, request);
                                    return;
                                }

                                request.ResponseCode = await ProcessSecondAuthenticationFactor(request);
                                if (request.ResponseCode != PacketCode.AccessAccept)
                                {
                                    request.ResponseCode = PacketCode.AccessReject;
                                    _logger.Error("The second factor was rejected");
                                    CreateAndSendRadiusResponse(request);
                                    return;
                                }

                                break;

                            case PreAuthnMode.None:
                                break;

                            default:
                                throw new NotImplementedException($"Unknown pre auth mode: {request.Configuration.PreAuthnMode}");
                        }
                    }  
                }
                
                var processor = _firstAuthFactorProcessorProvider.GetProcessor(request.Configuration.FirstFactorAuthenticationSource);
                // check that already was processed
                if (processor != firstAuthFactorProcessor)
                {
                    firstFactorAuthenticationResultCode = await processor.ProcessFirstAuthFactorAsync(request);
                }

                if (firstFactorAuthenticationResultCode == PacketCode.DisconnectNak)
                {
                    RequestWillNotBeProcessed?.Invoke(this, request);
                    return;
                }

                if (firstFactorAuthenticationResultCode != PacketCode.AccessAccept)
                {
                    //User password expired ot must be changed
                    if (request.MustChangePassword)
                    {
                        request.ResponseCode = _passwordChangeHandler.TryCreatePasswordChallenge(request);
                        _logger.Information($"CreatePasswordChallengeState: {request.State}");
                        CreateAndSendRadiusResponse(request);
                        return;
                    }

                    //first factor authentication rejected
                    request.ResponseCode = firstFactorAuthenticationResultCode;
                    CreateAndSendRadiusResponse(request);

                    //stop authencation process
                    return;
                }

                if (request.Configuration.PreAuthnMode.Mode == PreAuthnMode.None && request.Bypass2Fa)
                {
                    //second factor not required
                    _logger.Information("Bypass second factor for user '{user:l}' from {host:l}:{port}",
                        request.UserName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);

                    request.ResponseCode = PacketCode.AccessAccept;
                    CreateAndSendRadiusResponse(request);

                    //stop authencation process
                    return;
                }

                if (request.Configuration.PreAuthnMode.Mode == PreAuthnMode.None)
                {
                    request.ResponseCode = await ProcessSecondAuthenticationFactor(request);
                    if (request.ResponseCode == PacketCode.AccessChallenge)
                    {
                        AddStateChallengePendingRequest(request.State, request);
                    }
                }

                CreateAndSendRadiusResponse(request);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Request handling error: {msg:l}", ex.Message);
            }
        }

        private void ProcessUserNameTransformRules(PendingRequest request)
        {
            var userName = request.UserName;
            if (string.IsNullOrEmpty(userName)) return;

            foreach (var rule in request.Configuration.UserNameTransformRules)
            {
                var regex = new Regex(rule.Match, RegexOptions.IgnoreCase);
                if (rule.Count != null)
                {
                    userName = regex.Replace(userName, rule.Replace, rule.Count.Value);
                }
                else
                {
                    userName = regex.Replace(userName, rule.Replace);
                }
            }

            request.UpdateUserName(userName);
        }

        /// <summary>
        /// Authenticate request at MultiFactor with user-name only
        /// </summary>
        private async Task<PacketCode> ProcessSecondAuthenticationFactor(PendingRequest request)
        {
            var userName = request.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            if (request.RequestPacket.IsVendorAclRequest == true)
            {
                //security check
                if (request.Configuration.FirstFactorAuthenticationSource == AuthenticationSource.Radius)
                {
                    _logger.Information("Bypass second factor for user '{user:l}' from {host:l}:{port}", userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                    return PacketCode.AccessAccept;
                }
            }

            var response = await _multifactorApiClient.CreateSecondFactorRequest(request);

            return response;
        }

        /// <summary>
        /// Verify one time password from user input
        /// </summary>
        private async Task<PacketCode> ProcessChallenge(PendingRequest request, string state)
        {
            var userName = request.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            PacketCode response;
            string userAnswer;

            switch (request.RequestPacket.AuthenticationType)
            {
                case AuthenticationType.PAP:
                    //user-password attribute holds second request challenge from user
                    userAnswer = request.RequestPacket.TryGetUserPassword();

                    if (string.IsNullOrEmpty(userAnswer))
                    {
                        _logger.Warning("Can't find User-Password with user response in message id={id} from {host:l}:{port}", request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        return PacketCode.AccessReject;
                    }

                    break;
                case AuthenticationType.MSCHAP2:
                    var msChapResponse = request.RequestPacket.GetAttribute<byte[]>("MS-CHAP2-Response");

                    if (msChapResponse == null)
                    {
                        _logger.Warning("Can't find MS-CHAP2-Response in message id={id} from {host:l}:{port}", request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        return PacketCode.AccessReject;
                    }

                    //forti behaviour
                    var otpData = msChapResponse.Skip(2).Take(6).ToArray();
                    userAnswer = Encoding.ASCII.GetString(otpData);

                    break;
                default:
                    _logger.Warning("Unable to process {auth} challange in message id={id} from {host:l}:{port}", 
                        request.RequestPacket.AuthenticationType, request.RequestPacket.Id.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                    return PacketCode.AccessReject;
            }

            var stateChallengePendingRequest = GetStateChallengeRequest(state);

            if (request.Configuration.UseIdentityAttribute)
            {
                var existedAttributes = new LdapAttributes(request.Profile.LdapAttrs);
                existedAttributes.Replace(request.Configuration.TwoFAIdentityAttribyte, new[] { stateChallengePendingRequest.SecondFactorIdentity });
                request.Profile.UpdateAttributes(existedAttributes);
            }

            response = await _multifactorApiClient.Challenge(request, userAnswer, state);

            switch (response)
            {
                case PacketCode.AccessAccept:
                    if (stateChallengePendingRequest != null)
                    {
                        request.UserGroups = stateChallengePendingRequest.UserGroups;
                        request.ResponsePacket = stateChallengePendingRequest.ResponsePacket;
                        request.Profile.UpdateAttributes(stateChallengePendingRequest.Profile.LdapAttrs);
                    }
                    break;
                case PacketCode.AccessReject:
                    RemoveStateChallengeRequest(state);
                    break;
            }

            return response;
        }

        private void CreateAndSendRadiusResponse(PendingRequest request) => RequestProcessed?.Invoke(this, request);

        /// <summary>
        /// Add authenticated request to local cache for otp/challenge
        /// </summary>
        private void AddStateChallengePendingRequest(string state, PendingRequest request)
        {
            if (!_stateChallengePendingRequests.TryAdd(state, request))
            {
                _logger.Error("Unable to cache request id={id}", request.RequestPacket.Id.Identifier);
            }
        }

        /// <summary>
        /// Get authenticated request from local cache for otp/challenge
        /// </summary>
        private PendingRequest GetStateChallengeRequest(string state)
        {
            if (_stateChallengePendingRequests.TryRemove(state, out PendingRequest request))
            {
                return request;
            }

            _logger.Error("Unable to get cached request with state={state:l}", state);
            return null;
        }

        /// <summary>
        /// Remove authenticated request from local cache
        /// </summary>
        /// <param name="state"></param>
        private void RemoveStateChallengeRequest(string state)
        {
            _stateChallengePendingRequests.TryRemove(state, out PendingRequest _);
        }
    }
}