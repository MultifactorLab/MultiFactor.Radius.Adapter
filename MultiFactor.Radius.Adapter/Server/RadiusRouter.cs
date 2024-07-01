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
        private readonly PasswordChangeHandler _passwordChangeHandler;
        private readonly FirstAuthFactorProcessorProvider _firstAuthFactorProcessorProvider;
        private readonly MultifactorApiAdapter _apiAdapter;
        private readonly DateTime _startedAt = DateTime.Now;
        private readonly ILogger _logger;

        public RadiusRouter(PasswordChangeHandler passwordChangeHandler,
            FirstAuthFactorProcessorProvider firstAuthFactorProcessorProvider,
            MultifactorApiAdapter apiAdapter,
            ILogger logger)
        {
            _logger = logger;
            _passwordChangeHandler = passwordChangeHandler;
            _firstAuthFactorProcessorProvider = firstAuthFactorProcessorProvider;
            _apiAdapter = apiAdapter;
        }

        public async Task HandleRequest(PendingRequest request)
        {
            try
            {
                if (request.RequestPacket.Header.Code == PacketCode.StatusServer)
                {
                    //status
                    var uptime = (DateTime.Now - _startedAt);
                    request.ReplyMessage = $"Server up {uptime.Days} days {uptime:hh\\:mm\\:ss}";
                    request.AuthenticationState.Accept();
                    request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                    CreateAndSendRadiusResponse(request);
                    return;
                }


                if (request.RequestPacket.Header.Code != PacketCode.AccessRequest)
                {
                    _logger.Warning("Unprocessable packet type: {code}", request.RequestPacket.Header.Code);
                    return;
                }

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
                        var challengeCode = await ProcessChallenge(request, receivedState);
                        if (challengeCode != PacketCode.AccessAccept)
                        {
                            request.ResponseCode = challengeCode;
                            request.State = receivedState;  //state for Access-Challenge message if challenge is wrong or in a process.
                            CreateAndSendRadiusResponse(request);
                            return;
                        }

                        // 2fa was passed
                        request.AuthenticationState.SetSecondFactor(AuthenticationCode.Accept);
                    }
                }


                if (request.AuthenticationState.SecondFactor == AuthenticationCode.Awaiting && request.Configuration.PreAuthnMode.Mode != PreAuthnMode.None)
                {
                    var processor = _firstAuthFactorProcessorProvider.GetProcessor(AuthenticationSource.None);
                    var code = await processor.ProcessFirstAuthFactorAsync(request);
                    if (code != PacketCode.AccessAccept)
                    {
                        _logger.Error("Failed to validate user profile. Unable to ask pre-auth second factor");
                        // TODO
                        request.AuthenticationState.Reject();
                        request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                        CreateAndSendRadiusResponse(request);
                        return;
                    }

                    if (request.Configuration.FirstFactorAuthenticationSource == AuthenticationSource.None)
                    {
                        request.AuthenticationState.SetFirstFactor(AuthenticationCode.Accept);
                    }

                    if (request.AuthenticationState.SecondFactor == AuthenticationCode.Bypass)
                    {
                        _logger.Information("Bypass pre-auth second factor for user '{user:l}' from {host:l}:{port}",
                            request.UserName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        // TODO
                        request.ResponseCode = PacketCode.AccessAccept;
                    }
                    else
                    {
                        switch (request.Configuration.PreAuthnMode.Mode)
                        {
                            case PreAuthnMode.Otp when request.Passphrase.Otp == null:
                                request.AuthenticationState.SetSecondFactor(AuthenticationCode.Reject);
                                request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                                _logger.Error("The pre-auth second factor was rejected: otp code is empty");
                                CreateAndSendRadiusResponse(request);
                                return;

                            case PreAuthnMode.Otp:
                            case PreAuthnMode.Push:
                            case PreAuthnMode.Telegram: 
                                var respCode = await ProcessSecondAuthenticationFactor(request);
                                if (respCode == PacketCode.AccessChallenge)
                                {
                                    AddStateChallengePendingRequest(request.State, request);
                                    request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                                    CreateAndSendRadiusResponse(request);
                                    return;
                                }

                                if (respCode != PacketCode.AccessAccept)
                                {
                                    request.AuthenticationState.SetSecondFactor(AuthenticationCode.Reject);
                                    request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                                    _logger.Error("The pre-auth second factor was rejected");
                                    CreateAndSendRadiusResponse(request);
                                    return;
                                }

                                request.AuthenticationState.SetSecondFactor(AuthenticationCode.Accept);
                                break;

                            case PreAuthnMode.None:
                                break;

                            default:
                                throw new NotImplementedException($"Unknown pre-auth method: {request.Configuration.PreAuthnMode}");
                        }
                    }  
                }
                

                if (request.AuthenticationState.FirstFactor == AuthenticationCode.Awaiting)
                {
                    var processor = _firstAuthFactorProcessorProvider.GetProcessor(request.Configuration.FirstFactorAuthenticationSource);
                    var code = await processor.ProcessFirstAuthFactorAsync(request);
                    if (code == PacketCode.DisconnectNak)
                    {
                        RequestWillNotBeProcessed?.Invoke(this, request);
                        return;
                    }

                    if (code != PacketCode.AccessAccept)
                    {
                        //User password expired ot must be changed
                        if (request.MustChangePassword)
                        {
                            _passwordChangeHandler.CreatePasswordChallenge(request);
                            _logger.Information("CreatePasswordChallengeState: {State:l}", request.State);
                            CreateAndSendRadiusResponse(request);
                            return;
                        }

                        //first factor authentication rejected
                        request.AuthenticationState.SetFirstFactor(AuthenticationCode.Reject);
                        request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                        CreateAndSendRadiusResponse(request);
                        return;
                    }

                    request.AuthenticationState.SetFirstFactor(AuthenticationCode.Accept);
                }


                if (request.AuthenticationState.SecondFactor == AuthenticationCode.Bypass)
                {
                    //second factor not required
                    _logger.Information("Bypass second factor for user '{user:l}' from {host:l}:{port}",
                        request.UserName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);

                    request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                    CreateAndSendRadiusResponse(request);
                    return;
                }


                if (request.AuthenticationState.SecondFactor == AuthenticationCode.Awaiting)
                {
                    var code = await ProcessSecondAuthenticationFactor(request);
                    
                    if (code == PacketCode.AccessChallenge) 
                    {
                        request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                        AddStateChallengePendingRequest(request.State, request);
                        CreateAndSendRadiusResponse(request);
                        return;
                    }

                    if (code == PacketCode.AccessAccept)
                    {
                        _logger.Information("Second factor accepted for user '{user:l}' from {host:l}:{port}",
                            request.UserName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        request.AuthenticationState.SetSecondFactor(AuthenticationCode.Accept);
                        request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                        CreateAndSendRadiusResponse(request);
                        return;
                    }

                    if (code == PacketCode.AccessReject)
                    {
                        _logger.Information("Second factor rejected for user '{user:l}' from {host:l}:{port}",
                            request.UserName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        request.AuthenticationState.SetSecondFactor(AuthenticationCode.Reject);
                        request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
                        CreateAndSendRadiusResponse(request);
                        return;
                    }
                }

                request.ResponseCode = request.AuthenticationState.GetResultPacketCode();
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
            if (string.IsNullOrEmpty(request.UserName))
            {
                _logger.Warning("Unable to process 2FA authentication for message id={id} from {host:l}:{port}: Can't find User-Name", 
                    request.RequestPacket.Header.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            if (request.RequestPacket.IsVendorAclRequest == true)
            {
                //security check
                if (request.Configuration.FirstFactorAuthenticationSource == AuthenticationSource.Radius)
                {
                    _logger.Information("Bypass second factor for user '{user:l}' from {host:l}:{port}", 
                        request.UserName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                    return PacketCode.AccessAccept;
                }
            }

            var response = await _apiAdapter.CreateSecondFactorRequestAsync(request);
            request.State = response.ChallengeState;
            request.ReplyMessage = response.ReplyMessage;

            return response.Code;
        }

        /// <summary>
        /// Verify one time password from user input
        /// </summary>
        private async Task<PacketCode> ProcessChallenge(PendingRequest request, string state)
        {
            _logger.Information("Processing challenge {State:l} for message id={id} from {host:l}:{port}",
                state, request.RequestPacket.Header.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);

            if (string.IsNullOrEmpty(request.UserName))
            {
                _logger.Warning("Unable to process challenge {State:l} for message id={id} from {host:l}:{port}: Can't find User-Name", 
                    state, request.RequestPacket.Header.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }
        
            string userAnswer;
            switch (request.RequestPacket.AuthenticationType)
            {
                case AuthenticationType.PAP:
                    //user-password attribute holds second request challenge from user
                    userAnswer = request.Passphrase.Raw;

                    if (string.IsNullOrEmpty(userAnswer))
                    {
                        _logger.Warning("Unable to process challenge {State:l} for message id={id} from {host:l}:{port}: Can't find User-Password with user response",
                            state, request.RequestPacket.Header.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        return PacketCode.AccessReject;
                    }

                    break;
                case AuthenticationType.MSCHAP2:
                    var msChapResponse = request.RequestPacket.GetAttribute<byte[]>("MS-CHAP2-Response");

                    if (msChapResponse == null)
                    {
                        _logger.Warning("Unable to process challenge {State:l} for message id={id} from {host:l}:{port}: Can't find MS-CHAP2-Response",
                            state, request.RequestPacket.Header.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        return PacketCode.AccessReject;
                    }

                    //forti behaviour
                    var otpData = msChapResponse.Skip(2).Take(6).ToArray();
                    userAnswer = Encoding.ASCII.GetString(otpData);

                    break;
                default:
                    _logger.Warning("Unable to process challenge {State:l} for message id={id} from {host:l}:{port}: Unsupported authentication type '{Auth}'", 
                        state, request.RequestPacket.Header.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, request.RequestPacket.AuthenticationType);
                    return PacketCode.AccessReject;
            }

            var stateChallengePendingRequest = GetStateChallengeRequest(state);
            if (stateChallengePendingRequest != null && request.Configuration.UseIdentityAttribute)
            {
                Update2FaIdentityAttribute(request, stateChallengePendingRequest);
            }

            var response = await _apiAdapter.ChallengeAsync(request, userAnswer, state);
            request.ReplyMessage = response.ReplyMessage;
            switch (response.Code)
            {
                case PacketCode.AccessAccept:
                    if (stateChallengePendingRequest != null)
                    {
                        request.UpdateFromChallengeRequest(stateChallengePendingRequest);
                    }
                    RemoveStateChallengeRequest(state);
                    _logger.Debug("Challenge {State:l} was processed for message id={id} from {host:l}:{port} with result '{Result}'",
                        state, request.RequestPacket.Header.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, response.Code);
                    break;

                case PacketCode.AccessReject:
                    RemoveStateChallengeRequest(state);
                    _logger.Debug("Challenge {State:l} was processed for message id={id} from {host:l}:{port} with result '{Result}'",
                        state, request.RequestPacket.Header.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, response.Code);
                    break;
            }

            return response.Code;
        }

        private static void Update2FaIdentityAttribute(PendingRequest request, PendingRequest stateChallengePendingRequest)
        {
            var existedAttributes = new LdapAttributes(request.Profile.LdapAttrs);
            existedAttributes.Replace(request.Configuration.TwoFAIdentityAttribyte, new[] { stateChallengePendingRequest.SecondFactorIdentity });
            request.Profile.UpdateAttributes(existedAttributes);
        }

        private void CreateAndSendRadiusResponse(PendingRequest request) => RequestProcessed?.Invoke(this, request);

        /// <summary>
        /// Add authenticated request to local cache for otp/challenge
        /// </summary>
        private void AddStateChallengePendingRequest(string state, PendingRequest request)
        {
            if (!_stateChallengePendingRequests.TryAdd(state, request))
            {
                _logger.Error("Unable to cache request id={id}", request.RequestPacket.Header.Identifier);
            }
            else
            {
                _logger.Information("Challenge {State:l} was added for message id={id}", state, request.RequestPacket.Header.Identifier);
            }
        }

        /// <summary>
        /// Get authenticated request from local cache for otp/challenge
        /// </summary>
        private PendingRequest GetStateChallengeRequest(string state)
        {
            if (_stateChallengePendingRequests.TryGetValue(state, out PendingRequest request))
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