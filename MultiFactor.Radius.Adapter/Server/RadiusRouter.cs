//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server.FirstAuthFactorProcessing;
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

        public async Task HandleRequest(PendingRequest request, ClientConfiguration clientConfig)
        {
            try
            {
                if (request.RequestPacket.Code == PacketCode.StatusServer)
                {
                    //status
                    var uptime = (DateTime.Now - _startedAt);
                    request.ReplyMessage = $"Server up {uptime.Days} days {uptime:hh\\:mm\\:ss}";
                    request.ResponseCode = PacketCode.AccessAccept;
                    CreateAndSendRadiusResponse(request);
                    return;
                }

                if (request.RequestPacket.Code != PacketCode.AccessRequest)
                {
                    _logger.Warning("Unprocessable packet type: {code}", request.RequestPacket.Code);
                    return;
                }

                ProcessUserNameTransformRules(request, clientConfig);

                var passwordChangeStatusCode = _passwordChangeHandler.TryContinuePasswordChallenge(request, clientConfig);
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
                        request.ResponseCode = await ProcessChallenge(request, clientConfig, receivedState);
                        request.State = receivedState;  //state for Access-Challenge message if otp is wrong (3 times allowed)

                        CreateAndSendRadiusResponse(request);
                        return; //stop authentication process after otp code verification
                    }
                }

                var firstAuthFactorProcessor = _firstAuthFactorProcessorProvider.GetProcessor(clientConfig.FirstFactorAuthenticationSource);
                var firstFactorAuthenticationResultCode = await firstAuthFactorProcessor.ProcessFirstAuthFactorAsync(request, clientConfig);
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
                        request.MustChangePassword = true;
                        request.ResponseCode = _passwordChangeHandler.TryCreatePasswordChallenge(request, clientConfig);
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

                if (request.Bypass2Fa)
                {
                    //second factor not required
                    var userName = request.UserName;
                    _logger.Information("Bypass second factor for user '{user:l}' from {host:l}:{port}",
                        userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);

                    request.ResponseCode = PacketCode.AccessAccept;
                    CreateAndSendRadiusResponse(request);

                    //stop authencation process
                    return;
                }

                request.ResponseCode = await ProcessSecondAuthenticationFactor(request, clientConfig);
                if (request.ResponseCode == PacketCode.AccessChallenge)
                {
                    AddStateChallengePendingRequest(request.State, request);
                }

                CreateAndSendRadiusResponse(request);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Request handling error: {msg:l}", ex.Message);
            }
        }

        private void ProcessUserNameTransformRules(PendingRequest request, ClientConfiguration clientConfig)
        {
            var userName = request.UserName;
            if (string.IsNullOrEmpty(userName)) return;

            foreach (var rule in clientConfig.UserNameTransformRules)
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

            request.UserName = userName;
        }

        /// <summary>
        /// Authenticate request at MultiFactor with user-name only
        /// </summary>
        private async Task<PacketCode> ProcessSecondAuthenticationFactor(PendingRequest request, ClientConfiguration clientConfig)
        {
            var userName = request.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return PacketCode.AccessReject;
            }

            if (request.RequestPacket.IsVendorAclRequest == true)
            {
                //security check
                if (clientConfig.FirstFactorAuthenticationSource == AuthenticationSource.Radius)
                {
                    _logger.Information("Bypass second factor for user '{user:l}' from {host:l}:{port}", userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                    return PacketCode.AccessAccept;
                }
            }

            var response = await _multifactorApiClient.CreateSecondFactorRequest(request, clientConfig);

            return response;
        }

        /// <summary>
        /// Verify one time password from user input
        /// </summary>
        private async Task<PacketCode> ProcessChallenge(PendingRequest request, ClientConfiguration clientConfig, string state)
        {
            var userName = request.UserName;

            if (string.IsNullOrEmpty(userName))
            {
                _logger.Warning("Can't find User-Name in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
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
                        _logger.Warning("Can't find User-Password with user response in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        return PacketCode.AccessReject;
                    }

                    break;
                case AuthenticationType.MSCHAP2:
                    var msChapResponse = request.RequestPacket.GetAttribute<byte[]>("MS-CHAP2-Response");

                    if (msChapResponse == null)
                    {
                        _logger.Warning("Can't find MS-CHAP2-Response in message id={id} from {host:l}:{port}", request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                        return PacketCode.AccessReject;
                    }

                    //forti behaviour
                    var otpData = msChapResponse.Skip(2).Take(6).ToArray();
                    userAnswer = Encoding.ASCII.GetString(otpData);

                    break;
                default:
                    _logger.Warning("Unable to process {auth} challange in message id={id} from {host:l}:{port}", request.RequestPacket.AuthenticationType, request.RequestPacket.Identifier, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                    return PacketCode.AccessReject;
            }

            var stateChallengePendingRequest = GetStateChallengeRequest(state);
            request.TwoFAIdentityAttribyte = stateChallengePendingRequest.GetSecondFactorIdentity(clientConfig);
            response = await _multifactorApiClient.Challenge(request, clientConfig, userAnswer, state);

            switch (response)
            {
                case PacketCode.AccessAccept:
                    if (stateChallengePendingRequest != null)
                    {
                        request.UserGroups = stateChallengePendingRequest.UserGroups;
                        request.ResponsePacket = stateChallengePendingRequest.ResponsePacket;
                        request.LdapAttrs = stateChallengePendingRequest.LdapAttrs;
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
                _logger.Error("Unable to cache request id={id}", request.RequestPacket.Identifier);
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