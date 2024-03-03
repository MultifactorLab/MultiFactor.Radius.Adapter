//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md


using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Configuration.Features.PreAuthnModeFeature;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Server;
using MultiFactor.Radius.Adapter.Services.MultiFactorApi.Dto;
using Serilog;
using System;
using System.Net;
using System.Threading.Tasks;

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi
{
    public class MultifactorApiAdapter
    {
        private readonly MultifactorApiClient _api;
        private readonly AuthenticatedClientCache _authenticatedClientCache;
        private readonly ILogger _logger;

        public MultifactorApiAdapter(MultifactorApiClient api, AuthenticatedClientCache authenticatedClientCache, ILogger logger)
        {
            _api = api;
            _authenticatedClientCache = authenticatedClientCache;
            _logger = logger;
        }

        public async Task<SecondFactorResponseDto> CreateSecondFactorRequestAsync(PendingRequest request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(request.SecondFactorIdentity))
            {
                _logger.Warning("Empty user name for second factor request. Request rejected.");
                return new SecondFactorResponseDto(PacketCode.AccessReject);
            }

            var userName = request.SecondFactorIdentity;
            var displayName = request.Profile.DisplayName;
            var email = request.Profile.Email;
            var userPhone = request.Profile.Phone;
            var callingStationId = request.RequestPacket.CallingStationId;

            string calledStationId = null;
            if (request.RequestPacket.IsWinLogon) //only for winlogon yet
            {
                calledStationId = request.RequestPacket.CalledStationId;
            }

            //remove user information for privacy
            switch (request.Configuration.PrivacyMode.Mode)
            {
                case PrivacyMode.Full:
                    displayName = null;
                    email = null;
                    userPhone = null;
                    callingStationId = "";
                    calledStationId = null;
                    break;

                case PrivacyMode.Partial:
                    if (!request.Configuration.PrivacyMode.HasField("Name"))
                    {
                        displayName = null;
                    }

                    if (!request.Configuration.PrivacyMode.HasField("Email"))
                    {
                        email = null;
                    }

                    if (!request.Configuration.PrivacyMode.HasField("Phone"))
                    {
                        userPhone = null;
                    }

                    if (!request.Configuration.PrivacyMode.HasField("RemoteHost"))
                    {
                        callingStationId = "";
                    }

                    calledStationId = null;

                    break;
            }

            //try to get authenticated client to bypass second factor if configured
            if (_authenticatedClientCache.TryHitCache(request.RequestPacket.CallingStationId, userName, request.Configuration))
            {
                _logger.Information("Bypass second factor for user '{name:l}' with identity attribyte '{user:l}' from {host:l}:{port}", request.UserName, userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port);
                return new SecondFactorResponseDto(PacketCode.AccessAccept);
            }

            var dto = new CreateRequestDto
            {
                Identity = userName,
                Name = displayName,
                Email = email,
                Phone = userPhone,
                PassCode = GetPassCodeOrNull(request),
                CallingStationId = callingStationId,
                CalledStationId = calledStationId,
                Capabilities = new CapabilitiesDto
                {
                    InlineEnroll = true
                },
                GroupPolicyPreset = new GroupPolicyPresetDto
                {
                    SignUpGroups = request.Configuration.SignUpGroups
                }
            };

            try
            {
                var response = await _api.CreateRequestAsync(dto, request.Configuration);
                var responseCode = ConvertToRadiusCode(response);

                if (responseCode == PacketCode.AccessAccept && !response.Bypassed)
                {
                    LogGrantedInfo(userName, response, request);
                    _authenticatedClientCache.SetCache(request.RequestPacket.CallingStationId, userName, request.Configuration);
                }

                if (responseCode == PacketCode.AccessReject)
                {
                    _logger.Warning("Second factor verification for user '{name:l}' with identity attribyte '{user:l}' from {host:l}:{port} failed with reason='{reason:l}'. User phone {phone:l}",
                        request.UserName, userName, request.RemoteEndpoint.Address, request.RemoteEndpoint.Port, response?.ReplyMessage, response?.Phone);
                }

                return new SecondFactorResponseDto(responseCode, response?.Id, response?.ReplyMessage);
            }
            catch (MultifactorApiUnreachableException apiEx)
            {
                _logger.Error("Error occured while requesting API for user '{user:l}' from {host:l}:{port}, {msg:l}",
                    userName,
                    request.RemoteEndpoint.Address,
                    request.RemoteEndpoint.Port,
                    apiEx.Message);

                if (!request.Configuration.BypassSecondFactorWhenApiUnreachable)
                {
                    var radCode = ConvertToRadiusCode(null);
                    return new SecondFactorResponseDto(radCode);
                }

                _logger.Warning("Bypass second factor for user '{user:l}' from {host:l}:{port}",
                        userName,
                        request.RemoteEndpoint.Address,
                        request.RemoteEndpoint.Port);

                var code = ConvertToRadiusCode(AccessRequestDto.Bypass);
                return new SecondFactorResponseDto(code);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error occured while requesting API for user '{user:l}' from {host:l}:{port}, {msg:l}",
                    userName,
                    request.RemoteEndpoint.Address,
                    request.RemoteEndpoint.Port,
                    ex.Message);

                var code = ConvertToRadiusCode(null);
                return new SecondFactorResponseDto(code);
            }
        }

        public async Task<ChallengeResponseDto> ChallengeAsync(PendingRequest request, string answer, string state)
        {
            var userName = request.SecondFactorIdentity;
            var dto = new ChallengeDto
            {
                Identity = userName,
                Challenge = answer,
                RequestId = state
            };

            try
            {
                var response = await _api.ChallengeAsync(dto, request.Configuration);

                var responseCode = ConvertToRadiusCode(response);
                if (responseCode == PacketCode.AccessAccept && !response.Bypassed)
                {
                    LogGrantedInfo(userName, response, request);
                    _authenticatedClientCache.SetCache(request.RequestPacket.CallingStationId, userName, request.Configuration);
                }

                return new ChallengeResponseDto(responseCode, response?.ReplyMessage);
            }
            catch (MultifactorApiUnreachableException apiEx)
            {
                _logger.Error("Error occured while requesting API for user '{user:l}' from {host:l}:{port}, {msg:l}",
                    userName,
                    request.RemoteEndpoint.Address,
                    request.RemoteEndpoint.Port,
                    apiEx.Message);

                if (!request.Configuration.BypassSecondFactorWhenApiUnreachable)
                {
                    var radCode = ConvertToRadiusCode(null);
                    return new ChallengeResponseDto(radCode);
                }

                _logger.Warning("Bypass second factor for user '{user:l}' from {host:l}:{port}",
                        userName,
                        request.RemoteEndpoint.Address,
                        request.RemoteEndpoint.Port);
                var code = ConvertToRadiusCode(AccessRequestDto.Bypass);

                return new ChallengeResponseDto(code);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error occured while requesting API for user '{user:l}' from {host:l}:{port}, {msg:l}",
                    userName,
                    request.RemoteEndpoint.Address,
                    request.RemoteEndpoint.Port,
                    ex.Message);

                var code = ConvertToRadiusCode(null);
                return new ChallengeResponseDto(code);
            }
        }

        private string GetPassCodeOrNull(PendingRequest request)
        {
            //check static challenge
            var challenge = request.RequestPacket.TryGetChallenge();
            if (challenge != null)
            {
                return challenge;
            }

            //check password challenge (otp or passcode)
            var passphrase = request.Passphrase;
            switch (request.Configuration.PreAuthnMode.Mode)
            {
                case PreAuthnMode.Otp:
                    return passphrase.Otp;

                case PreAuthnMode.Push:
                    return "m";

                case PreAuthnMode.Telegram:
                    return "t";
            }

            if (passphrase.IsEmpty)
            {
                return null;
            }

            if (request.Configuration.FirstFactorAuthenticationSource != AuthenticationSource.None)
            {
                return null;
            }

            return request.Passphrase.Otp ?? passphrase.ProviderCode;
        }

        private PacketCode ConvertToRadiusCode(AccessRequestDto multifactorAccessRequest)
        {
            if (multifactorAccessRequest == null)
            {
                return PacketCode.AccessReject;
            }

            switch (multifactorAccessRequest.Status)
            {
                case Literals.RadiusCode.Granted:     //authenticated by push
                    return PacketCode.AccessAccept;
                case Literals.RadiusCode.Denied:
                    return PacketCode.AccessReject; //access denied
                case Literals.RadiusCode.AwaitingAuthentication:
                    return PacketCode.AccessChallenge;  //otp code required
                default:
                    _logger.Warning($"Got unexpected status from API: {multifactorAccessRequest.Status}");
                    return PacketCode.AccessReject; //access denied
            }
        }

        private void LogGrantedInfo(string userName, AccessRequestDto response, PendingRequest request)
        {
            string countryValue = null;
            string regionValue = null;
            string cityValue = null;
            string callingStationId = request?.RequestPacket?.CallingStationId;

            if (response != null && IPAddress.TryParse(callingStationId, out var ip))
            {
                countryValue = response.CountryCode;
                regionValue = response.Region;
                cityValue = response.City;
                callingStationId = ip.ToString();
            }

            _logger.Information("Second factor for user '{user:l}' verified successfully. Authenticator: '{authenticator:l}', account: '{account:l}', country: '{country:l}', region: '{region:l}', city: '{city:l}', calling-station-id: {clientIp}, authenticatorId: {authenticatorId}",
                        userName,
                        response?.Authenticator,
                        response?.Account,
                        countryValue,
                        regionValue,
                        cityValue,
                        callingStationId,
                        response.AuthenticatorId);
        }
    }
}
