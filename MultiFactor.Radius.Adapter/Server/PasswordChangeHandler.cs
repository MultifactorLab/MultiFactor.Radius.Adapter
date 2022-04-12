using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services;
using MultiFactor.Radius.Adapter.Services.Ldap;
using System;
using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Server
{
    public class PasswordChangeHandler
    {
        private CacheService _cache;

        private DataProtectionService _dataProtectionService;
        private IDictionary<string, ActiveDirectoryService> _activeDirectoryServices;

        public PasswordChangeHandler(CacheService cache, IDictionary<string, ActiveDirectoryService> activeDirectoryServices)
        {
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
            _activeDirectoryServices = activeDirectoryServices ?? throw new ArgumentNullException(nameof(activeDirectoryServices));

            _dataProtectionService = new DataProtectionService();
        }

        public PacketCode HandleRequest(PendingRequest request, ClientConfiguration clientConfig)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            if (request.MustChangePassword)
            {
                return CreatePasswordChallenge(request, clientConfig);
            }

            var passwordChangeRequest = _cache.GetPasswordChangeRequest(request.RequestPacket.State);
            if (passwordChangeRequest == null)
            {
                return PacketCode.AccessAccept; //not a password change request, continue authentication
            }

            var newPassword = request.RequestPacket.UserPassword;
            if (string.IsNullOrEmpty(newPassword))
            {
                return PacketCode.AccessReject; //some error
            }

            if (passwordChangeRequest.NewPasswordEncryptedData != null)
            {
                //re-entered new password
                var newPassword1 = _dataProtectionService.Unprotect(clientConfig, passwordChangeRequest.NewPasswordEncryptedData);
                if (newPassword1 != newPassword)
                {
                    return PasswordsNotMatchChallenge(request, passwordChangeRequest);
                }

                var currentPassword = _dataProtectionService.Unprotect(clientConfig, passwordChangeRequest.CurrentPasswordEncryptedData);
                var activeDirectoryService = _activeDirectoryServices[passwordChangeRequest.Domain];

                if (activeDirectoryService.ChangePassword(clientConfig, request.RequestPacket.UserName, currentPassword, newPassword, out var passwordDoesNotMeetRequirements))
                {
                    _cache.Remove(request.RequestPacket.State);
                    return PacketCode.AccessAccept;
                }

                if (passwordDoesNotMeetRequirements)
                {
                    return PasswordDoesNotMeetRequirementsChallenge(request, passwordChangeRequest);
                }

                //some AD error
                return PacketCode.AccessReject;
            }

            return RepeatPasswordChallenge(request, clientConfig, passwordChangeRequest);
        }

        private PacketCode CreatePasswordChallenge(PendingRequest request, ClientConfiguration clientConfig)
        {
            var passwordChangeRequest = new PasswordChangeRequest
            {
                Domain = request.MustChangePasswordDomain,
                CurrentPasswordEncryptedData = _dataProtectionService.Protect(clientConfig, request.RequestPacket.UserPassword)
            };
            _cache.RegisterPasswordChangeRequest(passwordChangeRequest);

            request.State = passwordChangeRequest.Id;
            request.ReplyMessage = "Please change password to continue. Enter new password: ";
            return PacketCode.AccessChallenge;
        }

        private PacketCode PasswordsNotMatchChallenge(PendingRequest request, PasswordChangeRequest passwordChangeRequest)
        {
            passwordChangeRequest.NewPasswordEncryptedData = null;

            _cache.RegisterPasswordChangeRequest(passwordChangeRequest);

            request.State = passwordChangeRequest.Id;
            request.ReplyMessage = "Passwords not match. Please enter new password: ";
            return PacketCode.AccessChallenge;
        }

        private PacketCode RepeatPasswordChallenge(PendingRequest request, ClientConfiguration clientConfig, PasswordChangeRequest passwordChangeRequest)
        {
            passwordChangeRequest.NewPasswordEncryptedData = _dataProtectionService.Protect(clientConfig, request.RequestPacket.UserPassword);

            _cache.RegisterPasswordChangeRequest(passwordChangeRequest);

            request.State = passwordChangeRequest.Id;
            request.ReplyMessage = "Please repeat new password: ";
            return PacketCode.AccessChallenge;
        }

        private PacketCode PasswordDoesNotMeetRequirementsChallenge(PendingRequest request, PasswordChangeRequest passwordChangeRequest)
        {
            passwordChangeRequest.NewPasswordEncryptedData = null;

            _cache.RegisterPasswordChangeRequest(passwordChangeRequest);

            request.State = passwordChangeRequest.Id;
            request.ReplyMessage = "New password is not complex enough. Please enter new password: ";
            return PacketCode.AccessChallenge;
        }
    }
}