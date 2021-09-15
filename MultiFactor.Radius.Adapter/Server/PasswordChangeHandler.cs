using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services;
using MultiFactor.Radius.Adapter.Services.Ldap;
using System;

namespace MultiFactor.Radius.Adapter.Server
{
    public class PasswordChangeHandler
    {
        private CacheService _cache;
        private Configuration _configuration;

        private DataProtectionService _dataProtectionService;
        private ActiveDirectoryService _activeDirectoryService;

        public PasswordChangeHandler(CacheService cache, Configuration configuration, ActiveDirectoryService activeDirectoryService)
        {
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _activeDirectoryService = activeDirectoryService ?? throw new ArgumentNullException(nameof(activeDirectoryService));

            _dataProtectionService = new DataProtectionService(_configuration);
        }

        public PacketCode HandleRequest(PendingRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            if (request.MustChangePassword)
            {
                return CreatePasswordChallenge(request);
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
                var newPassword1 = _dataProtectionService.Unprotect(passwordChangeRequest.NewPasswordEncryptedData);
                if (newPassword1 != newPassword)
                {
                    return PasswordsNotMatchChallenge(request, passwordChangeRequest);
                }

                var currentPassword = _dataProtectionService.Unprotect(passwordChangeRequest.CurrentPasswordEncryptedData);
                if (_activeDirectoryService.ChangePassword(request.RequestPacket.UserName, currentPassword, newPassword, out var passwordDoesNotMeetRequirements))
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

            return RepeatPasswordChallenge(request, passwordChangeRequest);
        }

        private PacketCode CreatePasswordChallenge(PendingRequest request)
        {
            var passwordChangeRequest = new PasswordChangeRequest
            {
                CurrentPasswordEncryptedData = _dataProtectionService.Protect(request.RequestPacket.UserPassword)
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

        private PacketCode RepeatPasswordChallenge(PendingRequest request, PasswordChangeRequest passwordChangeRequest)
        {
            passwordChangeRequest.NewPasswordEncryptedData = _dataProtectionService.Protect(request.RequestPacket.UserPassword);

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