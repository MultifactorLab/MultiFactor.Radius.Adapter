﻿using MultiFactor.Radius.Adapter.Configuration;
using MultiFactor.Radius.Adapter.Core;
using MultiFactor.Radius.Adapter.Services;
using MultiFactor.Radius.Adapter.Services.ActiveDirectory;
using System;
using System.Collections.Generic;

namespace MultiFactor.Radius.Adapter.Server
{
    //Changing the password consists of three stages:
    //1. Сreating a challenge (make user to enter a new password)
    //2. Re-entering the password to confirm and verify that these passwords match and also meet security requirements
    //3. Сhanging the password in LDAP
    public class PasswordChangeHandler
    {
        private readonly CacheService _cache;

        private readonly DataProtectionService _dataProtectionService;
        private readonly IDictionary<string, ActiveDirectoryService> _activeDirectoryServices;

        public PasswordChangeHandler(CacheService cache, IDictionary<string, ActiveDirectoryService> activeDirectoryServices)
        {
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
            _activeDirectoryServices = activeDirectoryServices ?? throw new ArgumentNullException(nameof(activeDirectoryServices));

            _dataProtectionService = new DataProtectionService();
        }

        /// <summary>
        /// Make user repeat password or try finalize password change flow and change password in AD.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <remarks>Step 2 and 3 of password change flow.</remarks>
        public PacketCode TryContinuePasswordChallenge(PendingRequest request, ClientConfiguration clientConfig)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            var passwordChangeRequest = _cache.GetPasswordChangeRequest(request.RequestPacket.State);
            if (passwordChangeRequest == null)
            {
                return PacketCode.AccessAccept; //not a password change request, continue authentication
            }

            var newPassword = request.RequestPacket.TryGetUserPassword();
            if (string.IsNullOrEmpty(newPassword))
            {
                return PacketCode.AccessReject; //some error
            }

            if (passwordChangeRequest.NewPasswordEncryptedData != null)
            {
                //re-entered new password
                var decryptedNewPassword = _dataProtectionService.Unprotect(clientConfig, passwordChangeRequest.NewPasswordEncryptedData);
                if (decryptedNewPassword != newPassword)
                {
                    return PasswordsNotMatchChallenge(request, passwordChangeRequest);
                }

                var currentPassword = _dataProtectionService.Unprotect(clientConfig, passwordChangeRequest.CurrentPasswordEncryptedData);
                var activeDirectoryService = _activeDirectoryServices[passwordChangeRequest.Domain];

                if (activeDirectoryService.ChangePassword(clientConfig, request.UserName, currentPassword, newPassword, out var passwordDoesNotMeetRequirements))
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

        /// <summary>
        /// Set request state and response code to initialize password change challenge.
        /// </summary>
        /// <returns>AccessChallenge packet code if user must change password; AccessAccept otherwise</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public PacketCode TryCreatePasswordChallenge(PendingRequest request, ClientConfiguration clientConfig)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            if (!request.MustChangePassword)
            {
                return PacketCode.AccessAccept; //not a password change request, continue authentication
            }
            var passwordChangeRequest = new PasswordChangeRequest
            {
                Domain = request.MustChangePasswordDomain,
                CurrentPasswordEncryptedData = _dataProtectionService.Protect(clientConfig, request.RequestPacket.TryGetUserPassword())
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
            passwordChangeRequest.NewPasswordEncryptedData = _dataProtectionService.Protect(clientConfig, request.RequestPacket.TryGetUserPassword());

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