//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;

namespace MultiFactor.Radius.Adapter.Server
{
    public class AuthenticationState
    {
        public AuthenticationCode FirstFactor { get; private set; } = AuthenticationCode.Awaiting;
        public AuthenticationCode SecondFactor { get; private set; } = AuthenticationCode.Awaiting;

        public void SetFirstFactor(AuthenticationCode code)
        {
            FirstFactor = code;
        }

        public void SetSecondFactor(AuthenticationCode code)
        {
            SecondFactor = code;
        }

        public PacketCode GetResultPacketCode()
        {
            if ((FirstFactor == AuthenticationCode.Accept || FirstFactor == AuthenticationCode.Bypass) && (SecondFactor == AuthenticationCode.Accept || SecondFactor == AuthenticationCode.Bypass))
            {
                return PacketCode.AccessAccept;
            }

            if (FirstFactor == AuthenticationCode.Reject || SecondFactor == AuthenticationCode.Reject)
            {
                return PacketCode.AccessReject;
            }

            return PacketCode.AccessChallenge;
        }

        public void Accept()
        {
            FirstFactor = AuthenticationCode.Accept;
            SecondFactor = AuthenticationCode.Accept;
        }
        
        public void Reject()
        {
            FirstFactor = AuthenticationCode.Reject;
            SecondFactor = AuthenticationCode.Reject;
        }
    }
}