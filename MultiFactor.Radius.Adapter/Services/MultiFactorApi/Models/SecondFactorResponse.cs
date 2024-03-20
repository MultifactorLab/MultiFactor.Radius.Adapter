//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md



//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md


using MultiFactor.Radius.Adapter.Core;

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi.Dto
{
    public class SecondFactorResponse
    {
        public PacketCode Code { get; }
        public string ChallengeState { get; }
        public string ReplyMessage { get; }

        public SecondFactorResponse(PacketCode code, string state = null, string replyMessage = null)
        {
            Code = code;
            ChallengeState = state;
            ReplyMessage = replyMessage;
        }
    }
}
