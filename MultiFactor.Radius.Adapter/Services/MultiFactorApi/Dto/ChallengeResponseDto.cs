//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

using MultiFactor.Radius.Adapter.Core;

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi.Dto
{
    public class ChallengeResponseDto
    {
        public PacketCode Code { get; }
        public string ReplyMessage { get; }

        public ChallengeResponseDto(PacketCode code, string replyMessage = null)
        {
            Code = code;
            ReplyMessage = replyMessage;
        }
    }
}
