//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi.Dto
{
    public class ChallengeDto
    {
        public string Identity { get; set; }
        public string Challenge { get; set; }
        public string RequestId { get; set; }
    }
}
