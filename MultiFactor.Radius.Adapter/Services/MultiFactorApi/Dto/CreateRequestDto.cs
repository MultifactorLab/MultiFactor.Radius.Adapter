//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi.Dto
{
    public class CreateRequestDto
    {
        public string Identity { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
        public string PassCode { get; set; }
        public string CallingStationId { get; set; }
        public string CalledStationId { get; set; }
        public CapabilitiesDto Capabilities { get; set; }
        public GroupPolicyPresetDto GroupPolicyPreset { get; set; }
    }
}
