using System;
namespace MultiFactor.Radius.Adapter.Server
{
    public class PasswordChangeRequest
    {
        public string Id { get; private set; }

        public PasswordChangeRequest()
        {
            Id = Guid.NewGuid().ToString();
        }

        public string CurrentPasswordEncryptedData { get; set; }
        public string NewPasswordEncryptedData { get; set; }
    }
}
