using System;
using System.Collections.Generic;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Services.Ldap.AttributeLoading
{
    public class LoadedAttributes
    {
        private readonly IDictionary<string, string[]> _attributes;

        public bool IsEmpty => _attributes.Count == 0;
        public static LoadedAttributes Empty => new LoadedAttributes(new Dictionary<string, string[]>());

        public LoadedAttributes(IDictionary<string, string[]> attributes)
        {
            _attributes = attributes ?? throw new ArgumentNullException(nameof(attributes));
        }

        public bool HasAttribute(string attribute)
        {
            return _attributes.Keys.Any(x => x.Equals(attribute, StringComparison.OrdinalIgnoreCase));
        }

        public IReadOnlyList<string> GetAttributeValue(string attribute)
        {
            var val = _attributes.Where(x => x.Key.Equals(attribute, StringComparison.OrdinalIgnoreCase)).ToList();
            if (val.Count == 0) throw new InvalidOperationException("Attribute not found");
            return val[0].Value.ToList().AsReadOnly();
        }
    }
}
