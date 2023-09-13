using System.Collections.Generic;
using System.DirectoryServices.Protocols;

namespace MultiFactor.Radius.Adapter.Extensions
{
    public static class SearchResponseExtensions
    {
        public static List<string> GetAttributeValuesByName(this SearchResponse response, string attributeName)
        {
            var result = new List<string>();
            for (var i = 0; i < response.Entries.Count; i++)
            {
                var entry = response.Entries[i];
                var attribute = entry.Attributes[attributeName];
                if (attribute != null)
                {
                    for (var j = 0; j < attribute.Count; j++)
                    {
                        result.Add(attribute[j].ToString());
                    }
                }
            }
            return result;
        }
    }
}
