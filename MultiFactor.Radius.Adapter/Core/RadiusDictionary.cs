//MIT License

//Copyright(c) 2017 Verner Fortelius

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Core
{
    public class RadiusDictionary : IRadiusDictionary
    {
        internal Dictionary<Byte, DictionaryAttribute> Attributes { get; set; } = new Dictionary<byte, DictionaryAttribute>();
        internal List<DictionaryVendorAttribute> VendorSpecificAttributes { get; set; } = new List<DictionaryVendorAttribute>();
        internal Dictionary<String, DictionaryAttribute> AttributeNames { get; set; } = new Dictionary<string, DictionaryAttribute>();
        
        private readonly ILogger _logger;

        /// <summary>
        /// Load the dictionary from a dictionary file
        /// </summary>        
        public RadiusDictionary(String dictionaryFilePath, ILogger logger)
        {
            _logger = logger;

            using (var sr = new StreamReader(dictionaryFilePath))
            {
                while (sr.Peek() >= 0)
                {
                    var line = sr.ReadLine();
                    if (line.StartsWith("Attribute"))
                    {
                        var lineparts = line.Split(new char[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var key = Convert.ToByte(lineparts[1]);

                        // If duplicates are encountered, the last one will prevail                        
                        if (Attributes.ContainsKey(key))
                        {
                            Attributes.Remove(key);
                        }
                        if (AttributeNames.ContainsKey(lineparts[2]))
                        {
                            AttributeNames.Remove(lineparts[2]);
                        }
                        var attributeDefinition = new DictionaryAttribute(lineparts[2], key, lineparts[3]);
                        Attributes.Add(key, attributeDefinition);
                        AttributeNames.Add(attributeDefinition.Name, attributeDefinition);
                    }

                    if (line.StartsWith("VendorSpecificAttribute"))
                    {
                        var lineparts = line.Split(new char[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var vsa = new DictionaryVendorAttribute(
                            Convert.ToUInt32(lineparts[1]),
                            lineparts[3],
                            Convert.ToUInt32(lineparts[2]),
                            lineparts[4]);

                        VendorSpecificAttributes.Add(vsa);

                        if (AttributeNames.ContainsKey(vsa.Name))
                        {
                            AttributeNames.Remove(vsa.Name);
                        }
                        AttributeNames.Add(vsa.Name, vsa);
                    }
                }

                _logger.Debug($"Parsed {Attributes.Count} attributes and {VendorSpecificAttributes.Count} vendor attributes from file");
            }
        }


        public DictionaryVendorAttribute GetVendorAttribute(uint vendorId, byte vendorCode)
        {
            return VendorSpecificAttributes.FirstOrDefault(o => o.VendorId == vendorId && o.VendorCode == vendorCode);
        }

        public DictionaryAttribute GetAttribute(byte typecode)
        {
            return Attributes[typecode];
        }

        public DictionaryAttribute GetAttribute(string name)
        {
            AttributeNames.TryGetValue(name, out var attributeType);
            return attributeType;
        }
    }
}
