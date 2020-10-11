//Copyright(c) 2020 MultiFactor
//Please see licence at 
//https://github.com/MultifactorLab/MultiFactor.Radius.Adapter/blob/master/LICENSE.md

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

namespace MultiFactor.Radius.Adapter.Core
{
    public interface IRadiusDictionary
    {
        /// <summary>
        /// Get a vendor specific attribute by vendorId and vendorCode
        /// </summary>
        /// <param name="vendorId"></param>
        /// <param name="vendorCode"></param>
        /// <returns></returns>
        DictionaryVendorAttribute GetVendorAttribute(uint vendorId, byte vendorCode);


        /// <summary>
        /// Get an RFC attribute by code
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        DictionaryAttribute GetAttribute(byte code);


        /// <summary>
        /// Get an attribute or vendor attribute by name
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        DictionaryAttribute GetAttribute(string name);
    }
}