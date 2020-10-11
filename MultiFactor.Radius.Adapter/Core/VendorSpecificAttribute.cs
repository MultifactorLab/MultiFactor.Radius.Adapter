﻿//Copyright(c) 2020 MultiFactor
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

using System;

namespace MultiFactor.Radius.Adapter.Core
{
    public class VendorSpecificAttribute
    {
        public Byte Length;
        public UInt32 VendorId;
        public Byte VendorCode;
        public Type VendorType;
        public Byte[] Value;


        /// <summary>
        /// Create a vsa from bytes
        /// </summary>
        /// <param name="contentBytes"></param>
        public VendorSpecificAttribute(Byte[] contentBytes)
        {
            var vendorId = new Byte[4];
            Buffer.BlockCopy(contentBytes, 0, vendorId, 0, 4);
            Array.Reverse(vendorId);
            VendorId = BitConverter.ToUInt32(vendorId, 0);

            var vendorType = new Byte[1];
            Buffer.BlockCopy(contentBytes, 4, vendorType, 0, 1);
            VendorCode = vendorType[0];

            var vendorLength = new Byte[1];
            Buffer.BlockCopy(contentBytes, 5, vendorLength, 0, 1);
            Length = vendorLength[0];

            var value = new Byte[contentBytes.Length - 6];
            Buffer.BlockCopy(contentBytes, 6, value, 0, contentBytes.Length - 6);
            Value = value;
        }
    }
}
