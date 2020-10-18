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

using System.Collections.Generic;
using System.Net;

namespace MultiFactor.Radius.Adapter.Core
{
    public interface IRadiusPacket
    {
        byte Identifier
        {
            get;set;
        }
        byte[] Authenticator
        {
            get; set;
        }
        byte[] SharedSecret
        {
            get;
        }
        PacketCode Code
        {
            get;
        }
        byte[] RequestAuthenticator
        {
            get;
        }
        bool IsEapMessageChallenge { get; }
        AuthenticationType AuthenticationType { get; }
        string UserName { get; }

        IRadiusPacket CreateResponsePacket(PacketCode responseCode);

        T GetAttribute<T>(string name);
        string GetString(string name);

        void AddAttribute(string name, string value);
        void AddAttribute(string name, uint value);
        void AddAttribute(string name, IPAddress value);
        void AddAttribute(string name, byte[] value);

        void CopyTo(IRadiusPacket packet);

        IDictionary<string, List<object>> Attributes
        {
            get; set;
        }
    }
}
