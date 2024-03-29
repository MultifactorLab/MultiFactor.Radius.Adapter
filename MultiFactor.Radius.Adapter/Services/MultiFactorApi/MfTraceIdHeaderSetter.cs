﻿using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.AspNetCore.Http;
using System;

namespace MultiFactor.Radius.Adapter.Services.MultiFactorApi
{
    public class MfTraceIdHeaderSetter : DelegatingHandler
    {
        private const string _key = "mf-trace-id";
        private readonly IHttpContextAccessor _httpContextAccessor;

        public MfTraceIdHeaderSetter(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var trace = _httpContextAccessor.HttpContext?.Items["mf-trace-id"] as string;
            if (!string.IsNullOrEmpty(trace) && !request.Headers.Contains(_key))
            {
                request.Headers.Add(_key, trace);
            }
            else
            {
                request.Headers.Add(_key, $"rds-{Guid.NewGuid()}");
            }
            var resp = await base.SendAsync(request, cancellationToken);

            if (!string.IsNullOrEmpty(trace) && !resp.Headers.Contains(_key))
            {
                resp.Headers.Add(_key, trace);
            }

            return resp;
        }
    }
}