// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
//using Newtonsoft.Json;
//using Newtonsoft.Json.Linq;
using Xunit;
using System.Text.Json.Nodes;

namespace IdentityServer.IntegrationTests.Clients
{
    public class CustomTokenResponseClients
    {
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;

        public CustomTokenResponseClients()
        {
            var builder = new WebHostBuilder()
                .UseStartup<StartupWithCustomTokenResponses>();
            var server = new TestServer(builder);

            _client = server.CreateClient();
        }

        [Fact]
        public async Task Resource_owner_success_should_return_custom_response()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                UserName = "bob",
                Password = "bob",
                Scope = "api1"
            });

            // raw fields
            var fields = GetFields(response);
            Assert.Equal("some_string", fields.TryGetString("string_value"));
            Assert.Equal(42, fields.TryGetValue("int_value").GetInt64());
            //((Int64)fields["int_value"]).Should().Be(42);

            Assert.Null(fields.TryGetString("identity_token"));
            Assert.Null(fields.TryGetString("refresh_token"));
            Assert.Null(fields.TryGetString("error"));
            Assert.Null(fields.TryGetString("error_description"));
            Assert.NotNull(fields.TryGetString("token_type"));
            Assert.True(fields.TryGetValue("expires_in").TryGetInt64(out var _));

            var responseObject = fields.TryGetValue("dto");
            responseObject.ValueKind.Should().Be(JsonValueKind.Object);

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(false);
            response.ExpiresIn.Should().Be(3600);
            response.TokenType.Should().Be("Bearer");
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            

            // token content
            var payload = GetPayload(response);
            payload.EnumerateObject().ToArray().Length.Should().Be(12);
            Assert.Equal("https://idsvr4", payload.TryGetString("iss"));
            Assert.Equal("roclient", payload.TryGetString("client_id"));
            Assert.Equal("bob", payload.TryGetString("sub"));
            Assert.Equal("local", payload.TryGetString("idp"));
            Assert.Equal("api", payload.TryGetString("aud"));

            var scopes = payload.TryGetValue("scope").EnumerateArray();
            scopes.First().ToString().Should().Be("api1");

            var amr = payload.TryGetValue("amr").EnumerateArray();
            amr.Count().Should().Be(1);
            amr.First().ToString().Should().Be("password");
        }

        [Fact]
        public async Task Resource_owner_failure_should_return_custom_error_response()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                UserName = "bob",
                Password = "invalid",
                Scope = "api1"
            });

            // raw fields
            var fields = GetFields(response);
            Assert.Equal("some_string", fields.TryGetString("string_value"));
            Assert.Equal(42, fields.TryGetValue("int_value").GetInt64());
            //((Int64)fields["int_value"]).Should().Be(42);

            Assert.Null(fields.TryGetString("identity_token"));
            Assert.Null(fields.TryGetString("refresh_token"));
            Assert.Null(fields.TryGetString("error"));
            Assert.Null(fields.TryGetString("error_description"));
            Assert.NotNull(fields.TryGetString("token_type"));
            Assert.True(fields.TryGetValue("expires_in").TryGetInt64(out var _));

            var responseObject = fields.TryGetValue("dto");
            responseObject.ValueKind.Should().Be(JsonValueKind.Object);

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(true);
            response.Error.Should().Be("invalid_grant");
            response.ErrorDescription.Should().Be("invalid_credential");
            response.ExpiresIn.Should().Be(0);
            response.TokenType.Should().BeNull();
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
        }

        [Fact]
        public async Task Extension_grant_success_should_return_custom_response()
        {
            var response = await _client.RequestTokenAsync(new TokenRequest
            {
                Address = TokenEndpoint,
                GrantType = "custom",

                ClientId = "client.custom",
                ClientSecret = "secret",

                Parameters =
                {
                    { "scope", "api1" },
                    { "outcome", "succeed"}
                }
            });


            // raw fields
            var fields = GetFields(response);
            Assert.Equal("some_string", fields.TryGetString("string_value"));
            Assert.Equal(42, fields.TryGetValue("int_value").GetInt64());
            //((Int64)fields["int_value"]).Should().Be(42);

            Assert.Null(fields.TryGetString("identity_token"));
            Assert.Null(fields.TryGetString("refresh_token"));
            Assert.Null(fields.TryGetString("error"));
            Assert.Null(fields.TryGetString("error_description"));
            Assert.NotNull(fields.TryGetString("token_type"));
            Assert.True(fields.TryGetValue("expires_in").TryGetInt64(out var _));

            var responseObject = fields.TryGetValue("dto");
            responseObject.ValueKind.Should().Be(JsonValueKind.Object);

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(false);
            response.ExpiresIn.Should().Be(3600);
            response.TokenType.Should().Be("Bearer");
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();


            // token content
            var payload = GetPayload(response);
            payload.EnumerateObject().ToArray().Length.Should().Be(12);
            Assert.Equal("https://idsvr4", payload.TryGetString("iss"));
            Assert.Equal("client.custom", payload.TryGetString("client_id"));
            Assert.Equal("bob", payload.TryGetString("sub"));
            Assert.Equal("local", payload.TryGetString("idp"));
            Assert.Equal("api", payload.TryGetString("aud"));

            var scopes = payload.TryGetValue("scope").EnumerateArray();
            scopes.First().ToString().Should().Be("api1");

            var amr = payload.TryGetValue("amr").EnumerateArray();
            amr.Count().Should().Be(1);
            amr.First().ToString().Should().Be("custom");

            //payload.Count().Should().Be(12);
            //payload.Should().Contain("iss", "https://idsvr4");
            //payload.Should().Contain("client_id", "client.custom");
            //payload.Should().Contain("sub", "bob");
            //payload.Should().Contain("idp", "local");

            //payload["aud"].Should().Be("api");

            //var scopes = payload["scope"] as JsonObject;
            //scopes.First().ToString().Should().Be("api1");

            //var amr = payload["amr"] as JsonArray;
            //amr.Count().Should().Be(1);
            //amr.First().ToString().Should().Be("custom");

        }

        [Fact]
        public async Task Extension_grant_failure_should_return_custom_error_response()
        {
            var response = await _client.RequestTokenAsync(new TokenRequest
            {
                Address = TokenEndpoint,
                GrantType = "custom",

                ClientId = "client.custom",
                ClientSecret = "secret",

                Parameters =
                {
                    { "scope", "api1" },
                    { "outcome", "fail"}
                }
            });


            // raw fields
            var fields = GetFields(response);
            Assert.Equal("some_string", fields.TryGetString("string_value"));
            Assert.Equal(42, fields.TryGetValue("int_value").GetInt64());
            //((Int64)fields["int_value"]).Should().Be(42);

            Assert.Null(fields.TryGetString("identity_token"));
            Assert.Null(fields.TryGetString("refresh_token"));
            Assert.Null(fields.TryGetString("error"));
            Assert.Null(fields.TryGetString("error_description"));
            Assert.NotNull(fields.TryGetString("token_type"));
            Assert.True(fields.TryGetValue("expires_in").TryGetInt64(out var _));

            var responseObject = fields.TryGetValue("dto");
            responseObject.ValueKind.Should().Be(JsonValueKind.Object);

            var responseDto = GetDto(responseObject);
            var dto = CustomResponseDto.Create;

            responseDto.string_value.Should().Be(dto.string_value);
            responseDto.int_value.Should().Be(dto.int_value);
            responseDto.nested.string_value.Should().Be(dto.nested.string_value);
            responseDto.nested.int_value.Should().Be(dto.nested.int_value);


            // token client response
            response.IsError.Should().Be(true);
            response.Error.Should().Be("invalid_grant");
            response.ErrorDescription.Should().Be("invalid_credential");
            response.ExpiresIn.Should().Be(0);
            response.TokenType.Should().BeNull();
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
        }

        private CustomResponseDto GetDto(JsonElement responseObject)
        {
            return JsonSerializer.Deserialize<CustomResponseDto>(responseObject.ToString());
        }

        private JsonElement GetFields(TokenResponse response)
        {
            return response.Json;
        }

        private JsonElement GetPayload(TokenResponse response)
        {
            var token = response.AccessToken.Split('.').Skip(1).Take(1).First();
            var dictionary = JsonSerializer.Deserialize<JsonElement>(Encoding.UTF8.GetString(Base64Url.Decode(token)));

            return dictionary;
        }
    }
}