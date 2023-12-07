// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients;
using IdentityServer.IntegrationTests.Endpoints.Introspection.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace IdentityServer.IntegrationTests.Endpoints.Introspection
{
    public class IntrospectionTests
    {
        private const string Category = "Introspection endpoint";
        private const string IntrospectionEndpoint = "https://server/connect/introspect";
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;
        private readonly HttpMessageHandler _handler;

        public IntrospectionTests()
        {
            var builder = new WebHostBuilder()
                .UseStartup<Startup>();
            var server = new TestServer(builder);

            _handler = server.CreateHandler();
            _client = server.CreateClient();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Empty_request_should_fail()
        {
            var form = new Dictionary<string, string>();

            var response = await _client.PostAsync(IntrospectionEndpoint, new FormUrlEncodedContent(form));

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Unknown_scope_should_fail()
        {
            var form = new Dictionary<string, string>();

            _client.SetBasicAuthentication("unknown", "invalid");
            var response = await _client.PostAsync(IntrospectionEndpoint, new FormUrlEncodedContent(form));

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Invalid_scope_secret_should_fail()
        {
            var form = new Dictionary<string, string>();

            _client.SetBasicAuthentication("api1", "invalid");
            var response = await _client.PostAsync(IntrospectionEndpoint, new FormUrlEncodedContent(form));

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Missing_token_should_fail()
        {
            var form = new Dictionary<string, string>();

            _client.SetBasicAuthentication("api1", "secret");
            var response = await _client.PostAsync(IntrospectionEndpoint, new FormUrlEncodedContent(form));

            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Invalid_token_should_fail()
        {
            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = "invalid"
            });

            introspectionResponse.IsActive.Should().Be(false);
            introspectionResponse.IsError.Should().Be(false);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Invalid_Content_type_should_fail()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",
                Scope = "api1"
            });

            var data = new
            {
                client_id = "api1",
                client_secret = "secret",
                token = tokenResponse.AccessToken
            };
            var json = JsonSerializer.Serialize(data);

            var client = new HttpClient(_handler);
            var response = await client.PostAsync(IntrospectionEndpoint, new StringContent(json, Encoding.UTF8, "application/json"));
            response.StatusCode.Should().Be(HttpStatusCode.UnsupportedMediaType);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Valid_token_and_valid_scope_should_succeed()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",
                Scope = "api1"
            });

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            });

            introspectionResponse.IsActive.Should().Be(true);
            introspectionResponse.IsError.Should().Be(false);

            var scopes = from c in introspectionResponse.Claims
                         where c.Type == "scope"
                         select c;

            scopes.Count().Should().Be(1);
            scopes.First().Value.Should().Be("api1");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Response_data_should_be_valid_using_single_scope()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",
                Scope = "api1"
            });

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            });

            var values = introspectionResponse.Json;

            Assert.NotNull(values.TryGetString("aud"));
            Assert.NotNull(values.TryGetString("iss"));
            Assert.True(values.TryGetValue("exp").TryGetInt64(out var _));
            Assert.True(values.TryGetValue("nbf").TryGetInt64(out var _));
            Assert.NotNull(values.TryGetString("client_id"));
            Assert.NotNull(values.TryGetBoolean("active"));
            Assert.NotNull(values.TryGetString("scope"));

            values.TryGetString("scope").Should().Be("api1");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Response_data_with_user_authentication_should_be_valid_using_single_scope()
        {
            var tokenResponse = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "ro.client",
                ClientSecret = "secret",
                UserName = "bob",
                Password = "bob",

                Scope = "api1",
            });

            tokenResponse.IsError.Should().BeFalse();

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            });

            var values = introspectionResponse.Json;

            Assert.NotNull(values.TryGetString("aud"));
            Assert.NotNull(values.TryGetString("iss"));
            Assert.True(values.TryGetValue("exp").TryGetInt64(out var _));
            Assert.True(values.TryGetValue("nbf").TryGetInt64(out var _));
            Assert.True(values.TryGetValue("auth_time").TryGetInt64(out var _));
            Assert.NotNull(values.TryGetString("client_id"));
            Assert.NotNull(values.TryGetString("sub"));
            Assert.NotNull(values.TryGetBoolean("active"));
            Assert.NotNull(values.TryGetString("scope"));
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Response_data_should_be_valid_using_multiple_scopes_multiple_audiences()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",

                Scope = "api2 api3-a api3-b",
            });

            tokenResponse.IsError.Should().BeFalse();

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api3",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            });

            var values = introspectionResponse.Json; //.Deserialize<Dictionary<string, object>>();

            var audiences = values.TryGetStringArray("aud");

            foreach (var aud in audiences)
            {
                aud.GetType().Should().Be(typeof(string));
            }

            Assert.NotNull(values.TryGetString("iss"));
            Assert.True(values.TryGetValue("exp").TryGetInt64(out var _));
            Assert.True(values.TryGetValue("nbf").TryGetInt64(out var _));
            Assert.NotNull(values.TryGetString("client_id"));
            Assert.NotNull(values.TryGetBoolean("active"));
            Assert.NotNull(values.TryGetString("scope"));

            var scopes = values.TryGetString("scope");
            scopes.Should().Be("api3-a api3-b");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Response_data_should_be_valid_using_multiple_scopes_single_audience()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",

                Scope = "api3-a api3-b",
            });

            tokenResponse.IsError.Should().BeFalse();

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api3",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            });

            var values = introspectionResponse.Json.Deserialize<Dictionary<string, JsonElement>>();

            Assert.NotNull(values["aud"].GetString()); 
            Assert.NotNull(values["iss"].GetString());
            Assert.True(values["exp"].TryGetInt64(out var _));
            Assert.True(values["nbf"].TryGetInt64(out var _));
            Assert.NotNull(values["client_id"].GetString());
            Assert.True(values["active"].GetBoolean());
            Assert.NotNull(values["scope"].GetString());

            var scopes = values["scope"].GetString();
            scopes.Should().Be("api3-a api3-b");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Token_with_many_scopes_but_api_should_only_see_its_own_scopes()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client3",
                ClientSecret = "secret",

                Scope = "api1 api2 api3-a",
            });

            tokenResponse.IsError.Should().BeFalse();

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api3",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            });

            introspectionResponse.IsActive.Should().BeTrue();
            introspectionResponse.IsError.Should().BeFalse();

            var scopes = from c in introspectionResponse.Claims
                         where c.Type == "scope"
                         select c.Value;

            scopes.Count().Should().Be(1);
            scopes.First().Should().Be("api3-a");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Valid_token_with_valid_multiple_scopes()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",

                Scope = "api1 api2",
            });

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api1",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            });

            introspectionResponse.IsActive.Should().Be(true);
            introspectionResponse.IsError.Should().Be(false);

            var scopes = from c in introspectionResponse.Claims
                         where c.Type == "scope"
                         select c;

            scopes.Count().Should().Be(1);
            scopes.First().Value.Should().Be("api1");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Valid_token_with_invalid_scopes_should_fail()
        {
            var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "client1",
                ClientSecret = "secret",

                Scope = "api1",
            });

            var introspectionResponse = await _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = IntrospectionEndpoint,
                ClientId = "api2",
                ClientSecret = "secret",

                Token = tokenResponse.AccessToken
            });

            introspectionResponse.IsActive.Should().Be(false);
            introspectionResponse.IsError.Should().Be(false);
        }
    }
}