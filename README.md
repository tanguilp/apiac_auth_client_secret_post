# APIacAuthClientSecretPost

An `APIac.Authenticator` plug for API authentication using the OAuth2 client secret post
scheme

The OAuth2 client secret post scheme simply consists in transmitting a client and its password
in www-URL-encoded body (example from RFC6749):

```http
 POST /token HTTP/1.1
 Host: server.example.com
 Content-Type: application/x-www-form-urlencoded

 grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
 &client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw
```

## Installation

```elixir
def deps do
  [
    {:apiac_auth_client_secret_post, github: "tanguilp/apiac_auth_client_secret_post", tag: "v0.1.0"}
  ]
end
```

## Example with callback function

The callback function will be called with the `realm` and `client` and return string password or an `%Expwd.Hashed{}` struct:

```elixir
plug APIacAuthClientSecretPost, realm: "my realm",
		      callback: &Module.get_client_password/2
```


## Example with configuration file

`{client_id, client_secret}` pairs can be configured in you application configuration files.
There will be compiled at **compile time**. If you need runtime configurability,
use the `callback` option instead.

Storing cleartext password requires special care, for instance: using \*.secret.exs files,
encrypted storage of these config files, etc. Consider using hashed password instead, such
as `Expwd.Hashed.Portable.t`

Pairs a to be set separately for each realm in the `clients` key, as following:
``` elixir
config :apiac_auth_client_secret_post,
  clients: %{
    # using Expwd Hashed portable password
    "realm_a" => [
      {"client_1", {:expwd, :sha256, "lYOmCIZUR603rPiIN0agzBHFyZDw9xEtETfbe6Q1ubU"}},
      {"client_2", {:expwd, :sha256, "mnAWHn1tSHEOCj6sMDIrB9BTRuD4yZkiLbjx9x2i3ug"}},
      {"client_3", {:expwd, :sha256, "9RYrMJSmXJSN4CSJZtOX0Xs+vP94meTaSzGc+oFcwqM"}},
      {"client_4", {:expwd, :sha256, "aCL154jd8bNw868cbsCUw3skHun1n6fGYhBiITSmREw"}},
      {"client_5", {:expwd, :sha256, "xSE6MkeC+gW7R/lEZKxsWGDs1MlqEV4u693fCBNlV4g"}}
    ],
    "realm_b" => [
      {"client_1", {:expwd, :sha256, "lYOmCIZUR603rPiIN0agzBHFyZDw9xEtETfbe6Q1ubU"}}
    ],
    # UNSAFE: cleartext passwords set directly in the config file
    "realm_c" => [
      {"client_6", "cleartext password"},
      {"client_7", "cleartext password again"}
    ]
  }
```

then in your Plug pipeline:

```elixir
Plug APIacAuthClientSecretPost, realm: "realm_a"
```
