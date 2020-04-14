defmodule APIacAuthClientSecretPost do
  @behaviour Plug
  @behaviour APIac.Authenticator

  use Bitwise

  @moduledoc """
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

  ## Security considerations

  Use of this scheme is not recommended (instead HTTP Basic authentication is recommended).

  ## Plug options

  - `realm`: a mandatory `String.t` that conforms to the HTTP quoted-string syntax,
  however without the surrounding quotes (which will be added automatically when
  needed). Defaults to `default_realm`
  - `callback`: a function that will return the password of a client. When a
  callback is configured, it takes precedence over the clients in the config
  files, which will not be used. The returned value can be:
    - A cleartext password (`String.t`)
    - An `Expwd.Hashed{}` (hashed password)
    - `nil` if the client is not known
  - `set_error_response`: function called when authentication failed. Defaults to
  `APIacAuthClientSecretPost.send_error_response/3`
  - `error_response_verbosity`: one of `:debug`, `:normal` or `:minimal`.
  Defaults to `:normal`

  ## Application configuration

  `{client_id, client_secret}` pairs can be configured in you application configuration files. There will be compiled at **compile time**. If you need runtime configurability,
  use the `callback` option instead.

  Storing cleartext password requires special care, for instance: using *.secret.exs files, encrypted storage of these config files, etc. Consider using hashed password instead, such
  as `%Expwd.Hashed{}`.

  Pairs a to be set separately for each realm in the `clients` key, as following:
  ``` elixir
  config :apiac_auth_client_secret_post,
    clients: %{
      # using Expwd Hashed portable password
      "realm_a" => [
        {"client_1", "expwd:sha256:lYOmCIZUR603rPiIN0agzBHFyZDw9xEtETfbe6Q1ubU"},
        {"client_2", "expwd:sha256:mnAWHn1tSHEOCj6sMDIrB9BTRuD4yZkiLbjx9x2i3ug"},
        {"client_3", "expwd:sha256:9RYrMJSmXJSN4CSJZtOX0Xs+vP94meTaSzGc+oFcwqM"},
        {"client_4", "expwd:sha256:aCL154jd8bNw868cbsCUw3skHun1n6fGYhBiITSmREw"},
        {"client_5", "expwd:sha256:xSE6MkeC+gW7R/lEZKxsWGDs1MlqEV4u693fCBNlV4g"}
      ],
      "realm_b" => [
        {"client_1", "expwd:sha256:lYOmCIZUR603rPiIN0agzBHFyZDw9xEtETfbe6Q1ubU"}
      ],
      # UNSAFE: cleartext passwords set directly in the config file
      "realm_c" => [
        {"client_6", "cleartext password"},
        {"client_7", "cleartext password again"}
      ]
    }
  ```
  """

  @default_realm "default_realm"

  @typedoc """
    The callback function returns an Expwd.Hashed.t or a client_secret (String.t) so as
    to prevent developers to [unsecurely compare passwords](https://codahale.com/a-lesson-in-timing-attacks/).

    Return `nil` if the client could not be gound for this realm
  """
  @type callback_fun ::
          (APIac.realm(), APIac.client() -> Expwd.Hashed.t() | client_secret | nil)

  @type client_secret :: String.t()

  @doc """
  Plug initialization callback
  """

  @impl Plug

  @spec init(Plug.opts()) :: Plug.opts()

  def init(opts) do
    if is_binary(opts[:realm]) and not APIac.rfc7230_quotedstring?("\"#{opts[:realm]}\""),
      do: raise "Invalid realm string (do not conform with RFC7230 quoted string)"

    realm = if opts[:realm], do: opts[:realm], else: @default_realm

    opts
    |> Enum.into(%{})
    |> Map.put_new(:realm, @default_realm)
    |> Map.put_new(:clients,
                   Application.get_env(:apiac_auth_client_secret_post, :clients)[realm] || [])
    |> Map.put_new(:callback, nil)
    |> Map.put_new(:set_error_response, &APIacAuthClientSecretPost.send_error_response/3)
    |> Map.put_new(:error_response_verbosity, :normal)
  end

  @doc """
  Plug pipeline callback
  """

  @impl Plug

  @spec call(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()

  def call(conn, %{} = opts) do
    if APIac.authenticated?(conn) do
      conn
    else
      do_call(conn, opts)
    end
  end

  def do_call(conn, opts) do
    with {:ok, conn, credentials} <- extract_credentials(conn, opts),
         {:ok, conn} <- validate_credentials(conn, credentials, opts) do
      conn
    else
      {:error, conn, %APIac.Authenticator.Unauthorized{} = error} ->
        opts[:set_error_response].(conn, error, opts)
    end
  end

  @doc """
  `APIac.Authenticator` credential extractor callback

  Returns the credentials under the form `{client_id, client_secret}` where both
  variables are binaries
  """

  @impl APIac.Authenticator
  def extract_credentials(%Plug.Conn{body_params:
    %{"client_id" => client_id, "client_secret" => client_secret}} = conn, _opts) do
    if not ctl_char?(client_secret) and not ctl_char?(client_secret) do
      {:ok, conn, {client_id, client_secret}}
    else
      {:error, conn,
       %APIac.Authenticator.Unauthorized{
         authenticator: __MODULE__,
         reason: :invalid_client_id_or_client_secret
       }}
    end
  end

  def extract_credentials(conn, _opts) do
    {:error, conn,
     %APIac.Authenticator.Unauthorized{
       authenticator: __MODULE__,
       reason: :credentials_not_found
     }}
  end

  defp ctl_char?(str) do
    Regex.run(~r/[\x00-\x1F\x7F]/, str) != nil
  end

  @doc """
  `APIac.Authenticator` credential validator callback
  """

  @impl APIac.Authenticator

  def validate_credentials(conn, {client_id, client_secret}, %{callback: callback} = opts)
      when is_function(callback) do
    case callback.(opts[:realm], client_id) do
      nil ->
        {:error, conn,
         %APIac.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :client_not_found}}

      stored_client_secret ->
        if Expwd.secure_compare(client_secret, stored_client_secret) == true do
          conn =
            conn
            |> Plug.Conn.put_private(:apiac_authenticator, __MODULE__)
            |> Plug.Conn.put_private(:apiac_client, client_id)
            |> Plug.Conn.put_private(:apiac_realm, opts[:realm])

          {:ok, conn}
        else
          {:error, conn,
           %APIac.Authenticator.Unauthorized{
             authenticator: __MODULE__,
             reason: :invalid_client_secret
           }}
        end
    end
  end

  @impl APIac.Authenticator

  def validate_credentials(conn, {client_id, client_secret}, opts) do
    case List.keyfind(opts[:clients], client_id, 0) do
      nil ->
        {:error, conn,
         %APIac.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :client_not_found}}

      {_stored_client_id, stored_client_secret} ->
        if Expwd.secure_compare(client_secret, stored_client_secret) == true do
          conn =
            conn
            |> Plug.Conn.put_private(:apiac_authenticator, __MODULE__)
            |> Plug.Conn.put_private(:apiac_client, client_id)
            |> Plug.Conn.put_private(:apiac_realm, opts[:realm])

          {:ok, conn}
        else
          {:error, conn,
           %APIac.Authenticator.Unauthorized{
             authenticator: __MODULE__,
             reason: :invalid_client_secret
           }}
        end
    end
  end

  @doc """
  Implementation of the `APIac.Authenticator` callback

  ## Verbosity

  The following elements in the HTTP response are set depending on the value
  of the `:error_response_verbosity` option:

  | Error response verbosity | HTTP Status | Headers | Body                                    |
  |:----------:|--------------------|-|--------------------------------------------------------|
  | `:debug`   | Unauthorized (401) | | `APIac.Authenticator.Unauthorized` exception's message |
  | `:normal`  | Unauthorized (401) | |                                                        |
  | `:minimal` | Unauthorized (401) | |                                                        |

  Note: this scheme does not advertise any HTTP `Authorization` header.

  """
  @impl APIac.Authenticator
  def send_error_response(conn, error, opts) do
    case opts[:error_response_verbosity] do
      :debug ->
        conn
        |> Plug.Conn.send_resp(:unauthorized, Exception.message(error))
        |> Plug.Conn.halt()

      :normal ->
        conn
        |> Plug.Conn.send_resp(:unauthorized, "")
        |> Plug.Conn.halt()

      :minimal ->
        conn
        |> Plug.Conn.send_resp(:unauthorized, "")
        |> Plug.Conn.halt()
    end
  end

  @doc """
  Saves failure in a `Plug.Conn.t()`'s private field and returns the `conn`

  See the `APIac.AuthFailureResponseData` module for more information.
  """
  @spec save_authentication_failure_response(
          Plug.Conn.t(),
          %APIac.Authenticator.Unauthorized{},
          any()
        ) :: Plug.Conn.t()
  def save_authentication_failure_response(conn, error, opts) do
    failure_response_data =
      case opts[:error_response_verbosity] do
        :debug ->
          %APIac.AuthFailureResponseData{
            module: __MODULE__,
            reason: error.reason,
            status_code: :unauthorized,
            body: Exception.message(error)
          }

        :normal ->
          %APIac.AuthFailureResponseData{
            module: __MODULE__,
            reason: error.reason,
            status_code: :unauthorized,
            body: ""
          }

        :minimal ->
          %APIac.AuthFailureResponseData{
            module: __MODULE__,
            reason: error.reason,
            www_authenticate_header: nil,
            status_code: :unauthorized,
            body: ""
          }
      end

    APIac.AuthFailureResponseData.put(conn, failure_response_data)
  end
end
