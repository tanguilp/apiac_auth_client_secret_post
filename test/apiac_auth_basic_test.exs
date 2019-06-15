defmodule APIacAuthClientSecretPostTest do
  use ExUnit.Case, async: true
  use Plug.Test

  @valid_client_id "my_client"
  @valid_client_secret "My secret"
  @test_realm_name "It's closed"

  setup_all do
    Application.put_env(
      :apiac_auth_client_secret_post,
      :clients,
      %{
        @test_realm_name => [
          {@valid_client_id, @valid_client_secret},
          # password is "Yg03EosS+2I7XxozZyMfshph1r4khGgLrj92nyEvmak"
          {"expwd_client", "expwd:sha256:xSE6MkeC+gW7R/lEZKxsWGDs1MlqEV4u693fCBNlV4g"}
        ]
      }
    )
  end

  test "Correct credentials - check APIac attributes are correctly set" do
    opts = APIacAuthClientSecretPost.init(realm: @test_realm_name)

    conn =
      conn(:post, "/")
      |> put_body(%{"client_id" => @valid_client_id, "client_secret" => @valid_client_secret})
      |> APIacAuthClientSecretPost.call(opts)

    refute conn.status == 401
    refute conn.halted
    assert APIac.authenticated?(conn) == true
    assert APIac.machine_to_machine?(conn) == true
    assert APIac.authenticator(conn) == APIacAuthClientSecretPost
    assert APIac.client(conn) == @valid_client_id
  end

  test "Incorrect credentials" do
    opts = APIacAuthClientSecretPost.init(clients: [{@valid_client_id, @valid_client_secret}])

    conn =
      conn(:post, "/")
      |> put_body(%{"client_id" => @valid_client_id, "client_secret" => "invalid secret"})
      |> APIacAuthClientSecretPost.call(opts)

    assert conn.status == 401
    assert conn.halted
  end

  test "Check www-authenticate header (none to be found)" do
    opts = APIacAuthClientSecretPost.init(realm: @test_realm_name)

    conn =
      conn(:post, "/")
      |> put_body(%{"client_id" => @valid_client_id, "client_secret" => "invalid secret"})
      |> APIacAuthClientSecretPost.call(opts)

    assert get_resp_header(conn, "www-authenticate") == []
    assert conn.halted
    assert conn.status == 401
  end

  test "Check function callback returning correct secret" do
    opts = APIacAuthClientSecretPost.init(callback: fn _realm, _client_id -> @valid_client_secret end)

    conn =
      conn(:get, "/")
      |> put_body(%{"client_id" => @valid_client_id, "client_secret" => @valid_client_secret})
      |> APIacAuthClientSecretPost.call(opts)

    refute conn.status == 401
    refute conn.halted
  end

  test "Check function callback returning invalid secret" do
    opts = APIacAuthClientSecretPost.init(callback: fn _realm, _client_id -> "invalid client_secret" end)

    conn =
      conn(:get, "/")
      |> put_body(%{"client_id" => @valid_client_id, "client_secret" => @valid_client_secret})
      |> APIacAuthClientSecretPost.call(opts)

    assert conn.status == 401
    assert conn.halted
  end

  defp put_body(conn, values) do
    %Plug.Conn{conn | body_params: values}
  end

end
