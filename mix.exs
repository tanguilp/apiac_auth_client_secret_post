defmodule APIacAuthClientSecretPost.Mixfile do
  use Mix.Project

  def project do
    [
      app: :apiac_auth_client_secret_post,
      description: "APIac Elixir plug for OAuth2 post client authentication ",
      version: "1.0.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      package: package(),
      source_url: "https://github.com/tanguilp/apiac_auth_client_secret_post"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:plug, "~> 1.0"},
      {:expwd, "~> 1.0"},
      {:apiac, "~> 1.0"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/apiac_auth_client_secret_post"}
    ]
  end
end
