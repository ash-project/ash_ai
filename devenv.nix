{ pkgs, lib, config, inputs, ... }:

{
  services.postgres = {
    enable = true;
    package = pkgs.postgresql_17;
    listen_addresses = "localhost";
    port = 5430;

   extensions = extensions: [
      extensions.pgvector
    ];

    # Create the "postgres" role with password and CREATEDB
    initialScript = ''
      CREATE ROLE postgres WITH LOGIN PASSWORD 'postgres' CREATEDB SUPERUSER;
    '';
  };

  packages = [
    pkgs.git
    pkgs.jq
    pkgs.beam.packages.erlang_27.elixir_1_18
    pkgs.beam.interpreters.erlang_27
    ];

  env.ERL_AFLAGS="-kernel shell_history enabled";

}
