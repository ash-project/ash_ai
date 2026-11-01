# SPDX-FileCopyrightText: 2024 ash_ai contributors <https://github.com/ash-project/ash_ai/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAi.Mcp.UriTemplateTest do
  use ExUnit.Case, async: true

  alias AshAi.Mcp.UriTemplate

  defp match(template, uri) do
    {:ok, template} = UriTemplate.parse(template)
    UriTemplate.match(template, uri)
  end

  defp parse_error(template) do
    assert {:error, message} = UriTemplate.parse(template)
    message
  end

  describe "template?/1" do
    test "is true only for URIs with braces" do
      assert UriTemplate.template?("photos://{id}")
      assert UriTemplate.template?("photos://id}")
      refute UriTemplate.template?("photos://featured")
    end
  end

  describe "simple expansion" do
    test "matches one non-empty path segment" do
      assert match("photos://{id}", "photos://123") == {:ok, %{"id" => "123"}}
      assert match("photos://{id}", "photos://") == :error
      assert match("photos://{id}", "photos://1/2") == :error
      assert match("photos://{id}", "photos://1?size=2") == :error
      assert match("photos://{id}", "photos://1#top") == :error
      assert match("photos://{id}", "albums://1") == :error
    end

    test "matches literals around and between variables" do
      template = "users://{user_id}/posts/{post_id}.json"

      assert match(template, "users://7/posts/42.json") ==
               {:ok, %{"user_id" => "7", "post_id" => "42"}}

      assert match(template, "users://7/posts/42.xml") == :error
      assert match(template, "users://7/comments/42.json") == :error
    end

    test "percent-decodes values" do
      assert match("photos://{id}", "photos://a%20b") == {:ok, %{"id" => "a b"}}
      assert match("photos://{id}", "photos://a%2Fb") == {:ok, %{"id" => "a/b"}}
      assert match("photos://{id}", "photos://caf%C3%A9") == {:ok, %{"id" => "café"}}
    end

    test "rejects malformed percent-encoding and invalid UTF-8" do
      assert match("photos://{id}", "photos://a%zz") == :error
      assert match("photos://{id}", "photos://a%FF") == :error
    end
  end

  describe "reserved expansion" do
    test "spans path segments" do
      assert match("file:///{+path}", "file:///a/b/c.txt") == {:ok, %{"path" => "a/b/c.txt"}}
      assert match("file:///{+path}", "file:///") == :error
      assert match("file:///{+path}", "file:///a?b") == :error
    end

    test "backtracks when the following literal also occurs in the value" do
      assert match("file:///{+path}.json", "file:///a.b.json") == {:ok, %{"path" => "a.b"}}
      assert match("file:///{+path}/raw", "file:///a/raw/raw") == {:ok, %{"path" => "a/raw"}}
    end
  end

  describe "form-style query" do
    @template "photos://{id}{?size,format}"

    test "treats every query variable as optional" do
      assert match(@template, "photos://1") == {:ok, %{"id" => "1"}}
      assert match(@template, "photos://1?") == {:ok, %{"id" => "1"}}
      assert match(@template, "photos://1?size=200") == {:ok, %{"id" => "1", "size" => "200"}}
    end

    test "accepts the variables in any order, percent-decoded" do
      assert match(@template, "photos://1?format=image%2Fpng&size=2") ==
               {:ok, %{"id" => "1", "size" => "2", "format" => "image/png"}}
    end

    test "takes a key without `=` as an empty value" do
      assert match(@template, "photos://1?size") == {:ok, %{"id" => "1", "size" => ""}}
    end

    test "rejects unknown, repeated and empty keys" do
      assert match(@template, "photos://1?width=2") == :error
      assert match(@template, "photos://1?size=1&size=2") == :error
      assert match(@template, "photos://1?size=1&") == :error
    end
  end

  describe "parse/1" do
    test "keeps literal-only URIs as a single literal" do
      assert {:ok, %UriTemplate{parts: [{:literal, "photos://featured"}], query: nil}} =
               UriTemplate.parse("photos://featured")
    end

    test "lists variables in order" do
      {:ok, template} = UriTemplate.parse("users://{user_id}/files/{+path}{?rev,raw}")
      assert UriTemplate.variables(template) == ~w(user_id path rev raw)
    end

    test "rejects unbalanced braces" do
      assert parse_error("photos://{id") =~ "`{` is never closed"
      assert parse_error("photos://id}") =~ "`}` has no matching `{`"
    end

    test "rejects unsupported operators and modifiers" do
      for operator <- ~w(# . / ; &) do
        assert parse_error("photos://x{#{operator}id}") =~
                 "the `#{operator}` operator, which isn't supported"
      end

      assert parse_error("photos://{id*}") =~ "modifier"
      assert parse_error("photos://{id:3}") =~ "modifier"
    end

    test "rejects several variables outside a query expression" do
      assert parse_error("photos://{a,b}") =~ "names several variables"
      assert parse_error("photos://{+a,b}") =~ "names several variables"
    end

    test "rejects empty expressions and invalid variable names" do
      assert parse_error("photos://{}") =~ "names no variable"
      assert parse_error("photos://{?}") =~ "names no variable"
      assert parse_error("photos://{photo-id}") =~ ~s(invalid variable name "photo-id")
      assert parse_error("photos://{?a,}") =~ ~s(invalid variable name "")
    end

    test "rejects a query expression that doesn't end the template" do
      assert parse_error("photos://{?size}/{id}") =~ "`{?...}` must end the template"
    end

    test "rejects a literal `?` before a query expression" do
      assert parse_error("photos://{id}?v=1{?size}") =~ "literal `?`"
    end

    test "rejects adjacent variables" do
      assert parse_error("photos://{a}{b}") =~ "`a` and `b` need literal text between them"
      assert parse_error("photos://{+a}{b}") =~ "`a` and `b` need literal text between them"
    end

    test "rejects repeated variables" do
      assert parse_error("photos://{id}/{id}") =~ "`id` appears more than once"
      assert parse_error("photos://{id}{?id}") =~ "`id` appears more than once"
    end
  end
end
