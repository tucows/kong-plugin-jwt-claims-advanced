-- Coverage for handler.lua's claim-processing/authorization logic,
-- including a regression test for HackerOne report #3940956: a claim
-- configured with `allow_undefined: true` caused plugin:access() to
-- return early when that claim was missing from the JWT, skipping every
-- claim configured after it -- including authorization checks such as
-- `contains`/`equals`.
--
-- The real Kong PDK, ngx, and `kong.plugins.jwt.jwt_parser` module are
-- only available inside a full Kong install, so this spec stubs the
-- minimal surface handler.lua actually touches. JWT decoding itself is
-- faked: the "token" used in tests IS the JSON-encoded claims payload,
-- and the fake jwt_parser just decodes it back into a `.claims` table.
-- This lets the test exercise the real claim-processing/authorization
-- logic in handler.lua without needing a signed JWT or a full Kong
-- runtime.

local cjson = require "cjson"

package.preload["kong.plugins.jwt.jwt_parser"] = function()
  local fake_jwt_parser = {}
  function fake_jwt_parser:new(token)
    local ok, claims = pcall(cjson.decode, token)
    if not ok then
      return nil, "invalid token"
    end
    return { claims = claims }
  end
  return fake_jwt_parser
end

_G.ngx = {
  re = {
    -- Minimal stand-in for ngx.re.gmatch, supporting only the single
    -- pattern handler.lua uses to pull a bearer token out of a header.
    gmatch = function(subject, _pattern)
      local done = false
      return function()
        if done then
          return nil
        end
        done = true
        local token = subject:match("^%s*[Bb]earer%s+(.+)$")
        if not token then
          return nil
        end
        return { token }
      end
    end,
  },
  var = {},
}

local current_request_headers
local current_query_args
local recorded

local function reset_recorder()
  recorded = {
    exit_calls = {},
    headers_set = {},
  }
end

_G.kong = {
  request = {
    get_query = function() return current_query_args end,
    get_headers = function() return current_request_headers end,
  },
  service = {
    request = {
      set_header = function(name, value)
        table.insert(recorded.headers_set, { name = name, value = value })
      end,
    },
  },
  response = {
    exit = function(status, body)
      table.insert(recorded.exit_calls, { status = status, body = body })
      return status
    end,
  },
  log = {
    err = function(...) end,
  },
}

-- handler.lua lives at the repo root, and is required as a plain module
-- (rather than via the "kong.plugins.jwt-claims-advanced.handler" path
-- luarocks installs it under) so the spec can run straight out of a
-- checkout without a full plugin install.
local plugin = require "handler"

local function set_jwt_claims(claims)
  current_request_headers = { authorization = "Bearer " .. cjson.encode(claims) }
end

local function set_jwt_claims_via_query(param_name, claims)
  current_query_args = { [param_name] = cjson.encode(claims) }
end

local function set_jwt_claims_via_cookie(cookie_name, claims)
  ngx.var["cookie_" .. cookie_name] = cjson.encode(claims)
end

local function make_claim(overrides)
  local claim = {
    allow_undefined = false,
    contains_one_of = {},
    contains_none_of = {},
    equals_one_of = {},
    equals_none_of = {},
  }
  for k, v in pairs(overrides) do
    claim[k] = v
  end
  return claim
end

local function make_config(claims, overrides)
  local config = {
    uri_param_names = {},
    header_names = { "authorization" },
    cookie_names = {},
    continue_on_error = true,
    claims = claims,
  }
  for k, v in pairs(overrides or {}) do
    config[k] = v
  end
  return config
end

local function header_value(name)
  for _, h in ipairs(recorded.headers_set) do
    if h.name == name then
      return h.value
    end
  end
  return nil
end

local function assert_allowed()
  assert.are.equal(0, #recorded.exit_calls)
end

local function assert_rejected(claim_path)
  assert.are.equal(1, #recorded.exit_calls)
  assert.are.equal(403, recorded.exit_calls[1].status)
  assert.are.equal(claim_path, recorded.exit_calls[1].body.claim_path)
end

describe("jwt-claims-advanced handler", function()

  before_each(function()
    reset_recorder()
    current_request_headers = {}
    current_query_args = {}
    ngx.var = {}
  end)

  describe("optional claim followed by an authorization claim (HackerOne #3940956)", function()

    local function config_with_filler_and_groups()
      return make_config({
        make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }),
        make_claim({ path = "groups", contains = "admin" }),
      })
    end

    it("rejects when the optional claim is present but the later claim fails (control)", function()
      set_jwt_claims({ filler = "present", groups = { "user" } })

      plugin:access(config_with_filler_and_groups())

      assert_rejected("groups")
      assert.are.equal("present", header_value("X-Filler"))
    end)

    it("still rejects when the optional claim is omitted (regression for the bypass)", function()
      set_jwt_claims({ groups = { "user" } })

      plugin:access(config_with_filler_and_groups())

      assert_rejected("groups")
      assert.are.equal("", header_value("X-Filler"))
    end)

    it("allows the request through when the optional claim is omitted but the later claim passes", function()
      set_jwt_claims({ groups = { "admin" } })

      plugin:access(config_with_filler_and_groups())

      assert_allowed()
      assert.are.equal("", header_value("X-Filler"))
    end)

  end)

  describe("claim operators", function()

    -- pass_claims / fail_claims are the JWT claims that should satisfy /
    -- violate `claim` (a single-claim config) respectively.
    local cases = {
      {
        name = "equals",
        claim = { path = "role", equals = "admin" },
        pass_claims = { role = "admin" },
        fail_claims = { role = "user" },
      },
      {
        name = "does_not_equal",
        claim = { path = "role", does_not_equal = "admin" },
        pass_claims = { role = "user" },
        fail_claims = { role = "admin" },
      },
      {
        name = "equals_one_of",
        claim = { path = "role", equals_one_of = { "admin", "superadmin" } },
        pass_claims = { role = "superadmin" },
        fail_claims = { role = "user" },
      },
      {
        name = "equals_none_of",
        claim = { path = "role", equals_none_of = { "admin", "superadmin" } },
        pass_claims = { role = "user" },
        fail_claims = { role = "admin" },
      },
      {
        name = "contains",
        claim = { path = "groups", contains = "admin" },
        pass_claims = { groups = { "admin", "user" } },
        fail_claims = { groups = { "user" } },
      },
      {
        name = "does_not_contain",
        claim = { path = "groups", does_not_contain = "admin" },
        pass_claims = { groups = { "user" } },
        fail_claims = { groups = { "admin" } },
      },
      {
        name = "contains_one_of",
        claim = { path = "groups", contains_one_of = { "admin", "superadmin" } },
        pass_claims = { groups = { "user", "admin" } },
        fail_claims = { groups = { "guest" } },
      },
      {
        name = "contains_none_of",
        claim = { path = "groups", contains_none_of = { "admin", "superadmin" } },
        pass_claims = { groups = { "guest" } },
        fail_claims = { groups = { "admin" } },
      },
    }

    for _, case in ipairs(cases) do

      it(case.name .. " allows the request through when satisfied", function()
        set_jwt_claims(case.pass_claims)

        plugin:access(make_config({ make_claim(case.claim) }))

        assert_allowed()
      end)

      it(case.name .. " rejects the request when violated", function()
        set_jwt_claims(case.fail_claims)

        plugin:access(make_config({ make_claim(case.claim) }))

        assert_rejected(case.claim.path)
      end)

    end

    describe("when the claim value is not an array (contains-style operators only)", function()

      local not_a_table_cases = {
        { name = "contains", claim = { path = "groups", contains = "admin" } },
        { name = "does_not_contain", claim = { path = "groups", does_not_contain = "admin" } },
        { name = "contains_one_of", claim = { path = "groups", contains_one_of = { "admin" } } },
        { name = "contains_none_of", claim = { path = "groups", contains_none_of = { "admin" } } },
      }

      for _, case in ipairs(not_a_table_cases) do
        it(case.name .. " rejects rather than erroring", function()
          set_jwt_claims({ groups = "admin" }) -- a plain string, not an array

          plugin:access(make_config({ make_claim(case.claim) }))

          assert_rejected("groups")
        end)
      end

    end)

    describe("deny-list bypass via claim type/shape (security review finding)", function()

      -- A deny-list rule (does_not_equal/equals_none_of/does_not_contain/
      -- contains_none_of) must fail closed when the claim's JSON shape
      -- doesn't match what the rule expects, rather than silently
      -- passing because tostring()/== can't see through the mismatch.
      -- The claim holder controls this shape directly: in Kong's
      -- default HS256 credential model a consumer signs their own
      -- token, so they can wrap a forbidden scalar in an array/object,
      -- or use a number where a string was configured, without any key
      -- compromise.

      it("does_not_equal rejects a forbidden value wrapped in an array instead of a scalar", function()
        set_jwt_claims({ role = { "admin" } })

        plugin:access(make_config({
          make_claim({ path = "role", does_not_equal = "admin", output_header = "X-JWT-Role" }),
        }))

        assert_rejected("role")
      end)

      it("equals_none_of rejects a forbidden value wrapped in an array instead of a scalar", function()
        set_jwt_claims({ role = { "admin" } })

        plugin:access(make_config({
          make_claim({ path = "role", equals_none_of = { "admin", "superadmin" } }),
        }))

        assert_rejected("role")
      end)

      it("contains_none_of rejects a numeric claim element against a string deny value", function()
        set_jwt_claims({ perms = { 911 } })

        plugin:access(make_config({
          make_claim({ path = "perms", contains_none_of = { "911" } }),
        }))

        assert_rejected("perms")
      end)

      it("does_not_contain rejects when the claim is a JSON object instead of an array", function()
        set_jwt_claims({ groups = { ["0"] = "banned-grp" } })

        plugin:access(make_config({
          make_claim({ path = "groups", does_not_contain = "banned-grp" }),
        }))

        assert_rejected("groups")
      end)

      it("contains_none_of rejects when the claim is a JSON object instead of an array", function()
        set_jwt_claims({ groups = { ["0"] = "banned-grp" } })

        plugin:access(make_config({
          make_claim({ path = "groups", contains_none_of = { "banned-grp" } }),
        }))

        assert_rejected("groups")
      end)

      it("does not regress a legitimate array claim through the new shape check", function()
        set_jwt_claims({ groups = { "admin", "user" } })

        plugin:access(make_config({
          make_claim({ path = "groups", contains = "admin" }),
        }))

        assert_allowed()
      end)

    end)

    describe("generalizing the HackerOne regression across every operator", function()

      -- Same shape as the HackerOne repro: an optional claim (missing,
      -- allow_undefined: true) followed by a claim that should still be
      -- enforced. Proves the fix isn't narrowly specific to `contains`.
      for _, case in ipairs(cases) do
        it("still enforces " .. case.name .. " when a preceding optional claim is omitted", function()
          set_jwt_claims(case.fail_claims) -- "filler" is entirely absent

          plugin:access(make_config({
            make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }),
            make_claim(case.claim),
          }))

          assert_rejected(case.claim.path)
          assert.are.equal("", header_value("X-Filler"))
        end)
      end

    end)

    it("continues through a longer chain of claims, not just one past the optional claim", function()
      set_jwt_claims({ role = "user", groups = { "user" }, tier = "gold" })

      plugin:access(make_config({
        make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }),
        make_claim({ path = "role", equals_one_of = { "user", "admin" } }),
        make_claim({ path = "groups", does_not_contain = "banned" }),
        make_claim({ path = "tier", equals = "platinum" }), -- fails
      }))

      assert_rejected("tier")
    end)

  end)

  describe("output_header value forwarding", function()

    it("JSON-encodes table/array claim values when forwarding as a header", function()
      local groups = { "admin", "user" }
      set_jwt_claims({ groups = groups })

      plugin:access(make_config({
        make_claim({ path = "groups", output_header = "X-Groups" }),
      }))

      assert_allowed()
      assert.are.equal(cjson.encode(groups), header_value("X-Groups"))
    end)

    it("documents current behavior: a required claim that's missing forwards a nil header value", function()
      set_jwt_claims({})

      plugin:access(make_config({
        make_claim({ path = "missing_claim", output_header = "X-Missing", allow_undefined = false }),
      }))

      assert_allowed()

      local found = false
      for _, h in ipairs(recorded.headers_set) do
        if h.name == "X-Missing" then
          found = true
          assert.is_nil(h.value)
        end
      end
      assert.is_true(found)
    end)

  end)

  describe("nested claim path traversal", function()

    it("resolves a multi-level dotted path", function()
      set_jwt_claims({ a = { b = { c = "deep-value" } } })

      plugin:access(make_config({
        make_claim({ path = "a.b.c", output_header = "X-Deep" }),
      }))

      assert_allowed()
      assert.are.equal("deep-value", header_value("X-Deep"))
    end)

    it("treats a path that continues past a non-table node as absent, not an error", function()
      set_jwt_claims({ a = { b = "leaf-string" } })

      plugin:access(make_config({
        make_claim({ path = "a.b.c", equals = "deep-value" }),
      }))

      assert_rejected("a.b.c")
    end)

  end)

  describe("token retrieval", function()

    it("finds the JWT via a configured uri_param_name", function()
      set_jwt_claims_via_query("jwt", { role = "admin" })

      plugin:access(make_config(
        { make_claim({ path = "role", equals = "admin" }) },
        { uri_param_names = { "jwt" } }
      ))

      assert_allowed()
    end)

    it("finds the JWT via a configured cookie_name", function()
      set_jwt_claims_via_cookie("jwt", { role = "admin" })

      plugin:access(make_config(
        { make_claim({ path = "role", equals = "admin" }) },
        { cookie_names = { "jwt" } }
      ))

      assert_allowed()
    end)

    it("checks each configured header_name in order, using whichever is present", function()
      set_jwt_claims({ role = "admin" }) -- lands on the default "authorization" header

      plugin:access(make_config(
        { make_claim({ path = "role", equals = "admin" }) },
        { header_names = { "x-custom-jwt", "authorization" } }
      ))

      assert_allowed()
    end)

    it("handles a header value provided as a table (repeated header)", function()
      local token = "Bearer " .. cjson.encode({ role = "admin" })
      current_request_headers = { authorization = { token, "Bearer some-other-token" } }

      plugin:access(make_config({ make_claim({ path = "role", equals = "admin" }) }))

      assert_allowed()
    end)

    it("treats a header that doesn't match the Bearer pattern as no token found", function()
      current_request_headers = { authorization = "Basic dXNlcjpwYXNz" }

      plugin:access(make_config({ make_claim({ path = "groups", contains = "admin" }) }))

      assert_rejected("groups")
    end)

    it("when continue_on_error is true and no token is found anywhere, allow_undefined claims still pass through", function()
      -- current_request_headers / current_query_args / ngx.var are all
      -- empty from before_each -- no token available via any transport.
      plugin:access(make_config({
        make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }),
      }))

      assert_allowed()
      assert.are.equal("", header_value("X-Filler"))
    end)

    it("when continue_on_error is false and no token is found anywhere, exits with 500", function()
      plugin:access(make_config(
        { make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }) },
        { continue_on_error = false }
      ))

      assert.are.equal(1, #recorded.exit_calls)
      assert.are.equal(500, recorded.exit_calls[1].status)
      assert.are.equal("Internal server error", recorded.exit_calls[1].body)
    end)

  end)

end)
