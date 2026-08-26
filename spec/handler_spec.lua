-- Coverage for handler.lua's claim-processing/authorization logic,
-- including a regression test for HackerOne report #3940956: a claim
-- configured with `allow_undefined: true` caused plugin:access() to
-- return early when that claim was missing from the JWT, skipping every
-- claim configured after it -- including authorization checks such as
-- `contains`/`equals`.
--
-- The real Kong PDK and `kong.plugins.jwt.jwt_parser` module are only
-- available inside a full Kong install, so this spec stubs the minimal
-- surface handler.lua actually touches. JWT decoding itself is faked: the
-- "token" used in tests IS the JSON-encoded claims payload, and the fake
-- jwt_parser just decodes it back into a `.claims` table. This lets the
-- test exercise the real claim-processing/authorization logic in
-- handler.lua without needing a signed JWT or a full Kong runtime.
--
-- handler.lua reads kong.ctx.shared.authenticated_jwt_token rather than
-- re-locating/decoding a token itself -- that field is only ever set by
-- the official jwt plugin after a successful signature verification (see
-- set_consumer() in kong/plugins/jwt/handler.lua), and stays nil on its
-- anonymous-consumer fallback or when run_on_preflight skips
-- verification. set_jwt_claims() below simulates "the jwt plugin
-- verified this payload"; leaving it unset simulates "the jwt plugin did
-- not verify anything on this request."

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

local recorded

local function reset_recorder()
  recorded = {
    exit_calls = {},
    headers_set = {},
    warnings = {},
  }
end

_G.kong = {
  ctx = {
    shared = {},
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
    warn = function(...)
      table.insert(recorded.warnings, table.concat({...}, ""))
    end,
  },
}

-- handler.lua lives at the repo root, and is required as a plain module
-- (rather than via the "kong.plugins.jwt-claims-advanced.handler" path
-- luarocks installs it under) so the spec can run straight out of a
-- checkout without a full plugin install.
local plugin = require "handler"

-- Simulates the official jwt plugin having verified this payload and
-- published it for downstream plugins.
local function set_jwt_claims(claims)
  kong.ctx.shared.authenticated_jwt_token = cjson.encode(claims)
end

-- Same as set_jwt_claims(), but takes a raw JSON string. Needed for
-- fixtures cjson.encode() can't produce from a Lua table literal -- most
-- notably an explicit JSON `null`, which decodes to the cjson.null
-- sentinel (not Lua nil, and not omittable from a table literal).
local function set_verified_token_raw(json_string)
  kong.ctx.shared.authenticated_jwt_token = json_string
end

-- Simulates an unverified/forged Authorization header sitting on the
-- request -- e.g. the jwt plugin fell back to its anonymous consumer, or
-- run_on_preflight skipped verification -- without kong.ctx.shared.
-- authenticated_jwt_token ever being set. handler.lua must not read this.
local function set_unverified_request_header(claims)
  kong.request = kong.request or {}
  kong.request.get_headers = function()
    return { authorization = "Bearer " .. cjson.encode(claims) }
  end
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
    kong.ctx.shared.authenticated_jwt_token = nil
    kong.request = nil
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

    it("rejects when a required (non-allow_undefined) claim with output_header is missing, rather than forwarding a nil header value", function()
      -- Regression test: previously this fell through to
      -- kong.service.request.set_header(header, nil), which is a Lua
      -- runtime error against Kong's real PDK (only string/number/boolean
      -- header values are accepted). A required claim that's genuinely
      -- absent is now treated as a failed claim instead.
      set_jwt_claims({})

      plugin:access(make_config({
        make_claim({ path = "missing_claim", output_header = "X-Missing", allow_undefined = false }),
      }))

      assert_rejected("missing_claim")
      assert.is_nil(header_value("X-Missing"))
    end)

    it("allow_undefined treats an explicit JSON null the same as a missing claim (matches documented behavior)", function()
      set_verified_token_raw('{"role": null}')

      plugin:access(make_config({
        make_claim({ path = "role", output_header = "X-Role", allow_undefined = true }),
      }))

      assert_allowed()
      assert.are.equal("", header_value("X-Role"))
    end)

    it("rejects when a required (non-allow_undefined) claim holds an explicit JSON null, rather than forwarding the raw null value", function()
      set_verified_token_raw('{"role": null}')

      plugin:access(make_config({
        make_claim({ path = "role", output_header = "X-Role", allow_undefined = false }),
      }))

      assert_rejected("role")
      assert.is_nil(header_value("X-Role"))
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

  describe("trusting only the jwt-plugin-verified token (security review finding: CWE-347)", function()

    it("when continue_on_error is true and no token was ever verified, allow_undefined claims still pass through", function()
      -- kong.ctx.shared.authenticated_jwt_token is nil from before_each --
      -- e.g. no jwt plugin ran, or the route genuinely has no JWT context.
      plugin:access(make_config({
        make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }),
      }))

      assert_allowed()
      assert.are.equal("", header_value("X-Filler"))
    end)

    it("when continue_on_error is false and no token was ever verified, exits with 500", function()
      plugin:access(make_config(
        { make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }) },
        { continue_on_error = false }
      ))

      assert.are.equal(1, #recorded.exit_calls)
      assert.are.equal(500, recorded.exit_calls[1].status)
      assert.are.equal("Internal server error", recorded.exit_calls[1].body)
    end)

    it("when continue_on_error is true and the verified token fails to decode, does not crash and treats claims as absent", function()
      -- kong.ctx.shared.authenticated_jwt_token is set (a token WAS
      -- verified by the jwt plugin) but is not valid JSON, so decoding it
      -- fails. This must degrade the same way "no token at all" does,
      -- not raise a Lua runtime error from indexing a nil decoded_jwt.
      set_verified_token_raw("not-valid-json")

      plugin:access(make_config({
        make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }),
      }))

      assert_allowed()
      assert.are.equal("", header_value("X-Filler"))
    end)

    it("when continue_on_error is false and the verified token fails to decode, exits with 500", function()
      set_verified_token_raw("not-valid-json")

      plugin:access(make_config(
        { make_claim({ path = "filler", output_header = "X-Filler", allow_undefined = true }) },
        { continue_on_error = false }
      ))

      assert.are.equal(1, #recorded.exit_calls)
      assert.are.equal(500, recorded.exit_calls[1].status)
      assert.are.equal("Internal server error", recorded.exit_calls[1].body)
    end)

    it("processes claims from kong.ctx.shared.authenticated_jwt_token when the jwt plugin verified a token", function()
      set_jwt_claims({ role = "admin" })

      plugin:access(make_config({ make_claim({ path = "role", equals = "admin" }) }))

      assert_allowed()
    end)

    it("ignores an unverified/forged Authorization header entirely, even when it satisfies an allow-list rule", function()
      -- No jwt plugin ran (or it fell back to anonymous / skipped
      -- verification on preflight), so kong.ctx.shared.authenticated_jwt_token
      -- is nil -- but the request still carries a self-signed, unverified
      -- token with admin claims. It must never be consulted.
      set_unverified_request_header({ requestor = { groups = { "admin-grp" } } })

      plugin:access(make_config({
        make_claim({ path = "requestor.groups", contains = "admin-grp" }),
      }))

      assert_rejected("requestor.groups")
    end)

    it("does not forward an output_header value sourced from an unverified request header", function()
      set_unverified_request_header({ requestor = { id = "admin" } })

      plugin:access(make_config({
        make_claim({ path = "requestor.id", output_header = "X-JWT-Requestor-ID", allow_undefined = true }),
      }))

      assert_allowed()
      assert.are.equal("", header_value("X-JWT-Requestor-ID"))
    end)

  end)

  describe("deny-list rules must not pass by default when no token was ever verified (security review finding: CWE-636)", function()

    -- Scenario A (the bug): no jwt plugin ran at all (or it fell back to
    -- anonymous / skipped verification), so there's no verified claims
    -- data whatsoever. A deny-list rule must reject rather than silently
    -- pass just because there's nothing to compare against.

    it("does_not_equal rejects when no token was ever verified, not just when the value actually matches", function()
      plugin:access(make_config({
        make_claim({ path = "tenant", does_not_equal = "banned-tenant" }),
      }))

      assert_rejected("tenant")
    end)

    it("equals_none_of rejects when no token was ever verified, not just when the value actually matches", function()
      plugin:access(make_config({
        make_claim({ path = "tenant", equals_none_of = { "banned-tenant", "suspended-tenant" } }),
      }))

      assert_rejected("tenant")
    end)

    -- Scenario B (left alone, deliberately): a token WAS verified, this
    -- specific optional claim just isn't present in it. Absence here is
    -- legitimate data, not a failure to obtain a token -- does_not_equal/
    -- equals_none_of passing in this case is existing, intended behavior
    -- for optional claims, and out of scope for this finding.

    it("documents current behavior: does_not_equal still passes when a verified token simply lacks this optional claim", function()
      set_jwt_claims({ role = "user" }) -- verified token, but no "tenant" claim at all

      plugin:access(make_config({
        make_claim({ path = "tenant", does_not_equal = "banned-tenant" }),
      }))

      assert_allowed()
    end)

    it("documents current behavior: equals_none_of still passes when a verified token simply lacks this optional claim", function()
      set_jwt_claims({ role = "user" })

      plugin:access(make_config({
        make_claim({ path = "tenant", equals_none_of = { "banned-tenant" } }),
      }))

      assert_allowed()
    end)

  end)

  describe("comprehensive operator x claim-shape coverage", function()

    -- Every scalar operator (equals, does_not_equal, equals_one_of,
    -- equals_none_of) crossed against every JSON shape a `role` claim
    -- could realistically take. "allow_family" operators are satisfied
    -- by a genuine match; "deny_family" operators are satisfied by the
    -- absence of one -- so the same shape produces opposite expected
    -- outcomes depending on which family is being evaluated.
    local scalar_operators = {
      { name = "equals", family = "allow_family",
        make = function(v) return { path = "role", equals = v } end },
      { name = "does_not_equal", family = "deny_family",
        make = function(v) return { path = "role", does_not_equal = v } end },
      { name = "equals_one_of", family = "allow_family",
        make = function(v) return { path = "role", equals_one_of = { v, "unrelated-value" } } end },
      { name = "equals_none_of", family = "deny_family",
        make = function(v) return { path = "role", equals_none_of = { v, "unrelated-value" } } end },
    }

    local role_shapes = {
      {
        name = "missing claim (path absent, but the token itself is verified)",
        claims = {},
        configured_value = "admin",
        allow_family = "reject", -- absent claim never equals "admin"
        deny_family = "allow",   -- absent optional claim: documented pass-through (scenario B)
      },
      {
        name = "explicit JSON null",
        claims_json = '{"role": null}',
        configured_value = "admin",
        allow_family = "reject", -- cjson.null never equals "admin"
        deny_family = "allow",   -- null behaves the same as absent here
      },
      {
        name = "matching string scalar",
        claims = { role = "admin" },
        configured_value = "admin",
        allow_family = "allow",
        deny_family = "reject",
      },
      {
        name = "mismatched string scalar",
        claims = { role = "user" },
        configured_value = "admin",
        allow_family = "reject",
        deny_family = "allow",
      },
      {
        name = "matching value as a JSON number compared against a string operand",
        claims_json = '{"role": 911}',
        configured_value = "911",
        allow_family = "allow", -- tostring() coercion: 911 == "911"
        deny_family = "reject",
      },
      {
        name = "value wrapped in an array (type/shape bypass attempt)",
        claims = { role = { "admin" } },
        configured_value = "admin",
        allow_family = "reject", -- a table never equals a scalar
        deny_family = "reject",  -- security fix: table shape fails closed rather than silently passing
      },
      {
        name = "value wrapped in an object (type/shape bypass attempt)",
        claims = { role = { nested = "admin" } },
        configured_value = "admin",
        allow_family = "reject",
        deny_family = "reject",  -- same table-shape guard, regardless of array vs object
      },
      {
        name = "matching value as a JSON boolean compared against a string operand",
        claims_json = '{"role": true}',
        configured_value = "true",
        allow_family = "allow", -- tostring() coercion: true == "true"
        deny_family = "reject",
      },
      {
        name = "mismatched JSON boolean",
        claims_json = '{"role": false}',
        configured_value = "true",
        allow_family = "reject",
        deny_family = "allow",
      },
    }

    for _, shape in ipairs(role_shapes) do
      describe(shape.name, function()
        for _, op in ipairs(scalar_operators) do
          local expected = shape[op.family]

          it(op.name .. " -> expect " .. expected, function()
            if shape.claims_json then
              set_verified_token_raw(shape.claims_json)
            else
              set_jwt_claims(shape.claims)
            end

            plugin:access(make_config({ make_claim(op.make(shape.configured_value)) }))

            if expected == "allow" then
              assert_allowed()
            else
              assert_rejected("role")
            end
          end)
        end
      end)
    end

    -- Every contains-family operator (contains, does_not_contain,
    -- contains_one_of, contains_none_of) crossed against every JSON
    -- shape a `groups` claim could realistically take. Unlike the
    -- scalar operators above, a shape that isn't a real JSON array
    -- (missing/null/scalar/object-masquerading-as-array) is rejected
    -- for BOTH families -- these operators only make sense against an
    -- array, so an unexpected shape fails closed either way.
    local contains_operators = {
      { name = "contains", family = "allow_family",
        make = function(v) return { path = "groups", contains = v } end },
      { name = "does_not_contain", family = "deny_family",
        make = function(v) return { path = "groups", does_not_contain = v } end },
      { name = "contains_one_of", family = "allow_family",
        make = function(v) return { path = "groups", contains_one_of = { v, "unrelated-value" } } end },
      { name = "contains_none_of", family = "deny_family",
        make = function(v) return { path = "groups", contains_none_of = { v, "unrelated-value" } } end },
    }

    local groups_shapes = {
      {
        name = "missing claim (path absent, but the token itself is verified)",
        claims = {},
        configured_value = "admin",
        allow_family = "reject",
        deny_family = "reject", -- not an array -> fails closed for both families
      },
      {
        name = "explicit JSON null",
        claims_json = '{"groups": null}',
        configured_value = "admin",
        allow_family = "reject",
        deny_family = "reject",
      },
      {
        name = "string scalar instead of an array",
        claims = { groups = "admin" },
        configured_value = "admin",
        allow_family = "reject",
        deny_family = "reject",
      },
      {
        name = "number scalar instead of an array",
        claims_json = '{"groups": 911}',
        configured_value = "911",
        allow_family = "reject",
        deny_family = "reject",
      },
      {
        name = "JSON object masquerading as an array",
        claims = { groups = { ["0"] = "admin" } },
        configured_value = "admin",
        allow_family = "reject", -- security fix: shape check, not just "is it a table"
        deny_family = "reject",
      },
      {
        name = "proper array containing the value",
        claims = { groups = { "admin", "user" } },
        configured_value = "admin",
        allow_family = "allow",
        deny_family = "reject",
      },
      {
        name = "proper array not containing the value",
        claims = { groups = { "user", "guest" } },
        configured_value = "admin",
        allow_family = "reject",
        deny_family = "allow",
      },
      {
        name = "proper array containing the value as a different JSON type (type coercion)",
        claims_json = '{"groups": [911]}',
        configured_value = "911",
        allow_family = "allow", -- security fix: 911 == "911" via tostring()
        deny_family = "reject",
      },
      {
        name = "proper array containing the value alongside an unrelated nested array element",
        claims = { groups = { "admin", { "nested" } } },
        configured_value = "admin",
        allow_family = "allow", -- the nested element is safely skipped, not compared raw
        deny_family = "reject",
      },
      {
        name = "proper array containing a null element but not the configured value",
        claims_json = '{"groups": [null, "user"]}',
        configured_value = "admin",
        allow_family = "reject", -- the null element is safely skipped, not a crash
        deny_family = "allow",
      },
      {
        name = "empty array (a real array with zero elements)",
        claims_json = '{"groups": []}',
        configured_value = "admin",
        allow_family = "reject", -- valid array shape, but nothing in it can match
        deny_family = "allow",   -- valid array shape, so it fails closed on shape but passes on membership
      },
      {
        name = "proper array containing the value as a JSON boolean compared against a string operand",
        claims_json = '{"groups": [true, "user"]}',
        configured_value = "true",
        allow_family = "allow", -- tostring() coercion: true == "true"
        deny_family = "reject",
      },
    }

    for _, shape in ipairs(groups_shapes) do
      describe(shape.name, function()
        for _, op in ipairs(contains_operators) do
          local expected = shape[op.family]

          it(op.name .. " -> expect " .. expected, function()
            if shape.claims_json then
              set_verified_token_raw(shape.claims_json)
            else
              set_jwt_claims(shape.claims)
            end

            plugin:access(make_config({ make_claim(op.make(shape.configured_value)) }))

            if expected == "allow" then
              assert_allowed()
            else
              assert_rejected("groups")
            end
          end)
        end
      end)
    end

  end)

  -- Regression coverage for a tostring()-coercion bypass: JSON 1.0 decodes
  -- to Lua number 1, and tostring(1) is "1", not "1.0". A comparator that
  -- stringifies the JWT-side value before comparing would therefore let
  -- does_not_equal/equals_none_of pass a forbidden value of "1.0" straight
  -- through. The fix compares numerically on both sides instead.
  describe("numeric comparisons are precision/format-aware, not string-formatting-aware", function()

    it("does_not_equal rejects a forbidden float value even when the claim encodes it without a fractional part", function()
      set_verified_token_raw('{"role": 1.0}')

      plugin:access(make_config({
        make_claim({ path = "role", does_not_equal = "1.0" }),
      }))

      assert_rejected("role")
    end)

    it("equals_none_of rejects a forbidden float value even when the claim encodes it without a fractional part", function()
      set_verified_token_raw('{"role": 1.0}')

      plugin:access(make_config({
        make_claim({ path = "role", equals_none_of = { "1.0" } }),
      }))

      assert_rejected("role")
    end)

    it("equals allows a float-configured value to match a claim encoded without a fractional part", function()
      set_verified_token_raw('{"role": 1}')

      plugin:access(make_config({
        make_claim({ path = "role", equals = "1.0" }),
      }))

      assert_allowed()
    end)

    it("equals_one_of allows a differently-formatted numeric match (scientific notation vs plain)", function()
      set_verified_token_raw('{"role": 100}')

      plugin:access(make_config({
        make_claim({ path = "role", equals_one_of = { "1e2" } }),
      }))

      assert_allowed()
    end)

    it("does_not_equal still rejects a matching integer value (no regression on the common case)", function()
      set_jwt_claims({ role = 911 })

      plugin:access(make_config({
        make_claim({ path = "role", does_not_equal = "911" }),
      }))

      assert_rejected("role")
    end)

    it("does_not_equal allows a fractional claim value that differs from the forbidden one", function()
      set_verified_token_raw('{"role": 1.1}')

      plugin:access(make_config({
        make_claim({ path = "role", does_not_equal = "1.2" }),
      }))

      assert_allowed()
    end)

    it("does_not_equal rejects a fractional claim value that exactly matches the forbidden one", function()
      set_verified_token_raw('{"role": 1.2}')

      plugin:access(make_config({
        make_claim({ path = "role", does_not_equal = "1.2" }),
      }))

      assert_rejected("role")
    end)

    it("equals rejects when the claim is numeric but the configured value isn't a valid number", function()
      set_jwt_claims({ role = 911 })

      plugin:access(make_config({
        make_claim({ path = "role", equals = "admin" }),
      }))

      assert_rejected("role")
    end)

  end)

  -- Lua/LuaJIT numbers are always IEEE-754 doubles, exact only up to 2^53.
  -- Beyond that, distinct decimal integers can round to the same double,
  -- so a numeric comparison can match a value that isn't really the one
  -- configured -- this can only happen when the issuer sends the claim as
  -- a JSON number; a JSON string claim is compared exactly and never hits
  -- this code path. There's no fix for the collision itself (the precision
  -- is already lost by the time cjson hands us a Lua number), so this only
  -- covers the warning meant to surface the condition to operators.
  describe("numeric comparisons beyond safe integer precision (2^53) log a warning", function()

    it("does not warn for an ordinary small numeric comparison", function()
      set_jwt_claims({ org_id = 42 })

      plugin:access(make_config({
        make_claim({ path = "org_id", equals = "42" }),
      }))

      assert_allowed()
      assert.are.equal(0, #recorded.warnings)
    end)

    it("warns when a claim value beyond 2^53 is compared, and documents that distinct large integers can still match", function()
      set_verified_token_raw('{"org_id": 9007199254740993}')

      plugin:access(make_config({
        make_claim({ path = "org_id", equals = "9007199254740992" }),
      }))

      -- Both values round to the same double, so the match "succeeds" --
      -- the point of this test is the warning, not the match itself.
      assert_allowed()
      assert.are.equal(1, #recorded.warnings)
    end)

    it("warns for a does_not_equal deny rule too, since the collision risk is the same", function()
      set_verified_token_raw('{"org_id": 9007199254740993}')

      plugin:access(make_config({
        make_claim({ path = "org_id", does_not_equal = "1" }),
      }))

      assert_allowed()
      assert.are.equal(1, #recorded.warnings)
    end)

    it("does not warn when the large identifier is sent as a JSON string instead of a number", function()
      set_jwt_claims({ org_id = "9007199254740993" })

      plugin:access(make_config({
        make_claim({ path = "org_id", equals = "9007199254740993" }),
      }))

      assert_allowed()
      assert.are.equal(0, #recorded.warnings)
    end)

  end)

  describe("multi-value list operators check every configured element, not just the first", function()

    it("equals_one_of allows when the claim matches the second configured value", function()
      set_jwt_claims({ role = "admin" })

      plugin:access(make_config({
        make_claim({ path = "role", equals_one_of = { "unrelated-value", "admin" } }),
      }))

      assert_allowed()
    end)

    it("equals_none_of rejects when the claim matches the second configured value", function()
      set_jwt_claims({ role = "admin" })

      plugin:access(make_config({
        make_claim({ path = "role", equals_none_of = { "unrelated-value", "admin" } }),
      }))

      assert_rejected("role")
    end)

    it("contains_one_of allows when the claim matches the second configured value", function()
      set_jwt_claims({ groups = { "admin" } })

      plugin:access(make_config({
        make_claim({ path = "groups", contains_one_of = { "unrelated-value", "admin" } }),
      }))

      assert_allowed()
    end)

    it("contains_none_of rejects when the claim matches the second configured value", function()
      set_jwt_claims({ groups = { "admin" } })

      plugin:access(make_config({
        make_claim({ path = "groups", contains_none_of = { "unrelated-value", "admin" } }),
      }))

      assert_rejected("groups")
    end)

  end)

  describe("continue_on_error interaction with a valid, successfully verified token", function()

    it("continue_on_error = false does not interfere when the token verifies and decodes cleanly", function()
      set_jwt_claims({ role = "admin" })

      plugin:access(make_config(
        { make_claim({ path = "role", equals = "admin" }) },
        { continue_on_error = false }
      ))

      assert_allowed()
    end)

  end)

  describe("dotted-path traversal cannot index into a JSON array by position", function()

    it("documents current behavior: a numeric path segment does not reach an array element", function()
      set_jwt_claims({ items = { "a", "b" } })

      -- allow_undefined: true here so this test isolates the path-
      -- traversal behavior specifically -- otherwise the claim resolving
      -- to nil would be caught by the required-claim-missing rejection
      -- (see "output_header value forwarding" describe block) instead.
      plugin:access(make_config({
        make_claim({ path = "items.0", output_header = "X-Item", allow_undefined = true }),
      }))

      assert_allowed()
      assert.are.equal("", header_value("X-Item"))
    end)

  end)

  describe("a plugin instance with no configured claims", function()

    it("is a pure pass-through regardless of whether a token was verified", function()
      set_jwt_claims({ role = "admin" })

      plugin:access(make_config({}))

      assert_allowed()
      assert.are.equal(0, #recorded.headers_set)
    end)

    it("is a pure pass-through when no token was ever verified either", function()
      plugin:access(make_config({}))

      assert_allowed()
      assert.are.equal(0, #recorded.headers_set)
    end)

  end)

end)
