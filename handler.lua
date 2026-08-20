local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local json = require "cjson"
local kong = kong

local plugin = {
  VERSION = "1.0.1",
  -- Note: The jwt plugin's priority is 1005, so making our priority lower ensures
  -- that the JWT plugin handles checking validity of the JWT token before we work
  -- with the parsed payload.
  PRIORITY = 999,
}


-- Traverses a table, and returns the item nested within based
-- on the path given.  path is expected to be in dotted notation.
-- Example:
--   local t = { thing1 = { sub_thing = "111" }, thing2 = { sub_thing = "222" } }
--   print("::: ".extract_table_item( t, "thing1.sub_thing" ))
-- Displays:
--   ::: 111
-- @param t table to traverse
-- @param path dotted notation to find node in table/tree
-- @return item (nil if item not found)
local function extract_table_item(t, path)

  if t == nil then
    return nil
  end

  -- Grab the path part up to the first dot
  local pos = string.find(path, "%.")
  local node = nil
  if pos == nil then
    node = path
    path = nil
  else
    node = string.sub(path, 1, pos-1)
    path = string.sub(path, pos+1)
  end

  -- Grab the item
  local item = t[node]
  if ( path ~= nil ) and ( type(item) == "table" ) then
    return extract_table_item(item, path)
  elseif ( path == nil ) then
    return item
  end

  return nil

end


-- Retrieve the fully decoded JWT that the official kong jwt plugin already
-- verified for this request. kong.ctx.shared.authenticated_jwt_token is
-- only ever set (see set_consumer() in kong/plugins/jwt/handler.lua) after
-- a successful signature verification -- it stays nil on the jwt plugin's
-- anonymous-consumer fallback, when run_on_preflight skips verification,
-- or if the jwt plugin never ran. Reading it here, rather than
-- independently re-locating and decoding a token ourselves, ensures this
-- plugin only ever evaluates claims from a token that was actually
-- verified, and that it's the same token the jwt plugin verified.
-- @return decoded_jwt object (can be a table) or nil
-- @return err
local function get_jwt_decoded()

  local token = kong.ctx.shared.authenticated_jwt_token
  if token == nil then
    return {}, "Token could not be retrieved"
  end

  local decoded_jwt, err = jwt_decoder:new(token)
  if decoded_jwt == nil then
    return {}, err
  end

  return decoded_jwt, err

end


local function table_contains_value (t, value)

  for idx, val in ipairs(t) do
    if type(val) ~= "table" and tostring(val) == tostring(value) then
      return true
    end
  end

  return false
end

-- A JSON array decodes to a Lua table whose keys are exactly 1..#t.
-- A JSON object (e.g. {"0": "x"}) does not satisfy this, even though
-- both are Lua tables -- the contains-family operators only make sense
-- against the former.
local function is_json_array (t)

  local pairs_count = 0
  for _ in pairs(t) do
    pairs_count = pairs_count + 1
  end

  local ipairs_count = 0
  for _ in ipairs(t) do
    ipairs_count = ipairs_count + 1
  end

  return pairs_count == ipairs_count
end

local function unauthorized_due_to_failed_claim(claim_name, failure_reason)
  if failure_reason == nil then
    failure_reason = "(unspecified)"
  end
  kong.log.err("Failed claim: "..claim_name..";  reason: "..failure_reason)
  return kong.response.exit(403, {
    message = "Unauthorized",
    claim_path = claim_name,
  })
end


function plugin:access(config)

  -- Use the token the official jwt plugin already verified for this
  -- request, and return the decoded JWT object...
  local decoded_jwt, err = get_jwt_decoded()
  if err and not config.continue_on_error then
    return kong.response.exit(500, "Internal server error")
  end

  -- No verified token was available for this request at all (err set),
  -- as opposed to a token being available but this particular claim path
  -- being absent from it. A deny-list rule must never be satisfied by
  -- the absence of any verifiable claims data whatsoever.
  local no_verified_claims = (err ~= nil)

  -- Go through our configured claims, and do what's requested...
  for i, claim_config in ipairs(config.claims) do

    local payload_claim_item = extract_table_item( decoded_jwt.claims, claim_config.path )

    -- Custom claims
    if claim_config.equals ~= nil then
      if tostring(payload_claim_item) ~= tostring(claim_config.equals) then
        return unauthorized_due_to_failed_claim(claim_config.path, "did not equal "..claim_config.equals)
      end
    end
    if claim_config.does_not_equal ~= nil then
      if no_verified_claims or type(payload_claim_item) == "table" or tostring(payload_claim_item) == tostring(claim_config.does_not_equal) then
        return unauthorized_due_to_failed_claim(claim_config.path, "was equal to "..claim_config.does_not_equal.." or was an unexpected table/array shape or no verified token was available")
      end
    end
    if #claim_config.equals_one_of ~= 0 then
      local match = false
      local check_count = 0
      for ei, ev in ipairs(claim_config.equals_one_of) do
        if tostring(payload_claim_item) == tostring(ev) then
          match = true
        end
        check_count = check_count + 1
      end
      if not match and check_count > 0 then
        return unauthorized_due_to_failed_claim(claim_config.path, "did not equal one of "..table.concat(claim_config.equals_one_of, "; "))
      end
    end
    if #claim_config.equals_none_of ~= 0 then
      local match = false
      local check_count = 0
      if no_verified_claims or type(payload_claim_item) == "table" then
        match = true
      end
      for ei, ev in ipairs(claim_config.equals_none_of) do
        if tostring(payload_claim_item) == tostring(ev) then
          match = true
        end
        check_count = check_count + 1
      end
      if match and check_count > 0 then
        return unauthorized_due_to_failed_claim(claim_config.path, "was equal to one of "..table.concat(claim_config.equals_none_of, "; "))
      end
    end
    if claim_config.contains ~= nil then
      if type(payload_claim_item) ~= "table" or not is_json_array(payload_claim_item) then
        return unauthorized_due_to_failed_claim(claim_config.path, "not an array")
      elseif not table_contains_value(payload_claim_item,claim_config.contains) then
        return unauthorized_due_to_failed_claim(claim_config.path, "does not contain "..claim_config.contains)
      end
    end
    if claim_config.does_not_contain ~= nil then
      if type(payload_claim_item) ~= "table" or not is_json_array(payload_claim_item) then
        return unauthorized_due_to_failed_claim(claim_config.path, "not an array")
      elseif table_contains_value(payload_claim_item,claim_config.does_not_contain) then
        return unauthorized_due_to_failed_claim(claim_config.path, "contains "..claim_config.does_not_contain)
      end
    end
    if #claim_config.contains_one_of ~= 0 then
      if type(payload_claim_item) ~= "table" or not is_json_array(payload_claim_item) then
        return unauthorized_due_to_failed_claim(claim_config.path, "not an array")
      else
        local match = false
        local check_count = 0
        for ci, cv in ipairs(claim_config.contains_one_of) do
          if table_contains_value(payload_claim_item,cv) then
            match = true
          end
          check_count = check_count + 1
        end
        if not match and check_count > 0 then
          return unauthorized_due_to_failed_claim(claim_config.path, "does not contain one of "..table.concat(claim_config.contains_one_of, "; "))
        end
      end
    end
    if #claim_config.contains_none_of ~= 0 then
      if type(payload_claim_item) ~= "table" or not is_json_array(payload_claim_item) then
        return unauthorized_due_to_failed_claim(claim_config.path, "not an array")
      else
        local match = false
        local check_count = 0
        for ci, cv in ipairs(claim_config.contains_none_of) do
          if table_contains_value(payload_claim_item,cv) then
            match = true
          end
          check_count = check_count + 1
        end
        if match and check_count > 0 then
          return unauthorized_due_to_failed_claim(claim_config.path, "contains one of "..table.concat(claim_config.contains_none_of, "; "))
        end
      end
    end

    -- Output in headers...
    if claim_config.output_header ~= nil then
      if payload_claim_item == nil or payload_claim_item == json.null then
        if claim_config.allow_undefined then
          kong.service.request.set_header(claim_config.output_header, "")
        else
          -- allow_undefined is false (the default): this claim is
          -- required, per the documented contract, and a nil/null value
          -- is never valid to forward as a header (Kong's PDK rejects
          -- it outright), so treat a required-but-absent claim as a
          -- failed claim rather than crashing or silently proceeding.
          return unauthorized_due_to_failed_claim(claim_config.path, "required claim was missing or null")
        end
      else
        local payload_claim_item_as_text = payload_claim_item
        if type(payload_claim_item) == "table" then
          payload_claim_item_as_text = json.encode(payload_claim_item)
        end
        -- Set header on upstream request
        kong.service.request.set_header(claim_config.output_header, payload_claim_item_as_text)
      end
    end

  end

end

return plugin

