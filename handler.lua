local constants = require("kong.constants")
local jwt_decoder = require("kong.plugins.jwt.jwt_parser")
local re_gmatch = ngx.re.gmatch
local json = require("cjson")
local kong = kong

-- Note: The jwt plugin's priority is 1005, so making our priority lower ensures
-- that the JWT plugin handles checking validity of the JWT token before we work
-- with the parsed payload.
local JWTClaimsHeaderExtHandler = {
	VERSION = "1.1.0",
	PRIORITY = 999,
}

---- A modified version of the one found in kong.plugin.jwt because
---- we cannot access the original retrieve_token() declared as local
---- to that plugin...
--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the configured header_names (defaults to `[Authorization]`).
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(conf)
	local args = kong.request.get_query()

	for _, v in ipairs(conf.uri_param_names) do
		if args[v] then
			return args[v]
		end
	end

	local var = ngx.var
	for _, v in ipairs(conf.cookie_names) do
		local cookie = var["cookie_" .. v]
		if cookie and cookie ~= "" then
			return cookie
		end
	end

	local request_headers = kong.request.get_headers()
	for _, v in ipairs(conf.header_names) do
		local token_header = request_headers[v]
		if token_header then
			if type(token_header) == "table" then
				token_header = token_header[1]
			end
			local iterator, iter_err = re_gmatch(token_header, "\\s*[Bb]earer\\s+(.+)")
			if not iterator then
				kong.log.err(iter_err)
				break
			end

			local m, err = iterator()
			if err then
				kong.log.err(err)
				break
			end

			if m and #m > 0 then
				return m[1]
			end
		end
	end
end

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
		node = string.sub(path, 1, pos - 1)
		path = string.sub(path, pos + 1)
	end

	-- Grab the item
	local item = t[node]
	if (path ~= nil) and (type(item) == "table") then
		return extract_table_item(item, path)
	elseif path == nil then
		return item
	end

	return nil
end

-- Retrieve the fully decoded JWT as provided in the incoming request
-- @param config Plugin configuration
-- @return decoded_jwt object (can be a table) or nil
-- @return err
local function get_jwt_decoded(config)
	local token, err = retrieve_token(config)
	if err and not config.continue_on_error then
		return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
	end

	if token == nil then
		return {}, "Token could not be retrieved"
	end

	local decoded_jwt, err = jwt_decoder:new(token)
	return decoded_jwt, err
end

local function table_contains_value(t, value)
	for idx, val in ipairs(t) do
		if val == value then
			return true
		end
	end

	return false
end

local function unauthorized_due_to_failed_claim(claim_name, failure_reason)
	if failure_reason == nil then
		failure_reason = "(unspecified)"
	end
	kong.log.err("Failed claim: " .. claim_name .. ";  reason: " .. failure_reason)
	return kong.response.exit(403, {
		message = "Unauthorized",
		claim_path = claim_name,
	})
end

function JWTClaimsHeaderExtHandler:new()
	JWTClaimsHeaderExtHandler.super.new(self, "jwt-claims-advanced")
end

function JWTClaimsHeaderExtHandler:access(config)
	JWTClaimsHeaderExtHandler.super.access(self)

	-- Find the JWT using the same types of configurations the
	-- main JWT plugin uses, and return the decoded JWT object...
	local decoded_jwt, err = get_jwt_decoded(config)
	if err and not config.continue_on_error then
		return kong.response.exit(500, "Internal server error")
	end

	-- Go through our configured claims, and do what's requested...
	for i, claim_config in ipairs(config.claims) do
		local payload_claim_item = extract_table_item(decoded_jwt.claims, claim_config.path)

		-- Custom claims
		if claim_config.equals ~= nil then
			if tostring(payload_claim_item) ~= tostring(claim_config.equals) then
				return unauthorized_due_to_failed_claim(claim_config.path, "did not equal " .. claim_config.equals)
			end
		end
		if claim_config.does_not_equal ~= nil then
			if tostring(payload_claim_item) == tostring(claim_config.does_not_equal) then
				return unauthorized_due_to_failed_claim(
					claim_config.path,
					"was equal to " .. claim_config.does_not_equal
				)
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
				return unauthorized_due_to_failed_claim(
					claim_config.path,
					"did not equal one of " .. table.concat(claim_config.equals_one_of, "; ")
				)
			end
		end
		if #claim_config.equals_none_of ~= 0 then
			local match = false
			local check_count = 0
			for ei, ev in ipairs(claim_config.equals_none_of) do
				if tostring(payload_claim_item) == tostring(ev) then
					match = true
				end
				check_count = check_count + 1
			end
			if match and check_count > 0 then
				return unauthorized_due_to_failed_claim(
					claim_config.path,
					"was equal to one of " .. table.concat(claim_config.equals_none_of, "; ")
				)
			end
		end
		if claim_config.contains ~= nil then
			if type(payload_claim_item) ~= "table" then
				return unauthorized_due_to_failed_claim(claim_config.path, "not a table")
			elseif not table_contains_value(payload_claim_item, claim_config.contains) then
				return unauthorized_due_to_failed_claim(claim_config.path, "does not contain " .. claim_config.contains)
			end
		end
		if claim_config.does_not_contain ~= nil then
			if type(payload_claim_item) ~= "table" then
				return unauthorized_due_to_failed_claim(claim_config.path, "not a table")
			elseif table_contains_value(payload_claim_item, claim_config.does_not_contain) then
				return unauthorized_due_to_failed_claim(claim_config.path, "contains " .. claim_config.does_not_contain)
			end
		end
		if #claim_config.contains_one_of ~= 0 then
			if type(payload_claim_item) ~= "table" then
				return unauthorized_due_to_failed_claim(claim_config.path, "not a table")
			else
				local match = false
				local check_count = 0
				for ci, cv in ipairs(claim_config.contains_one_of) do
					if table_contains_value(payload_claim_item, cv) then
						match = true
					end
					check_count = check_count + 1
				end
				if not match and check_count > 0 then
					return unauthorized_due_to_failed_claim(
						claim_config.path,
						"does not contain one of " .. table.concat(claim_config.contains_one_of, "; ")
					)
				end
			end
		end
		if #claim_config.contains_none_of ~= 0 then
			if type(payload_claim_item) ~= "table" then
				return unauthorized_due_to_failed_claim(claim_config.path, "not a table")
			else
				local match = false
				local check_count = 0
				for ci, cv in ipairs(claim_config.contains_none_of) do
					if table_contains_value(payload_claim_item, cv) then
						match = true
					end
					check_count = check_count + 1
				end
				if match and check_count > 0 then
					return unauthorized_due_to_failed_claim(
						claim_config.path,
						"contains one of " .. table.concat(claim_config.contains_none_of, "; ")
					)
				end
			end
		end

		-- Output in headers...
		if claim_config.output_header ~= nil then
			local payload_claim_item_as_text = payload_claim_item
			if type(payload_claim_item) == "table" then
				payload_claim_item_as_text = json.encode(payload_claim_item)
			end
			ngx.req.set_header(claim_config.output_header, payload_claim_item_as_text)
		end
	end
end

return JWTClaimsHeaderExtHandler
