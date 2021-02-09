local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-claims-advanced",
  fields = {
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          -- These 3 params 100% match the JWT plugin for how
          -- the JWT is found in the incoming request, and used
          -- from this plugin in the same way...
          { 
            uri_param_names = {
              type = "set",
              elements = { type = "string" },
              default = { "jwt" },
            },
          },
          {
            header_names = {
            type = "set",
            elements = { type = "string" },
            default = { "authorization" },
            },
          },
          {
            cookie_names = {
              type = "set",
              elements = { type = "string" },
              default = {}
            },
          },
          -- These params are the new ones for this plugin...
          {
            continue_on_error = {
              type = "boolean",
              default = true
            },
          },
          {
            claims = {
              type = "array",
              default = {},
              elements = {
                type = "record",
                fields = {
                  {
                    -- Path to the claim in the JWT payload
                    -- Example: custom.path.to.item
                    path = {
                      type = "string",
                      --required: true,
                    },
                  },

                  {
                    -- Example: X-MyHeader
                    output_header = {
                      type = "string",
                    },
                  },
                  -- This claim (array/table) must contain the value specified with the "contains" param
                  {
                    contains = {
                      type = "string",
                    },
                  },
                  -- This claim (array/table) must contain at least ONE of the values specified with the "contains_one_of" param
                  {
                    contains_one_of = {
                      type = "array",
                      elements = {
                        type = "string",
                      },
                      default = {},
                    },
                  },
                  -- This claim must match the value specified with the "equals" param
                  {
                    equals = {
                      type = "string",
                    },
                  },
                  -- This claim must match at least ONE of the values specified with the "equals_one_of" param
                  {
                    equals_one_of = {
                      type = "array",
                      elements = {
                        type = "string",
                      },
                      default = {},
                    },
                  },
                },
                entity_checks = {
                  {
                    at_least_one_of = { "output_header", "contains", "contains_one_of", "equals", "equals_one_of" },
                  },
                },
              },
            },
          },
        },
      },
    },
  }
}
