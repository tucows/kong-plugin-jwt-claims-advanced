package = "kong-plugin-jwt-claims-advanced"
version = "0.2-0"
description = {
  summary = "A Kong plugin to allow custom JWT claims/values checking, validation, and forwarding as custom HTTP headers.",
  license = "Apache 2.0",
}
dependencies = {
  "lua ~> 5.1"
}
source = {
  url = "git+https://github.com/tucows/kong-plugin-jwt-claims-advanced.git",
  tag = "v0.2-0"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-claims-advanced.handler"] = "handler.lua",
    ["kong.plugins.jwt-claims-advanced.schema"] = "schema.lua"
  }
}

