.PHONY: test build local-build dependencies

UNAME_S := $(shell uname -s)

# Installs the tooling needed to run the test suite (lua/luarocks via the
# platform package manager, then the busted/lua-cjson rocks). Safe to run
# repeatedly - each step is a no-op if already satisfied.
dependencies:
ifeq ($(UNAME_S),Darwin)
	@command -v luarocks >/dev/null 2>&1 || brew install lua luarocks
else
	@command -v luarocks >/dev/null 2>&1 || (sudo apt-get update && sudo apt-get install -y lua5.1 luarocks)
endif
	@luarocks show busted >/dev/null 2>&1 || luarocks install --local busted
	@luarocks show lua-cjson >/dev/null 2>&1 || luarocks install --local lua-cjson

test: dependencies
	@busted spec/

# Release build: fetches source from the git tag referenced in the
# rockspec (source.url/source.tag). Requires that tag to already exist
# on the remote - see the "Releasing a New Version" section in the
# README before running this.
build:
	@luarocks build --local --pack-binary-rock kong-plugin-jwt-claims-advanced-*.rockspec

# Local/dev build: builds straight from the working tree, no git fetch.
# Use this to sanity-check the rockspec/build table before tagging a
# release.
local-build:
	@luarocks make --local --pack-binary-rock kong-plugin-jwt-claims-advanced-*.rockspec
