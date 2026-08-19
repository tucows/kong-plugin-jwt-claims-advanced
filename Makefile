.PHONY: test build local-build

test:
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
