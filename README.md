# kong-plugin-jwt-claims-advanced

Kong plugin to check JWT payload claims in various ways, and/or forward them as headers to your upstream services.

## Problem Being Solved

This plugin was created to overcome the shortcomings of the publicly available jwt-claims-headers and jwt-claims-checks kong plugins.  Projects sometimes have a need to allow for checking nested structures that can be found in a JWT, as well as the ability to forward particular items from the JWT payload as headers upstream from kong.

This plugin was created to satisfy those needs.

*NOTE: THIS PLUGIN IS NOT A REPLACEMENT FOR THE OFFICIAL KONG JWT PLUGIN.  IT IS MEANT TO AUGMENT, NOT REPLACE!!!*

## Compatibility

This plugin is compatible with Kong 2.3.x.

## Installation

TODO: Add specific instructions

Follow the instructions for installing kong plugins found [here](https://docs.konghq.com/2.3.x/plugin-development/distribution/).

## Configuring Kong to use this Plugin

The configurations shown here are for the jwt-claims-advanced plugin ONLY, and assumes that you already have the official kong JWT plugin installed, and configured to your needs.

Consider the following JWT data from a decoded token...

``` jsonc
{
  // Payload data format can be totally arbitrary to your needs.  This example is meant to demonstrate the capabilities of the jwt-claims-advanced plugin
  "jti": "some-unique-id",
  "requestor": {
    "id": "you-are-number-6",
    "groups": [
      "admin-grp",
      "sales-grp",
      "developer-grp",
      "customer-grp"
    ],
    "meta": {
      "what": "eva"
    }
  },
  // NOTE: The official kong JWT plugin enforces the rule that the issuer MUST match what is configured under the jwt_secrets.key config.
  "iss": "eddie-was-here",
  // NOTE: The official kong JWT plugin automatically checks the expiration
  "exp": 100353266160
}

```

Here is a sample configuration that can do som additional claims checks above and beyond what the official Kong JWT plugin can...

```yaml

# Your exising kong routes/services...
services:
- name: service1
  url: http://myapp:3000
  routes:
  - name: service1_main
    paths:
    - /
    strip_path: false
    preserve_host: true

plugins:
# You must have the JWT plugin installed, and configured here, as
# jwt-claims-advanced is NOT a replacement for the kong JWT plugin...
- name: jwt
  service: service1
- name: jwt-claims-advanced
  service: service1
  config:
    # If the JWT's configs for header_names, cookie_names, or uri_param_names are customized above, then this plugin needs to be configured to match, as it finds the JWT in the same way the official JWT plugin does, but cannot access those configs, so we need them duplicated here if customized.
    claims:
    - path: requestor
      output_header: X-JWT-Requestor
    - path: requestor.id
      output_header: X-JWT-Requestor-ID
    - path: exp
      output_header: X-JWT-Expires-At
    - path: requestor.groups
      contains: developer-grp
      output_header: X-JWT-Requestor-Groups
      allow_undefined: false
    - path: nonexistant_claim
      output_header: X-JWT-Nonexistant-Claim
      allow_undefined: true

```

## Configuration Options

The below examples assume the JWT is in the format as previously described above.

### path (required)

This configuration is required, and describes the path of the item found within the decoded JWT's data structure.

Examples:

| path             | evaluates to (in above JWT example)  |
|------------------|--------------------------------------|
| requestor.id     | you-are-number-6                     |
| requestor        | { "id": "you-are-number-6", "groups": [ "admin-grp", "sales-grp", "developer-grp", "customer-grp" ], "meta": { "what": "eva" } } |
| requestor.groups | [ "admin-grp", "sales-grp", "developer-grp", "customer-grp" ] |
| requestor.meta   | { "what": "eva" } |
| exp              | 100353266160                         |

### output_header (optional)

Any node/element of the JWT can be output in the HTTP headers to be sent to your upstream service.  If you look at the above kong configuration...that would result in the following HTTP headers being sent upstream to your service...

```
  X-JWT-Requestor-ID: you-are-number-6
  X-JWT-Requestor: { "id": "you-are-number-6", "groups": [ "admin-grp", "sales-grp", "developer-grp", "customer-grp" ], "meta": { "what": "eva" } }
  X-JWT-Requestor-Groups: [ "admin-grp", "sales-grp", "developer-grp", "customer-grp" ]
  X-JWT-Expires-At: 100353266160
  X-JWT-Nonexistant-Claim: ""

```

### allow_undefined (optional)

Values can be either true or false (false is the default). When this option is enabled it will set the value of HTTP header for this claim to an empty string if the claim doesn't exist or is holding a value of undefined or null. If not, then the claim is required and should be part of the payload

### equals

Checks the string/number value at the location specified by path to make sure it equals the value given in this configuration.  If it does not, then processing stops, and a 403/unauthorized is returned out.

### does_not_equal

Checks the string/number value at the location specified by path to make sure it does not equal the value given in this configuration.  If it does, then processing stops, and a 403/unauthorized is returned out.

### equals_one_of

Checks the string/number value at the location specified by path to make sure it equals one of the given values in this configuration.  If it does not, then processing stops, and a 403/unauthorized is returned out.

### equals_none_of

Checks the string/number value at the location specified by path to make sure it does not equal any of the given values in this configuration.  If it does, then processing stops, and a 403/unauthorized is returned out.

### contains

Checks the array at the given location specified by path to make sure that it has an element that is equal to the given value in this configuration.  If it does not, then processing stops, and a 403/unauthorized is returned out.

### does_not_contain

Checks the array at the given location specified by path to make sure that it has no element that is equal to the given value in this configuration.  If it does, then processing stops, and a 403/unauthorized is returned out.

### contains_one_of

Checks the array at the given location specified by path to make sure that it has an element that is equal to one of the given values in this configuration.  If it does not, then processing stops, and a 403/unauthorized is returned out.

### contains_none_of

Checks the array at the given location specified by path to make sure that it has no element that is equal to any of the given values in this configuration.  If it does, then processing stops, and a 403/unauthorized is returned out.

## Running Tests

Tests are written using [busted](https://lunarmodules.github.io/busted/), the standard test framework used across Kong plugins. They stub the minimal Kong PDK surface (`kong.*`, `ngx.*`) and the `kong.plugins.jwt.jwt_parser` module so `handler.lua` can be exercised directly, without a full Kong install.

Install the tooling (once):

```
luarocks install busted
luarocks install lua-cjson
```

Run the test suite from the repo root:

```
make test
```

## Building the Rock

There are two build targets, for two different purposes:

- `make local-build` -- builds straight from your working tree (via `luarocks make`), with no git fetch involved. Use this while developing, to sanity-check that the rockspec/build table still works, before you've tagged anything.
- `make build` -- the release build (via `luarocks build`). This fetches source from the git tag referenced in the rockspec's `source.url`/`source.tag` fields, so it only works once that tag has been pushed to the remote. This is the reproducible build anyone (CI, another dev, luarocks.org) would get if they built this same version later -- see "Releasing a New Version" below.

## Releasing a New Version

**Only ever tag on `main`, and only after the version-bump changes have actually landed there.** The rockspec's `source.tag` points at a specific commit on the upstream remote, so tagging a feature branch (or tagging before the PR is merged) means the tag doesn't point at the commit `main` actually ends up with -- `make build` (and anyone else building this version later) would fetch the wrong source, or fail if the branch is later deleted.

1. Decide on the new version number, e.g. `0.5-0`.
2. On your feature branch, rename the rockspec to match: `git mv kong-plugin-jwt-claims-advanced-<old>.rockspec kong-plugin-jwt-claims-advanced-<new>.rockspec`.
3. Update the `version` and `source.tag` fields inside the renamed rockspec to match (e.g. `version = "0.5-0"`, `tag = "v0.5-0"`).
4. Run `make test` and `make local-build` to confirm everything still works.
5. Commit the version bump and open a PR against `main` as usual (do **not** tag yet).
6. Once the PR is reviewed and merged into `main`, switch to `main` and pull the merge commit: `git checkout main && git pull`.
7. Tag that commit on `main` to match the rockspec version exactly: `git tag v0.5-0`.
8. Push the tag: `git push origin v0.5-0`.
9. Build the release rock from that tag: `make build`.
10. (Optional) Publish the rock -- e.g. `luarocks upload kong-plugin-jwt-claims-advanced-0.5-0.rockspec` if publishing to luarocks.org, or attach the packed `.rock` file to a GitHub release.

## Notes

- Building/releasing: see "Building the Rock" and "Releasing a New Version" above.
