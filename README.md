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

```

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

## Notes

- To build the rock file: `luarocks build --local --pack-binary-rock kong-plugin-jwt-claims-advanced-*.rockspec`
