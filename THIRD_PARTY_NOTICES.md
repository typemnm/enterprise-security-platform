# Third-party dependency notices

This file records dependency versions and declared SPDX license identifiers. It does not change the license of this project; see `LICENSE` for the original product code. Original dependency license and notice files are retained in the Lambda deployment packages. Review those files when redistributing a package.

## Python Lambda runtime

Versions and wheel hashes are pinned in `runtime-requirements.lock.txt`. SPDX identifiers were checked against installed wheel metadata and the corresponding license files.

| Package | Version | SPDX license |
| --- | --- | --- |
| boto3 | 1.43.106 | Apache-2.0 |
| botocore | 1.43.113 | Apache-2.0 |
| jmespath | 1.1.0 | MIT |
| python-dateutil | 2.9.0.post0 | Apache-2.0 OR BSD-3-Clause |
| s3transfer | 0.19.2 | Apache-2.0 |
| six | 1.17.0 | MIT |
| urllib3 | 2.8.0 | MIT |

## Node.js Lambda dashboard

The complete dependency inventory below is derived from `dashboard/package-lock.json`. Nested dependencies and separately pinned versions are listed individually. The lockfile also records each upstream registry archive and integrity digest.

| Package | Version | SPDX license |
| --- | --- | --- |
| @aws-sdk/checksums | 3.1001.3 | Apache-2.0 |
| @aws-sdk/client-dynamodb | 3.1151.0 | Apache-2.0 |
| @aws-sdk/client-lambda | 3.1151.0 | Apache-2.0 |
| @aws-sdk/client-s3 | 3.1151.0 | Apache-2.0 |
| @aws-sdk/client-sfn | 3.1151.0 | Apache-2.0 |
| @aws-sdk/client-wafv2 | 3.1151.0 | Apache-2.0 |
| @aws-sdk/core | 3.978.3 | Apache-2.0 |
| @aws-sdk/credential-provider-env | 3.972.74 | Apache-2.0 |
| @aws-sdk/credential-provider-http | 3.972.76 | Apache-2.0 |
| @aws-sdk/credential-provider-ini | 3.973.19 | Apache-2.0 |
| @aws-sdk/credential-provider-login | 3.972.81 | Apache-2.0 |
| @aws-sdk/credential-provider-node | 3.972.86 | Apache-2.0 |
| @aws-sdk/credential-provider-process | 3.972.74 | Apache-2.0 |
| @aws-sdk/credential-provider-sso | 3.973.18 | Apache-2.0 |
| @aws-sdk/credential-provider-web-identity | 3.972.80 | Apache-2.0 |
| @aws-sdk/dynamodb-codec | 3.973.48 | Apache-2.0 |
| @aws-sdk/endpoint-cache | 3.972.11 | Apache-2.0 |
| @aws-sdk/lib-dynamodb | 3.1151.0 | Apache-2.0 |
| @aws-sdk/middleware-endpoint-discovery | 3.972.32 | Apache-2.0 |
| @aws-sdk/middleware-sdk-s3 | 3.972.79 | Apache-2.0 |
| @aws-sdk/nested-clients | 3.997.48 | Apache-2.0 |
| @aws-sdk/signature-v4-multi-region | 3.996.48 | Apache-2.0 |
| @aws-sdk/token-providers | 3.1150.0 | Apache-2.0 |
| @aws-sdk/types | 3.974.6 | Apache-2.0 |
| @aws-sdk/util-dynamodb | 3.996.9 | Apache-2.0 |
| @aws-sdk/xml-builder | 3.972.41 | Apache-2.0 |
| @aws/lambda-invoke-store | 0.3.0 | Apache-2.0 |
| @codegenie/serverless-express | 5.0.0 | Apache-2.0 |
| @smithy/core | 3.36.0 | Apache-2.0 |
| @smithy/credential-provider-imds | 4.5.2 | Apache-2.0 |
| @smithy/fetch-http-handler | 5.8.0 | Apache-2.0 |
| @smithy/node-http-handler | 4.12.1 | Apache-2.0 |
| @smithy/signature-v4 | 5.7.4 | Apache-2.0 |
| @smithy/types | 4.19.0 | Apache-2.0 |
| accepts | 2.0.0 | MIT |
| body-parser | 2.3.0 | MIT |
| bowser | 2.14.1 | MIT |
| bytes | 3.1.2 | MIT |
| call-bind-apply-helpers | 1.0.2 | MIT |
| call-bound | 1.0.4 | MIT |
| content-disposition | 2.0.1 | MIT |
| content-type | 2.1.0 | MIT |
| cookie | 0.7.2 | MIT |
| cookie-signature | 1.2.2 | MIT |
| dayjs | 1.11.23 | MIT |
| debug | 4.4.3 | MIT |
| deepmerge | 4.3.1 | MIT |
| depd | 2.0.0 | MIT |
| dom-serializer | 3.1.1 | MIT |
| domelementtype | 3.0.0 | BSD-2-Clause |
| domhandler | 6.0.1 | BSD-2-Clause |
| domutils | 4.0.2 | BSD-2-Clause |
| dunder-proto | 1.0.1 | MIT |
| ee-first | 1.1.1 | MIT |
| encodeurl | 2.0.0 | MIT |
| entities | 8.1.0 | BSD-2-Clause |
| es-define-property | 1.0.1 | MIT |
| es-errors | 1.3.0 | MIT |
| es-object-atoms | 1.1.2 | MIT |
| escape-html | 1.0.3 | MIT |
| escape-string-regexp | 4.0.0 | MIT |
| etag | 1.8.1 | MIT |
| express | 5.3.0 | MIT |
| finalhandler | 2.1.1 | MIT |
| forwarded | 0.2.0 | MIT |
| fresh | 2.0.0 | MIT |
| function-bind | 1.1.2 | MIT |
| get-intrinsic | 1.3.0 | MIT |
| get-proto | 1.0.1 | MIT |
| gopd | 1.2.0 | MIT |
| has-symbols | 1.1.0 | MIT |
| hasown | 2.0.4 | MIT |
| htmlparser2 | 12.0.0 | MIT |
| http-errors | 2.0.1 | MIT |
| iconv-lite | 0.7.3 | MIT |
| inherits | 2.0.4 | ISC |
| ipaddr.js | 1.9.1 | MIT |
| ipaddr.js | 2.5.0 | MIT |
| is-plain-object | 5.1.0 | MIT |
| is-promise | 4.0.0 | MIT |
| jose | 6.2.12 | MIT |
| launder | 1.7.2 | MIT |
| marked | 18.1.1 | MIT |
| math-intrinsics | 1.1.0 | MIT |
| media-typer | 1.1.1 | MIT |
| merge-descriptors | 2.0.0 | MIT |
| mime-db | 1.54.0 | MIT |
| mime-types | 3.0.2 | MIT |
| mnemonist | 0.38.3 | MIT |
| ms | 2.1.3 | MIT |
| nanoid | 3.3.20 | MIT |
| negotiator | 1.1.0 | MIT |
| object-inspect | 1.13.4 | MIT |
| obliterator | 1.6.1 | MIT |
| on-finished | 2.4.1 | MIT |
| once | 1.4.0 | ISC |
| parse-srcset | 1.0.2 | MIT |
| parseurl | 1.3.3 | MIT |
| path-to-regexp | 8.4.2 | MIT |
| picocolors | 1.1.1 | ISC |
| postcss | 8.5.30 | MIT |
| proxy-addr | 2.0.8 | MIT |
| qs | 6.16.0 | BSD-3-Clause |
| range-parser | 1.3.0 | MIT |
| raw-body | 3.0.2 | MIT |
| router | 2.2.0 | MIT |
| safer-buffer | 2.1.2 | MIT |
| sanitize-html | 2.18.0 | MIT |
| send | 1.2.1 | MIT |
| serve-static | 2.2.1 | MIT |
| setprototypeof | 1.2.0 | ISC |
| side-channel | 1.1.1 | MIT |
| side-channel-list | 1.0.1 | MIT |
| side-channel-map | 1.0.1 | MIT |
| side-channel-weakmap | 1.0.2 | MIT |
| source-map-js | 1.2.2 | BSD-3-Clause |
| statuses | 2.0.2 | MIT |
| toidentifier | 1.0.1 | MIT |
| tslib | 2.8.1 | 0BSD |
| type-is | 2.1.0 | MIT |
| unpipe | 1.0.0 | MIT |
| vary | 1.1.2 | MIT |
| wrappy | 1.0.2 | ISC |

## Local build and CI tools

These tools validate source and templates. They are not added to the Python Lambda runtime ZIP.

| Tool | Version | SPDX license |
| --- | --- | --- |
| jsonschema | 4.25.1 | MIT |
| cfn-lint | 1.57.2 | MIT-0 |
| actions/checkout | pinned official v6 commit | MIT |
| actions/setup-python | pinned official v6 commit | MIT |
| actions/setup-node | pinned official v6 commit | MIT |
| actions/upload-artifact | pinned official v6 commit | MIT |

SPDX texts: [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html), [MIT](https://spdx.org/licenses/MIT.html), [MIT-0](https://spdx.org/licenses/MIT-0.html), [ISC](https://spdx.org/licenses/ISC.html), [BSD-2-Clause](https://spdx.org/licenses/BSD-2-Clause.html), [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html), [0BSD](https://spdx.org/licenses/0BSD.html).

Dependency updates require lockfile regeneration, tests, SDK capability verification, an updated inventory and a rebuilt deployment bundle. The installed package license files remain the authoritative notices for each dependency.
