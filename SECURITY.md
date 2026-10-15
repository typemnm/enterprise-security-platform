# Security reports

Report a vulnerability through the repository's [private vulnerability reporting form](https://github.com/typemnm/enterprise-security-platform/security/advisories/new). If that option is unavailable, request a private reporting channel in an issue without including technical exploit details, credentials, customer identifiers or logs.

Include the affected release, the security boundary involved, a minimal reproduction using synthetic resources and the expected versus observed result. Do not post AWS keys, Slack bot tokens, OAuth tokens, Step Functions task tokens, receipt handles, administrator emails, company endpoints or report bodies.

Only the latest published release is the current maintenance target. Security reports will be reviewed; this repository does not promise a response deadline or hosted monitoring service. Company operators own their AWS account, incident response decisions and installation settings.

Use company configuration outside the checkout, for example `%USERPROFILE%/company-security/installation.json` on Windows or `${HOME}/company-security/installation.json` on Linux. The public example is a template. Keep installation results, audit exports and validation evidence outside Git and never upload them as CI artifacts.

The default CI uses no AWS credentials and performs no deployment or security response. Production installations must retain Cognito authentication, administrator groups, CSRF checks, service registration, evidence binding, explicit enforcement policy and audit retention. Do not weaken these checks to resolve a deployment problem; report a synthetic reproduction instead.

Before publication run `python -B tools/publication_check.py --root .`. Before sharing the deploy ZIP run `python -B tools/publication_check.py --archive dist/enterprise-security-platform-deploy.zip`. These checks are safeguards; reviewers must also inspect the diff and confirm that the upload contains only neutral product files.
