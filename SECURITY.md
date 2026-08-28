# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability involving
secret disclosure, cryptography, local storage, command execution, or sync
bundles.

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Advisories**.
3. Select **Report a vulnerability**.

Include the affected version, operating system, reproduction steps, expected
behavior, observed behavior, and potential impact. Remove real credentials and
other sensitive values from reports and logs.

## Supported versions

Until envctl reaches 1.0, security fixes are provided for the latest published
release only.

## Security model

envctl encrypts secret values at rest and stores the master key in the operating
system keyring when possible. If no supported keyring is available, it falls
back to a local file created with restrictive permissions. Encrypted sync
bundles are protected by a separate user-managed sync root key.

Anyone who obtains a usable master key can decrypt its corresponding local
database. Anyone who obtains a sync root key and an encrypted bundle can decrypt
the operations in that bundle. Protect keys independently from the data they
encrypt.

envctl does not protect secrets after they have been injected into a child
process. The operating system, debuggers, process inspection tools, crash dumps,
and the child process itself may expose those values.
