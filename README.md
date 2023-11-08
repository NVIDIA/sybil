# Sybil

This project provides a set of tools to perform Kerberos protocol transition and ticket impersonation.

It is comprised of:
- A privileged daemon hosted alongside the KDC which provides impersonation services (`sybild`)
- A command line interface which can be used to request tickets on behalf of users (`sybil`)

When used together, this enables services which provide their own authentication mechanism to utilize a Kerberized infrastructure.  
For example, this can allow a CI/CD agent to submit pipelines on behalf of a user authenticated outside of the Kerberos realm (e.g. OIDC, SAML).

This project relies among other things on [GSSAPI](https://datatracker.ietf.org/doc/html/rfc2743) and the [Microsoft S4U protocol extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94).

## Build

#### Binaries
```sh
# Prerequisites
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
apt install clang libkrb5-dev

make release
```

#### Packages
```sh
# Prerequisites
cargo install cargo-generate-rpm cargo-deb

make deb rpm
```

## Setup

Assuming an existing [FreeIPA](https://www.freeipa.org/) or [RHEL IdM](https://access.redhat.com/products/identity-management/) install:

```sh
# Create the Sybil service principal and generate its keytab
ipa service-add sybil/ipa.domain.lan
ipa-getkeytab -p sybil/ipa.domain.lan -k /etc/krb5.keytab

# Create the the Sybil DNS service record
ipa dnsrecord-add --srv-priority=0 --srv-weight=100 --srv-port=57811 --srv-target=ipa.domain.lan. domain.lan _sybil._tcp

# Allow a host to perform impersonation against the Sybil service
ipa servicedelegationtarget-add sybil-target
ipa servicedelegationtarget-add-member --principals sybil/ipa.domain.lan sybil-target
ipa servicedelegationrule-add sybil
ipa servicedelegationrule-add-member --principals host/server.domain.lan sybil
ipa servicedelegationrule-add-target --servicedelegationtargets=sybil-target sybil
ipa host-mod --ok-to-auth-as-delegate=true server.domain.lan

# Configure and run Sybil
cat > /etc/sybil.toml <<EOF
tkt_cipher = "aes256-sha1"
tkt_flags = "FRI"
tkt_life = "10h"
tkt_renew_life = "7d"
allow_networks = ["192.168.0.0/24"]
allow_realms = ["DOMAIN.LAN"]
allow_groups = ["group@domain.lan"]
strip_domain = true
cross_realm = ""
EOF

systemctl enable --now sybil
```

## Usage

```sh
# Retrieve a ticket for the host
kinit -k

# Acquire a ticket on behalf of the given principal
sybil kinit user@domain.lan

# Verify that a ticket has been acquired
sudo -u user klist

Default principal: user@DOMAIN.LAN

Valid starting       Expires              Service principal
09/15/2023 00:38:23  09/15/2023 10:38:23  krbtgt/DOMAIN.LAN@DOMAIN.LAN
        renew until 09/22/2023 00:38:23
```
