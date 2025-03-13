# Sybil

This project offers tools for managing Kerberos credentials in specialized environments, such as Batch and CI/CD.

It is comprised of:
- A privileged daemon hosted alongside the KDC which provides delegation and impersonation services: `sybild`
- A command line interface to interact with the sybil server and manage credentials: `sybil`
- A [SPANK](https://slurm.schedmd.com/spank.html) plugin that integrates with the [Slurm](https://slurm.schedmd.com) workload manager to forward and retrieve credentials as part of the job lifecycle

When used together, this enables the use of Kerberos inside traditional HPC infrastructure and allow services which provide their own authentication mechanism to work within a Keberized environment.  
For example, a CI/CD agent can leverage this to submit pipelines on behalf of a user authenticated outside of the Kerberos realm (e.g. OIDC, SAML).

This project relies among other things on [GSSAPI](https://datatracker.ietf.org/doc/html/rfc2743) and the [Microsoft S4U protocol extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94).

## Build

#### Binaries
```sh
# Prerequisites
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
apt install clang libkrb5-dev

make release

# Alternatively, with Slurm support
make release WITH_SLURM=1 SLURM_VERSION=24.11
```

#### Packages
```sh
# Prerequisites
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install cargo-generate-rpm cargo-deb
apt install clang libkrb5-dev

make deb rpm

# Alternatively, with Slurm support
make deb rpm WITH_SLURM=1 SLURM_VERSION=24.11
```

## Setup

### KDC Configuration

Before running Sybil, one needs to configure the KDC appropriately with a new service principal and necessary authorizations.  
Below, we provide sample configurations for the two most popular implementations, MIT Kerberos and FreeIPA.

#### IPA

Assuming an existing [FreeIPA](https://www.freeipa.org/) or [RHEL IdM](https://access.redhat.com/products/identity-management/) install:

```sh
# Create the Sybil service principal and generate its keytab
ipa service-add sybil/ipa.domain.lan
ipa-getkeytab -p sybil/ipa.domain.lan -k /etc/krb5.keytab

# Create the Sybil DNS service record
ipa dnsrecord-add --srv-priority=0 --srv-weight=100 --srv-port=57811 --srv-target=ipa.domain.lan. domain.lan _sybil._tcp

# In case user impersonation is needed (i.e. sybil kinit user@REALM)
# Allow a given host to perform impersonation against the Sybil service
ipa servicedelegationtarget-add sybil-target
ipa servicedelegationtarget-add-member --principals sybil/ipa.domain.lan sybil-target
ipa servicedelegationrule-add sybil
ipa servicedelegationrule-add-member --principals host/server.domain.lan sybil
ipa servicedelegationrule-add-target --servicedelegationtargets=sybil-target sybil
ipa host-mod --ok-to-auth-as-delegate=true server.domain.lan

# Allow delegation to the Sybil server
ipa service-mod --ok-as-delegate=true sybil/ipa.domain.lan
```

#### MIT Kerberos

Assuming an existing MIT Kerberos install with the [LDAP backend](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_ldap.html) (required for S4U to work):

```sh
# Create the Sybil service principal and generate its keytab
kadmin.local addprinc -randkey sybil/mit.domain.lan
kadmin.local ktadd -k /etc/krb5.keytab sybil/mit.domain.lan

# Create the Sybil DNS service record as follow in your DNS server
# _sybil._tcp.domain.lan. 86400 IN SRV 0 100 57811 mit.domain.lan.

# In case user impersonation is needed (i.e. sybil kinit user@REALM)
# Allow a given host to perform impersonation against the Sybil service
ldapmodify -Y EXTERNAL -H ldapi:// <<EOF
dn: krbPrincipalName=host/server.domain.lan@DOMAIN.LAN,cn=DOMAIN.LAN,cn=krbContainer,dc=domain,dc=lan
changetype: modify
add: krbAllowedToDelegateTo
krbAllowedToDelegateTo: sybil/mit.domain.lan
EOF
kadmin.local modprinc +ok_to_auth_as_delegate host/server.domain.lan

# Allow delegation to the Sybil server
kadmin.local modprinc +ok_as_delegate sybil/ipa.domain.lan
```

### Sybil Configuration

The Sybil server relies on the [KCM protocol](https://web.mit.edu/kerberos/krb5-latest/doc/basic/ccache_def.html) to store delegated credentials.  
Both KCM and the Sybil server need to be deployed alongside the KDC.

#### KCM 

Install and configure KCM to store and refresh tickets delegated to Sybil:

```sh
# Install KCM
apt install sssd-kcm

# Configure KCM to automatically renew tickets (e.g. every 30 mins)
tee /etc/sssd/conf.d/kcm.conf <<EOF
[kcm]
tgt_renewal = true
krb5_renew_interval = 30m
EOF

# Start KCM
systemctl enable --now sssd-kcm
```

#### Sybil server

Install and configure the Sybil server (c.f. [reference configuration](pkg/sybil.toml)).  
Arbitrary policies can be defined via ACL rules to restrict the set of operations available to each client principal:

```sh
# Install Sybil
apt install ./sybil_*.deb

# Configure Sybil with a set of predefined policies
tee /etc/sybil.toml <<EOF
[ticket]
cipher = "aes256-sha2"
flags = "FRA"
lifetime = "10h"
renewable_lifetime = "7d"
minimum_lifetime = "5m"
fully_qualified_user = false
cross_realm = false

# Allow any principal in the DOMAIN.LAN realm to store/fetch/list its tickets
[[acl]]
principal = '^.*@DOMAIN\.LAN$'
[acl.permissions]
fetch = true
store = true
list = true

# Allow host principals on a given subnet to fetch user tickets
[[acl]]
principal = '^host/.*@DOMAIN\.LAN$'
hosts = ["192.168.0.0/24"]
[acl.permissions]
fetch = true
masquerade = true

# Allow principals in the admin group to impersonate users, authenticating on their behalf (S4U)
[[acl]]
group = '^admin@domain\.lan$'
[acl.permissions]
kinit = true
EOF

# Start Sybil
systemctl enable --now sybil
```

### Slurm Configuration (optional)

Sybil ships with a [SPANK](https://slurm.schedmd.com/spank.html) plugin which allows users to automatically forward and renew Kerberos credentials as part of their [Slurm](https://slurm.schedmd.com) jobs.  
This plugin needs to be installed and configured on all the submission and compute nodes, after which a new `--kerberos=[auto|yes|no|force]`
parameter becomes available to the `salloc`/`srun`/`sbatch` commands.

```sh
# Install Sybil and its SPANK plugin
apt install ./sybil-spank*.deb

# Add Sybil to the list of Slurm plugins
install -D -m 644 /usr/share/sybil/slurm/plugstack.conf /etc/slurm/plugstack.conf.d/sybil.conf

# On the compute nodes only, configure the slurmd systemd override
install -D -m 644 /usr/share/sybil/slurm/slurm.conf /etc/systemd/system/slurmd.service.d/sybil.conf
```

The folowing options can be adjusted in the plugstack configuration:  
| Option | Description |
| ------ | ----------- |
| default | Specify the default value for the `--kerberos` parameter |
| min_tkt_lifetime | Specify the minimum ticket lifetime required at submission time (`--kerberos=force` overrides this)|

## Usage

```sh
# Retrieve a ticket for the host
kinit -k

# Acquire a ticket on behalf of the given principal
sybil kinit user@DOMAIN.LAN

# Change to the user
su - user

# Verify that a ticket has been acquired
klist

Default principal: user@DOMAIN.LAN

Valid starting       Expires              Service principal
09/15/2023 00:38:23  09/15/2023 10:38:23  krbtgt/DOMAIN.LAN@DOMAIN.LAN
        renew until 09/22/2023 00:38:23

# Send this ticket to the server
sybil store

# List the tickets present on the server
sybil list

UID         START_TIME           END_TIME             RENEW_UNTIL          PRINCIPAL
1000        2025-03-12T15:04:27  2025-03-13T01:04:27  2025-03-17T12:18:00  user@DOMAIN.LAN

# Submit a Slurm job, forwarding credentials to the allocated nodes
srun --kerberos=true klist

Default principal: user@DOMAIN.LAN

Valid starting       Expires              Service principal
09/15/2023 00:38:23  09/15/2023 10:38:23  krbtgt/DOMAIN.LAN@DOMAIN.LAN
        renew until 09/22/2023 00:38:23
```
