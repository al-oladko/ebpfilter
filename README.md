# ebpfilter

**ebpfilter** is an XDP-based stateful firewall with support for L7 (application-layer) traffic filtering using DPI (Deep Packet Inspection). It maintains connection state, so once a session is allowed, packets within that session do not need to be re-evaluated against the rules.

It supports standard L4-level firewall filtering options such as source and destination IP addresses, protocols, and port numbers. L7 protocol detection is performed using a lightweight DPI engine. DPI analysis is independent of destination port, and currently has the following limitation: the L7 protocol must be detected in the first packet carrying payload data.

---

## Installation

To install ebpfilter, follow these steps:

```bash
git clone https://github.com/al-oladko/ebpfilter
./configure
make
sudo make install
````

---

## Usage

Use the `ebpfilter` utility to load, unload, and manage filtering rules.

### Load XDP program

Attach the XDP filter to a network interface:

```bash
ebpfilter load dev <ifname>
```

### Show attached interfaces

List all interfaces where the XDP program is currently attached:

```bash
ebpfilter status
```

You can attach the program to multiple interfaces. Each interface maintains its own independent rule set.

### Unload XDP program

Unload the XDP program from a specific interface:

```bash
ebpfilter unload [dev <ifname>]
```

If `<ifname>` is not specified, the program will be unloaded from all interfaces.

### Reload XDP program

Reattaching the XDP program while preserving the loaded rule set:

```bash
ebpfilter reload [dev <ifname>]
```

If `<ifname>` is not specified, the program will be reloaded on all interfaces.

---

### View connection

View connection tracking table:

```bash
ebpfilter connection [dev <ifname>]
```

If `<ifname>` is not specified, the program will be reloaded on all interfaces.

## Managing Rules

### Set default policy

Specify the default action for packets that do not match any rule:

```bash
ebpfilter rule set default {accept|drop} [dev <ifname>]
```

### Add a rule

Add a new filtering rule:

```bash
ebpfilter rule add <rule-options> [dev <ifname>]
```

You may omit `ifname` if the program is attached to only one interface. If attached to multiple interfaces, `ifname` is required.

**Example L3 rule (IP-based filtering):**

```bash
ebpfilter rule add src 10.20.0.0/16 dst 192.168.1.0/24 action accept
```

**Example L7 rule (DPI-based protocol detection):**

```bash
ebpfilter rule add service tls action accept
```

This rule allows TLS traffic regardless of the destination port (not limited to port 443). L7 rules can be combined with L3/L4 filters:

```bash
ebpfilter rule add src any dst 192.168.1.1 tcp port 443 service tls action accept
```
**Setting connection limit**

```bash
ebpfilter rule add tcp port 443 connlimit 100/1s action accept
```

Limit of new connections for the rule. The format is [connections_per_period]/[period], where the period is specified in seconds, minutes, or hours, and must be indicated with the suffixes s, m, or h, respectively.

To get information about other options when adding a rule, see the help for the rule command.

### View help for rule syntax

```bash
ebpfilter rule help
```

### Show current policy

Display the currently loaded rule set:

```bash
ebpfilter rule show [dev <ifname>]
```

Each rule includes statistics on matches, such as packet and byte counts.

### Delete a rule

Remove a rule by its number:

```bash
ebpfilter rule delete [dev <ifname>]
```

### Flush all rules

Remove all rules from the policy:

```bash
ebpfilter rule flush [dev <ifname>]
```

---

## Example Policy

```bash
ebpfilter rule add udp port 53 service dns action accept
ebpfilter rule add service tls action accept
ebpfilter rule set default drop
```

This configuration allows:

* DNS traffic over UDP port 53
* TLS traffic on any port
* All other traffic will be dropped by default.

---

## License

This project is licensed under the GNU General Public License v2 only.
