# auditrd - A library to read Linux audit logs

[![License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](http://opensource.org/licenses/MIT)

## About

`auditrd` is a library implemented in pure Go which exposes an API to read and
process the Linux audit logs from an already existing set of audit rules. This
library is a fork from [slackhq/go-audit](https://github.com/slackhq/go-audit/)
which is then transformed to expose a client API. The motive of this library is
the ability to manipulate audit logs in a more flexible way than writing a
audisp plugin or writing C code.

##### Goals

To justify yet another audit client other than the [go-audit](https://github.com/slackhq/go-audit/)
, [go-libaudit](github.com/elastic/go-libaudit) or
[osquery](https://github.com/osquery/osquery]) is to be able to provide a
simpler yet low level API to read audit logs rather than defining what can be
done with it. It's implemented in pure Go which adds another layer of
flexibility to it in terms of
* being compiled
* relatively safe and quick to implement
* ability to write plugins for osquery using [osquery-go](https://github.com/osquery/osquery-go)

If you are familiar with osquery, it already has an Audit log client, so why use
this? The builtin log parser uses a different philosophy to identify FIM events
which can be lead to less false positives but can lead to relatively high CPU
utilization and subsequent respawns by the watchdog. This library has existing
parsers for a more simplified approach which may introduce a few false positives
given the rules are configured correctly.

## Usage

The library can be used in the following way (checkout
[pkg/cmd/audit.go](./pkg/cmd/audit.go) which can also be used as a runnable
binary on a linux system.

```sh
make
sudo ./audit
```

### API Usage
```go
rd, _ := auditrd.NewAuditReader(1100, 1400, 1024, 1024)
for msg := range rd {
    if msg != nil {
        // allocate buffers for audit logs events per event ID
        tokenList := make([]auditrd.AuditMessageTokenMap, 0, 6)

        // Iterate over all events for a single event ID and tokenize them
        for _, d := range msg.Msgs {
            tokenList = append(tokenList, auditrd.AuditMessageTokenMap{
                AuditEventType: d.Type,
                Tokens:         auditrd.Tokenize(d.Data),
            })
        }

        // Run a parser on the Tokenized Events
        ev, ok := auditrd.ParseAuditEvent(tokenList)
        if ok {
            // If a valid event (process_event of fim_event) is found
            // print it to stdout
            json.NewEncoder(os.Stdout).Encode(ev)
        }
    }
}
```
