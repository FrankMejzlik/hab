# HashSig

A software for broadcasting & receiving the authenticated data stream using a protocol based on hash-based few time signatures.

## Compile

```sh
cargo build
# For release version
cargo build --release
```

## Running

Run sender & receiver in different terminal windows.

```sh
./scripts/run-sender.sh
./scripts/run-receiver.sh
```

## Monitor

### Sender

```sh
# General log
tail -f ./env/sender/logs/output.log
# The main sender loop
tail -f ./env/sender/logs/sender.log
# The task managing the requests from receivers
tail -f ./env/sender/logs/registrator_task.log
```

### Receiver

```sh
# General log
tail -f ./env/receiver/logs/output.log
# The main sender loop
tail -f ./env/receiver/logs/receiver.log
# The task sending periodic heartbeats to the sender
tail -f ./env/receiver/logs/heartbeat_task.log
```
