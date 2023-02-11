# HashSig

A software for broadcasting & receiving the authenticated data stream using a protocol based on hash-based few time signatures.

## Compile & run

```sh
cargo run -- sender
cargo run -- receiver
```

## Logs

To monitor logs from the different logical units:

```sh
# The main sender loop
tail -f logs/sender.log
# The task managing the requests from receivers
tail -f logs/registrator.log
```
