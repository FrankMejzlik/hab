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

### Running without a network via files only

You use `sender` mode to sign the message from file and make it output it back to some file.
Then you can verify the output with `receiver` mode and, if the signature is valid, output the original message to the file.

```sh
# Sign the message in `./env/data.input` and store the signed block to `./env/data.signed`
./target/debug/hashsig sender "0.0.0.0:5555" --input ./env/data.input --output ./env/data.signed

# Verify the signed block  in `./env/data.signed` and if valid write it to `./env/data.output`
./target/debug/hashsig receiver "127.0.0.1:5555" --input ./env/data.signed --output ./env/data.output
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
# The list of active subscribers
tail -f ./env/sender/logs/subscribers.log
# The UTF-8 repre of broadcasted messages
tail -f ./env/sender/logs/broadcasted.log
```

### Receiver

```sh
# General log
tail -f ./env/receiver/logs/output.log
# The main sender loop
tail -f ./env/receiver/logs/receiver.log
# The task sending periodic heartbeats to the sender
tail -f ./env/receiver/logs/heartbeat_task.log
# The UTF-8 repre of valid received messages
tail -f ./env/receiver/logs/received.log
# The inner state of fragmented block receiver
tail -f ./env/receiver/logs/fragmented_blocks.log
```
