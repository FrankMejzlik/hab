# HashSig

A toolkit for broadcasting or receiving authenticated data stream using a protocol built upon hash-based few-time signatures (e.g. HORST, PORST, SPHINCS).

Current implementation uses the HORST signature scheme. This scheme is vulnarable against "weak words" attack and against adaptive attacks. Therefore we will also add an option to use PORST with SPHINCS-like extension to mitigate those vulnerabilites.

It's important to note that the protocol itself is agnostic to few-time signature scheme used.

## **Compile**

```sh
# A debug build
cargo build
# A release build
cargo build --release
# Run unit tests
cargo test
```

## **Running**

Run sender & receiver in different terminal windows. These scripts run the sender & receiver inside the `env` directory (and in the `sender` & `receiver` subdirectories).

```sh
./scripts/run-sender.sh
./scripts/run-receiver.sh
```

### Permanent identities (state of the receiver & sender)

Both sender & receiver modes store their state to `.identity` directory in the directory from which the binary is run. At the moment those are not encrypted (TODO using ~/.ssh/ keys) and the state writes are not fault-tolerant (TODO using speculative write & atomic `mv`).

```sh
./scripts/clear-ids.sh
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

## **Logging**

For sake of readability we are using a "tagged" output to different files which you can monitor in real time (e.g. using `tail -f`). This effectively emulates a multiple terminals. Feel free to open multiple terminal (or use e.g. `tmux` to split into panes) and monitor whatever you're interested in.

### `tmux` one-liners

```sh
# TODO: write a tmux one-liner that splits the panes for you and runs the belowmentioned commands to live monitor the logs
```

### Sender

#### **Supported logs:**

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
# The state of key layers
tail -f ./env/sender/logs/block_signer.log
```

### Receiver

#### **Supported logs**

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
# The state of the public keys in the keystore
tail -f ./env/receiver/logs/block_verifier.log
```
