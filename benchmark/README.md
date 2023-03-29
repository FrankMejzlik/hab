# HAB benchmarking

## Key distributions

```sh
# Skip-exponential
let key_dist = vec![
 vec![65536, 100],
 vec![16384, 0],
 vec![8192, 0],
 vec![4096, 0],
 vec![1024, 0],
 vec![256, 0],
 vec![64, 0],
 vec![16, 0],
 vec![4, 0],
 vec![1, 0],
];
```

### Sender

#### **Supported logs:**

```sh
# General log
tail -f ./env/sender/logs/output.log
# ---
# The main sender loop
tail -f logs/sender.log
# The UTF-8 repre of broadcasted messages
tail -f ./env/sender/logs/broadcasted.log
# The state of key layers
tail -f ./env/sender/logs/block_signer.log
# ---
# The task managing the requests from receivers
tail -f ./env/sender/logs/registrator_task.log
# The list of active subscribers
tail -f ./env/sender/logs/subscribers.log
```

### Receiver

#### **Supported logs**

```sh
# General log
tail -f ./env/receiver/logs/output.log
# ---
# The main sender loop
tail -f logs/receiver.log
# The UTF-8 repre of valid received messages
tail -f logs/received.log
# The state of the public keys in the keystore
tail -f ./env/receiver/logs/block_verifier.log
tail -f ./env/receiver/logs/delivery_queues.log
# ---
# The task sending periodic heartbeats to the sender
tail -f ./env/receiver/logs/heartbeat_task.log
# The inner state of fragmented block receiver
tail -f ./env/receiver/logs/fragmented_blocks.log
```
