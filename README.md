# HAB 

> This software is a part of the Master thesis of *Frantisek Mejzlik* titled **Fast hash-based signing protocol for message stream authentication**.

**H**ash-based **A**uthentication **B**roadcaster (HAB in short) is a library for broadcasting and receiving authenticated data streams using a protocol built upon hash-based few-time signatures (e.g. [HORST](https://link.springer.com/chapter/10.1007/978-3-662-46800-5_15); the HORST scheme is also implemented and published by this crate as `HorstSigScheme`).

Beware that the HORST scheme is vulnerable to adaptive chosen-message and weak-message attacks, and even if this use case does not allow the attacker to get his messages signed, it should not be used for production builds. Schemes without known vulnerabilities (e.g. [FORS](https://dl.acm.org/doi/10.1145/3319535.3363229)) should be used for production builds.

It's important to note that the protocol implementation is independent of the few-time signature scheme used. One can implement a different signature scheme that implements `FtsSchemeTrait` and use it to parametrise the `Sender` and `Receiver` instances.

> The crate is not yet suitable for production builds. Please see the *Limitations* section.

## **Prerequisites**

* **Operating system**: The crate **should** work fine on common modern Linux distributions, Windows NT systems and MacOS. Though, it was explicitly tested with Debian 11 and Windows 10/11.
* [**Rust compiler**](https://www.rust-lang.org/learn/get-started): Version 1.58 or higher.
* **Dependencies**: Not all used third-party crates may be written in pure Rust and may depend on some libraries (standard shared object libraries) that must be installed in the system. These are usually easy to install using the system package manager (`apt`, `yum`, ...). If so, the compiler will let you know what library is missing.

## **Build**

```sh
# A debug build
cargo build
# A release build
cargo build --release
```

## **Usage**
To use the library, it is quite straightforward.

```rs
// BROADCASTER
println!("Running the example broadcaster at '{}'...", params.sender_addr);
let mut bcaster = Sender::<SignerInst>::new(params);
loop {
    let data = read_input();
    if let Err(e) = bcaster.broadcast(data) {
        eprintln!("Failed to broadcast! ERROR: {e}");
    }
}

// RECEIVER
```
For more, please see the examples for [broadcaster](examples/broadcaster.rs) and [receiver](examples/receiver.rs) together with the documentation.

### Implementing a custom few-time signature scheme

The `Sender` and `Receiver` structs expect one generic type parameter and that is a few-time signature scheme.

```rs
struct Sender<Signer: FtsSchemeTrait> { ... }
struct Receiver<Signer: FtsSchemeTrait> { ... }
```

So your signature scheme must implement the [`FtsScheme`](https://gitlab.mff.cuni.cz/mejzlikf/hab/-/blob/master/src/traits.rs#L125) trait. That's it! Once you have that, your signature scheme will work as a drop-in replacement for the bundled-in HORST scheme.

## **Examples**

```sh
# Runs the broadcaster that broadcasts the datetime string periodically
cargo run --example broadcaster
# Runs the receiver that receivers the datetime broadcasted by the broadcaster above
cargo run --example receiver
```

### Complex example
The complex example usage is demonstrated in the separate directory [`audibro`](https://gitlab.mff.cuni.cz/mejzlikf/audibro). Please head there to see how the library can be used for real-time audio broadcasting software.

## **Documentation**

To see the developer documentation, run the following. The documentation will be built and shown in your default browser.

```sh
cargo doc --open
```

## **Known limitations**

This crate is still in proof-of-concept state and therefore there are some things to keep in mind when using it. 

* The crate is not-optimized. It is in the state of proof-of-concept and the performance is quite poor.
* The crate is not thoroughly tested and **is not suitable for production application**.

Any collaboration and improvements are very welcome.

## **License**

Copyright © 2023 Frantisek Mejzlik <frankmejzlik@proton.me>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
