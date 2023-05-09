# HAB 

Hash-based Authentication Broadcaster is a library for broadcasting and receiving authenticated data stream using a protocol built upon hash-based few-time signatures (e.g. HORST).

It's important to note that the protocol itself is independent of the few-time signature scheme used.

## **Prerequisites**

* [Rust compiler](https://www.rust-lang.org/learn/get-started)
* Dependencies - Not all used third-party dependencies may be written in pure Rust and **may** depend on some libraries that are installed in the system. These are usually easy to install using system package manager. If this is the case, the compiler will let you know what is missing.

## **Compile**

```sh
# A debug build
cargo build
# A release build
cargo build --release
# Run unit tests
cargo test
```

## Examples

The example usage is in the separate directory [`audibro`](https://gitlab.mff.cuni.cz/mejzlikf/audibro). Head there to see how the library can be used.

## License

Copyright © 2023 Frantisek Mejzlik <frankmejzlik@proton.me>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
