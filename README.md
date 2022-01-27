# frost-secp256k1-js

Low Level JS Bindings for [frost-secp256k1](https://github.com/XP-NETWORK/frost-secp256k1)

## Usage

See [examples](./examples)

## Warn

This library uses handles for data that's not so easy to wrap for JS (or has too much overhead).  
These handles are literally pointers to an object on the heap. For safety reasons, the handles are consumed as soon as they are used.  
Do not re-use these handles as they point to uninitialized memory after consumption.  
Do not make changes to these handles. They are not "number". They are a pointer.
