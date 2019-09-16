# Introduction

Pairing Based Cryptography (PBC) library for Julia based on the [RELIC toolkit](https://github.com/relic-toolkit/relic).

Primary goals are:
- [ ] introduce a high-level cryptographic model, which is intuitive and flexible.
- [ ] Make it easy to implement the BLS Signature scheme

# Key Features

- [x] Supports multiple Curves (BLS381 and BN254)
- [x] Supports both 32 and 64 bit machines
- [x] Supports common operative systems (Linux, Mac, Windows)
- [x] State-of-the art performance
- [x] Implement the simple [BLS Signature Scheme](https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716)
- [ ] Implement [Threshold Signature Scheme](https://blog.dash.org/secret-sharing-and-threshold-signatures-with-bls-954d1587b5f)
- [x] Can verify very large sets of public keys at constant memory consumption
- [ ] Production Ready (timing, side-channel resistance)

# Quick Start

So lets implement the simplest possible BLS signature scheme in 10 lines of code!

The symbols (e.g. `pk`, `H(m)`) below were chosen to be consistent with this [excellent blog](https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716).

```julia
using Pkg
Pkg.add(PackageSpec(url="https://github.com/blenessy/PBC.jl"))
```

Import the PBC lib:
```julia
using PBC
```

Lets create a Private Key:
```julia
sk = rand(PrivateKey)
```

Then sign some messages:
```julia
sig = PBC.sign(sk, "hello")
```

Finally we verify the signature is good:
```julia
pk = PublicKey(sk)
@assert PBC.verify(sig, pk, "hello")
```

# Performance

You can run the performance tests with:

```julia
make CURVE=BLS381 bench
```

You should get something like this on a 4-5 year old 2.2GHz Core i7:

```
...
[PBC] PBC.verify(::Signature, ::PublicKey, ::Hash): 3.393 ms (alloc: 700, mem: 24.52 KiB, gc: 0.000 ns)
...
[PBC] PBC.sign(::PrivateKey, ::Hash): 564.749 μs (alloc: 2, mem: 320 bytes, gc: 0.000 ns)
...
```

# Configurations

Cofiguration is done through environment variables.
The number of configuration possibilities should be limited for simplicity.

Key | Default | Description
--- | --- | ---
`RELIC_TOOLKIT_CURVE` | (all curves are loaded) | Used for limiting, which curve is loaded (saves memory) at startup. Possible values are: `BN254` and `BLS381`.
`JULIA_NUM_THREADS` | `1` | Used for enabling parallelims over multiple *threads* (default).
`PBC_NPROCS` | `1` | Used for enabling parallelims over multiple *processes* where possible (`auto` uses all cores).
`PBC_SMALL_SIGNATURES` | `n` | Enable with `y`, in which case signatures will be smalles and public key bigger.

# Contibutions

Contributions are welcome!
If you are unsure where to chip in, please see the roadmap below.

## Testing

Test | Purpose
--- | ---
`UnitTests` | Make sure the `ccall` are working and do not crash Julia.
`PerfTests` | Fair benchmarks for performance awareness

## Fixes and minor features

Just create a PR (as usual in GitHub) and make sure that the code coverage stays at 100%.

## High-level API changes and new Features

1. Please start by creating an issue and explain your use-case and goal.
2. Create a PR (as usual in GitHub) with the implementation and add a new `SysTest` to protect your use-case.

# Roadmap

## 0.1.0: Threshold Signatures

- [ ] setup `.travis.yml` for CI
- [ ] implement [Threshold Signature Scheme](https://blog.dash.org/secret-sharing-and-threshold-signatures-with-bls-954d1587b5f)



