module PBC
export PrivateKey, PublicKey, Signature, Hash

module Curve
    # load curve dynamically
    const CURVE = get(ENV, "RELIC_TOOLKIT_CURVE", "BLS381")
    eval(Meta.parse("using RelicToolkit.$CURVE"))
    eval(Meta.parse("using RelicToolkit.$CURVE: bn_read_bin!, bn_write_bin!"))
end

module Config
    import ..Curve
    include(joinpath(@__DIR__, "Config.jl"))
end

module Util
    import ..Config, ..Curve
    include(joinpath(@__DIR__, "Util.jl"))
end

module Model
    import ..Config, ..Util, ..Curve
    include(joinpath(@__DIR__, "Model.jl"))
end

module Spawn
    import ..Config, ..Model, ..Curve
    abstract type SpawnProcesses end
    #segfaults in 1.3-alpha
    #abstract type SpawnThreads end
    #const OptimalSpawn = isdefined(Threads, Symbol("@spawn")) ? SpawnThreads : SpawnProcesses
    const OptimalSpawn = SpawnProcesses
    include(joinpath(@__DIR__, "Distributed.jl"))
end

const PrivateKey = Model.PrivateKey
const PublicKey = Model.PublicKey
const Signature = Model.Signature
const Hash = Model.Hash

#sign(sk::PrivateKey, point::Util.Point) = sign(sk, Util.encode(point))
sign(sk::PrivateKey, hash::Hash) = Signature(sk, hash)
sign(sk::PrivateKey, bytes::Vector{UInt8}) = sign(sk, Hash(bytes))
sign(sk::PrivateKey, msg::String) = sign(sk, Hash(msg))

pair(ep::Curve.EP, ep2::Curve.EP2) = field_final_exp(curve_miller(ep, ep2))
pair(ep2::Curve.EP2, ep::Curve.EP) = field_final_exp(curve_miller(ep, ep2))

# The following random signatures 
struct  PubKeyAndHashGen
    n::Int
end

Base.length(rsg::PubKeyAndHashGen) = rsg.n
Base.getindex(rsg::PubKeyAndHashGen, r::UnitRange{Int}) = [getindex(rsg, i) for i in r]
function Base.getindex(rsg::PubKeyAndHashGen, i::Int)
    sk = rand(PrivateKey)
    hash = Hash(rand(UInt8, 10))
    return PublicKey(sk)=>hash
end
Base.iterate(rsg::PubKeyAndHashGen) = iterate(rsg, 1)
Base.iterate(rsg::PubKeyAndHashGen, state::Int) = (getindex(rsg, state), state + 1)


"""
verify(sig, pkhashpairs)

Cryptographically verify of the specified signature against one or more `PublicKey` and `Hash` pairs,
which are presented as an iterator with potentially millions of `Pair{PublicKey,Hash}` items.

# Complexity

Memory complexity is Θ(1) and time complexity is Θ(n) of this function.
It is possible to define the `PBC_THREADS=n` environment variable, which will
spawn extra processes to split up the computation (linearly) between multiple threads.

# Custom Iterators

You need to define a couple of methods for your `CustomPublicKeyAndHashIterator` to work:

```julia
Base.length(iter::CustomPublicKeyAndHashIterator)
Base.getindex(iter::CustomPublicKeyAndHashIterator, r::UnitRange{Int})
Base.getindex(iter::CustomPublicKeyAndHashIterator, i::Int)
Base.iterate(iter::CustomPublicKeyAndHashIterator)
Base.iterate(iter::CustomPublicKeyAndHashIterator, state)
```
"""
function verify(sig::Signature, pkhashpairs)
    isempty(pkhashpairs) && error("pkhashpairs is empty")
    return Spawn.verify(Spawn.OptimalSpawn, sig, pkhashpairs)
end
# mostly for and or simple use cases
verify(sig::Signature, pk::PublicKey, hash::Hash) = verify(sig, (pk=>hash,))
verify(sig::Signature, pk::PublicKey, bytes::Vector{UInt8}) = verify(sig, (pk=>Hash(bytes),))
verify(sig::Signature, pk::PublicKey, msg::String) = verify(sig, (pk=>Hash(msg),))

Base.Vector{UInt8}(sk::PrivateKey) = Curve.bn_write_bin!(Vector{UInt8}(undef, Config.PRIVATE_KEY_SIZE), sk.sk)
Base.Vector{UInt8}(pk::PublicKey) = Util.encode(pk.pk)
Base.Vector{UInt8}(sig::Signature) = Util.encode(sig.sig)
Base.Vector{UInt8}(hash::Hash) = Util.encode(hash.hash)

Base.iszero(sk::PrivateKey) = iszero(sk.sk)
Base.isinf(pk::PublicKey) = isinf(pk.pk)
Base.isinf(sig::Signature) = isinf(sig.sig)
Base.isinf(hash::Hash) = isinf(hash.hash)

# TODO: how can we trick the compiler to always perform both checks (constant time)?
Base.isvalid(sk::PrivateKey) = iszero(sk.sk.sign) && sk.sk < Config.ORDER
Base.isvalid(pk::PublicKey) = isvalid(pk.pk)
Base.isvalid(hash::Hash) = isvalid(hash.hash)
Base.isvalid(sig::Signature) = isvalid(sig.sig)

Base.:(+)(a::PublicKey, b::PublicKey) = PublicKey(a.pk + b.pk)
Base.:(+)(a::Signature, b::Signature) = Signature(a.sig + b.sig)
Base.:(-)(a::PublicKey, b::PublicKey) = PublicKey(a.pk - b.pk)
Base.:(-)(a::Signature, b::Signature) = Signature(a.sig - b.sig)

function Base.rand(::Type{PrivateKey})
    # Throw away keys are are outside of the allowed key space
    # (mod break the uniform key distribution)
    while true
        sk = PrivateKey(rand(Curve.BN, bits=Config.PRIVATE_KEY_SIZE_BITS))
        isvalid(sk) && return sk
        @debug "throwing away invalid private key"
    end
end

Base.:(==)(a::PrivateKey, b::PrivateKey) = a.sk == b.sk
Base.:(==)(a::Model.AbstractPublicKey, b::Model.AbstractPublicKey) = a.pk == b.pk
Base.:(==)(a::Signature, b::Signature) = a.pk == b.pk
Base.:(==)(a::Hash, b::Hash) = a.hash == b.hash

function __init__()
    if Spawn.OptimalSpawn == Spawn.SpawnProcesses
        Spawn.add_processes()
    end
    @debug (
        CURVE = Curve.CURVE,
        SMALL_SIGNATURES = Config.SMALL_SIGNATURES,
        PRIVATE_KEY_SIZE = Config.PRIVATE_KEY_SIZE,
        PUBLIC_KEY_SIZE = Config.PUBLIC_KEY_SIZE,
        SIGNATURE_SIZE = Config.SIGNATURE_SIZE,
    )
end

end # module
