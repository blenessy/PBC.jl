module PBC
export PrivateKey, PublicKey, Signature, Hash, Identity, PrivateKeyPoly, PublicKeyPoly, SignatureShares

module Curve
    # load curve dynamically
    const CURVE = get(ENV, "RELIC_TOOLKIT_CURVE", "BLS381")
    eval(Meta.parse("using RelicToolkit.$CURVE"))
    eval(Meta.parse("using RelicToolkit.$CURVE: bn_read_bin!, bn_write_bin!, LIB, Limb"))
end

module Config
    import ..Curve
    include(joinpath(@__DIR__, "Config.jl"))
end

module Util
    import ..Config, ..Curve
    include(joinpath(@__DIR__, "Util.jl"))
end

module Shamir
    import ..Config, ..Curve, ..Util
    include(joinpath(@__DIR__, "LagrangeCoeffGenerator.jl"))
    include(joinpath(@__DIR__, "BarycentricWeightGenerator.jl"))
    include(joinpath(@__DIR__, "Shamir.jl"))
end


module Model
    import ..Config, ..Util, ..Curve, ..Shamir
    include(joinpath(@__DIR__, "Model.jl"))
end

module Spawn
    import ..Config, ..Model, ..Curve
    abstract type SpawnProcesses end
    abstract type SpawnThreads end
    const DefaultSpawn = SpawnThreads
    include(joinpath(@__DIR__, "Distributed.jl"))
    include(joinpath(@__DIR__, "Threads.jl"))
end

using .Model: PrivateKey, PublicKey, Signature, Hash, Identity, PrivateKeyPoly, PublicKeyPoly, SignatureShares

#sign(sk::PrivateKey, point::Util.Point) = sign(sk, Util.encode(point))
sign(sk::PrivateKey, hash::Hash) = Signature(sk, hash)
sign(sk::PrivateKey, bytes::Vector{UInt8}) = sign(sk, Hash(bytes))
sign(sk::PrivateKey, msg::String) = sign(sk, Hash(msg))

pair(ep::Curve.EP, ep2::Curve.EP2) = field_final_exp(curve_miller(ep, ep2))
pair(ep2::Curve.EP2, ep::Curve.EP) = field_final_exp(curve_miller(ep, ep2))

function create_share(skp::PrivateKeyPoly, id::Model.AbstractIdentity)
    return PrivateKey(Shamir.evalpoly(skp.coeffs, id.id))
end
create_share(skp::PrivateKeyPoly, pk::PublicKey) = create_share(skp, Model.Identity(pk))

function verify_share(pkp::PublicKeyPoly, id::Model.AbstractIdentity, sks::PrivateKey)
    return Shamir.evalpoly(pkp.coeffs, id.id) == Util.genpk(sks.sk)
end
verify_share(pkp::PublicKeyPoly, pk::PublicKey, sks::PrivateKey) = verify_share(pkp, Model.Identity(pk), sks)

Model.Signature(ss::SignatureShares) = Signature(Shamir.lagrange_interpolate_c0(ss.weights, ss.shares))
PublicKey(pkp::PublicKeyPoly) = PublicKey(pkp.coeffs[1])

Base.setindex!(ss::SignatureShares, sigshare::Signature, pk::PublicKey) = setindex!(ss, sigshare, Model.Identity(pk))
function Base.setindex!(ss::SignatureShares, sigshare::Signature, id::Model.AbstractIdentity)
    ss.shares[id.id] = sigshare.sig # register share
    push!(ss.weights, id.id) # register id
end

Base.length(poly::PrivateKeyPoly) = length(poly.coeffs)
Base.getindex(poly::PrivateKeyPoly, i::Int) = getindex(poly.coeffs, i)
Base.iterate(poly::PrivateKeyPoly) = iterate(poly.coeffs)
Base.iterate(poly::PrivateKeyPoly, state) = iterate(poly.coeffs, state)

Base.length(poly::PublicKeyPoly) = length(poly.coeffs)
Base.getindex(poly::PublicKeyPoly, i::Int) = getindex(poly.coeffs, i)
Base.iterate(poly::PublicKeyPoly) = iterate(poly.coeffs)
Base.iterate(poly::PublicKeyPoly, state) = iterate(poly.coeffs, state)

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
    return Spawn.verify(Spawn.DefaultSpawn, sig, pkhashpairs)
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

Base.:(+)(a::PrivateKey, b::PrivateKey) = PrivateKey(mod(a.sk + b.sk, Config.ORDER))
Base.:(+)(a::PublicKey, b::PublicKey) = PublicKey(a.pk + b.pk)
Base.:(+)(a::PublicKeyPoly, b::PublicKeyPoly) = PublicKeyPoly(map(+, a.coeffs, b.coeffs))
Base.:(+)(a::Signature, b::Signature) = Signature(a.sig + b.sig)
Base.:(-)(a::PrivateKey, b::PrivateKey) = PrivateKey(mod(a.sk - b.sk, Config.ORDER))
Base.:(-)(a::PublicKey, b::PublicKey) = PublicKey(a.pk - b.pk)
Base.:(-)(a::PublicKeyPoly, b::PublicKeyPoly) = PublicKeyPoly(map(-, a.coeffs, b.coeffs))
Base.:(-)(a::Signature, b::Signature) = Signature(a.sig - b.sig)

Base.rand(::Type{PrivateKey}) = PrivateKey(Util.gensk())

Base.:(==)(a::PrivateKey, b::PrivateKey) = a.sk == b.sk
Base.:(==)(a::Model.AbstractPublicKey, b::Model.AbstractPublicKey) = a.pk == b.pk
Base.:(==)(a::Signature, b::Signature) = a.sig == b.sig
Base.:(==)(a::Hash, b::Hash) = a.hash == b.hash

"""
tl;dr: Given 1_000_000_000 random Affline Points, there is a 5.42% chance of a conflict with this algo.

Assuming that x in each point is a uniformly distributed Prime Field element, 
then the probability of conflict can be calculated with (for 32-bit systems):

P(conflict) = 1/k + 2/k + ... + (n-1)/k = 1/k * (n-1)^2/2; where k=2^63

Q: Why is k!=2^64?  
A: Because some of the Lagrange Coeff and Barycentric Weight calculation involves signed arithmetic (e.g. i - k)
   which should not overflow

Example: n = 1_000_000_000 => P(conflict) = 1/2^63 * (1_000_000_000 - 1)^2/2 = 999_999_999^2 / 2^64 = 0.0542...
"""
Base.Int64(p::Curve.EP; i=1) = signed(Curve.Limb == UInt64 ? p.x[i] : p.x[2i] << 32 | p.x[2i-1])
Base.Int64(p::Curve.EP2; i=1) = signed(Curve.Limb == UInt64 ? p.x[1][i] : p.x[1][2i] << 32 | p.x[1][2i-1])
Base.Int128(p::Util.Point; i=1) = Int128(Int64(p, i=2i)) << 64 | Int128(Int64(p, i=2i-1))

function __init__()
    Spawn.add_processes(Config.NPROCS)
    @debug (
        CURVE = Curve.CURVE,
        SMALL_SIGNATURES = Config.SMALL_SIGNATURES,
        PRIVATE_KEY_SIZE = Config.PRIVATE_KEY_SIZE,
        PUBLIC_KEY_SIZE = Config.PUBLIC_KEY_SIZE,
        SIGNATURE_SIZE = Config.SIGNATURE_SIZE,
    )
end

end # module
