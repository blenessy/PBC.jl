using .Curve: BN, FP, bn_read_bin!

abstract type AbstractPrivateKey end
struct PrivateKey <: AbstractPrivateKey
    sk::BN
    PrivateKey(sk) = PrivateKey(BN(sk))
    function PrivateKey(sk::BN)
        safesk = mod(sk, Config.ORDER)
        safesk == sk || @warn "Unsafe private key detected"
        return new(safesk)
    end
    function PrivateKey(bytes::Vector{UInt8})
        length(bytes) >= Config.PRIVATE_KEY_SIZE || @warn "Weak private key used"
        return PrivateKey(bn_read_bin!(BN(), bytes))
    end
end

abstract type AbstractPublicKey end
struct PublicKey <: AbstractPublicKey
    pk::Config.@EP2
    PublicKey(pk::Config.@EP2) = new(pk)
    PublicKey(sk::PrivateKey) = PublicKey(Util.genpk(sk.sk))
    function PublicKey(bytes::Vector{UInt8})
        length(bytes) == Config.PUBLIC_KEY_SIZE || error("bytes array has wrong size: $(length(bytes))")
        return PublicKey(Util.decode(Config.@EP2, bytes))
    end
end

struct SignedPublicKey <: AbstractPublicKey
    pk::Config.@EP2
    sig::Config.@EP
    SignedPublicKey(pk::Config.@EP2, sig::Config.@EP) = new(pk, sig)
    SignedPublicKey(sk::PrivateKey) = SignedPublicKey(Util.genpk(sk.sk), Util.sign(sk.sk, pk))
    function SignedPublicKey(bytes::Vector{UInt8})
        if length(bytes) != (Config.PUBLIC_KEY_SIZE + Config.SIGNATURE_SIZE)
            error("bytes array has wrong size: $(length(bytes))")
        end
        data = Util.decode(Config.@EP2, bytes[1:Config.PUBLIC_KEY_SIZE])
        signature = Util.decode(Config.@EP, bytes[Config.PUBLIC_KEY_SIZE+1:end])
        return new(data, signature)
    end
end

abstract type AbstractIdentity end
struct Identity{T} <: AbstractIdentity
    id::T
    Identity(id::T) where {T<:Signed} = new{T}(T(id & typemax(T)))
    Identity(::Type{T}, pk::PublicKey) where {T<:Signed} = Identity(T(pk.pk))
    Identity(pk::PublicKey) = Identity(Int64(pk.pk))
end

abstract type AbstractHash end
struct Hash <: AbstractHash
    hash::Config.@EP
    Hash(hash::Config.@EP) = new(hash)
    Hash(msg::Vector{UInt8}) = Hash(Util.hash2curve(msg))
    Hash(msg::String) = Hash(Vector{UInt8}(msg))
end

abstract type AbstractSignature end
struct Signature <: AbstractSignature
    sig::Config.@EP
    Signature(sig::Config.@EP) = new(sig)
    Signature(sk::PrivateKey, hash::Hash) = Signature(Util.sign(sk.sk, hash.hash))
    function Signature(bytes::Vector{UInt8})
        length(bytes) == Config.SIGNATURE_SIZE || error("bytes array has wrong size: $(length(bytes))")
        return Signature(Util.decode(Config.@EP, bytes))
    end
end
