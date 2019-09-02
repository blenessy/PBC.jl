using .Curve: BN, FP, bn_read_bin!
using .Config: @EP, @EP2, @ID, SIGNATURE_SIZE, PUBLIC_KEY_SIZE, PRIVATE_KEY_SIZE, ORDER
using .Shamir: BarycentricWeightGenerator

abstract type AbstractPrivateKey end
struct PrivateKey <: AbstractPrivateKey
    sk::BN
    PrivateKey(sk) = PrivateKey(BN(sk))
    function PrivateKey(sk::BN)
        safesk = mod(sk, ORDER)
        safesk == sk || @warn "Unsafe private key detected"
        return new(safesk)
    end
    function PrivateKey(bytes::Vector{UInt8})
        length(bytes) >= PRIVATE_KEY_SIZE || @warn "Weak private key used"
        return PrivateKey(bn_read_bin!(BN(), bytes))
    end
end

abstract type AbstractPublicKey end
struct PublicKey <: AbstractPublicKey
    pk::@EP2
    PublicKey(pk::@EP2) = new(pk)
    PublicKey(sk::PrivateKey) = PublicKey(Util.genpk(sk.sk))
    function PublicKey(bytes::Vector{UInt8})
        length(bytes) == PUBLIC_KEY_SIZE || error("bytes array has wrong size: $(length(bytes))")
        return PublicKey(Util.decode(@EP2, bytes))
    end
end

abstract type AbstractIdentity end
struct Identity <: AbstractIdentity
    id::@ID
    Identity(id::@ID) = new((@ID)(id & typemax(@ID)))
    Identity(pk::PublicKey) = Identity((@ID)(pk.pk))
end

abstract type AbstractHash end
struct Hash <: AbstractHash
    hash::@EP
    Hash(hash::@EP) = new(hash)
    Hash(msg::Vector{UInt8}) = Hash(Util.hash2curve(msg))
    Hash(msg::String) = Hash(Vector{UInt8}(msg))
end

abstract type AbstractSignature end
struct Signature <: AbstractSignature
    sig::@EP
    Signature(sig::@EP) = new(sig)
    Signature(sk::PrivateKey, hash::Hash) = Signature(Util.sign(sk.sk, hash.hash))
    function Signature(bytes::Vector{UInt8})
        length(bytes) == SIGNATURE_SIZE || error("bytes array has wrong size: $(length(bytes))")
        return Signature(Util.decode(@EP, bytes))
    end
end

abstract type AbstractPrivateKeyPoly end
struct PrivateKeyPoly <: AbstractPrivateKeyPoly
    coeffs::Vector{BN}
    PrivateKeyPoly(degree::Int) = new([Util.gensk() for i in 0:degree])
end

abstract type AbstractPublicKeyPoly end
struct PublicKeyPoly <: AbstractPublicKeyPoly
    coeffs::Vector{@EP2}
    PublicKeyPoly(coeffs::Vector{@EP2}) = new(coeffs)
    PublicKeyPoly(skpoly::PrivateKeyPoly) = PublicKeyPoly([Util.genpk(sk) for sk in skpoly])
end

abstract type AbstractSignatureShares end
struct SignatureShares <: AbstractSignatureShares
    shares::Dict{@ID,@EP}
    weights::BarycentricWeightGenerator
    SignatureShares() = new(Dict{@ID,@EP}(), BarycentricWeightGenerator())
end
