using .Curve: BN, FP, EP, EP2, LIB, Limb
using .Model: AbstractIdentity, AbstractPrivateKey, AbstractSignature
using .Util: Point
using .Config: PRIME, ORDER


evalpoly(poly, x) = evalpoly(poly, BN(x))
function evalpoly(poly, x::BN)
    @assert length(poly) > 0
    xpow, y = x, first(poly)
    for coeff in Iterators.drop(poly, 1)
        y += xpow * coeff
        xpow = mod(x * xpow, ORDER)
    end
    return isa(y, Point) ? y : mod(y, ORDER)
end

# TODO: move to RelicToolkit.jl
# function Base.:(*)(a::BN, b::BN)
#     c = BN()
#     ccall((:bn_mul_comba, Curve.LIB), Cvoid, (Ref{BN}, Ref{BN}, Ref{BN}), c, a, b)
#     return c
# end

# Base.:(*)(a::BN, b::FP) = FP(a) * b
# Base.:(*)(a::FP, b::BN) = a * FP(b)
#Base.:(*)(a::FP, b::EP) = BN(a) * b
#Base.:(*)(a::FP, b::EP2) = BN(a) * b
# function Base.:(+)(a::BN, b::BN)
#     c = BN()
#     ccall((:bn_add, Curve.LIB), Cvoid, (Ref{BN}, Ref{BN}, Ref{BN}), c, a, b)
#     return c
# end

# function Curve.BN(a::Curve.FP)
#     c = BN()
#     ccall((:fp_prime_back, Curve.LIB), Cvoid, (Ref{BN}, Ref{Curve.FP}), c, a)
#     return c
# end
# Curve.FP(a::Curve.FP) = a


"""
This optimised Lagrange polynomial interpolation.
This version only cares about finding the secret coefficient (index 0) as fast as possible.

weights need to be pre-calculated with `updateweights!` before calling this function.
"""
function lagrange_interpolate_c0(coeffs::LagrangeCoeffGenerator, shares::AbstractDict{Int64,T})  where {T}
    length(shares) >= 2 || error("need at least two shares")
    c0 = zero(T)
    for (x, y) in shares
        c0 += coeffs[x] * y
    end
    return isa(c0, Point) ? c0 : mod(c0, ORDER)
end

function lagrange_interpolate_c0(weights::BarycentricWeightGenerator, shares::AbstractDict{Int64,T}) where {T}
    length(shares) >= 2 || error("need at least two shares")
    num, denom = zero(T), zero(BN)
    for (x, y) in shares
        # optimisation: normally inv is done when calculating weights
        #w = invmod(weights[j], ORDER)
        w = invmod(weights[x], ORDER)
        #@info weights[j], w
        num += w * y
        # just addition in practice no risk of overflow
        denom += w
    end
    c0 = invmod(mod(denom, ORDER), ORDER) * num
    return isa(c0, Point) ? c0 : mod(c0, ORDER)
end

lagrange_interpolate_c0(::Type{T}, shares::AbstractDict{Int64,S}) where {S,T} = lagrange_interpolate_c0(T(keys(shares)), shares)
lagrange_interpolate_c0(shares::AbstractDict{Int64,T}) where {T} = lagrange_interpolate_c0(LagrangeCoeffGenerator, shares)

