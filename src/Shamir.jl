using .Curve: BN, FP, EP, EP2, LIB, Limb
using .Model: AbstractIdentity, AbstractPrivateKey, AbstractSignature
using .Util: Point
using .Config: PRIME, ORDER


function evalpoly(poly, x)
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
function lagrange_interpolate_c0(coeffs::LagrangeCoeffGenerator, x::AbstractVector{Int}, y::AbstractVector{T})  where {T}
    length(x) >= 2 || error("need at least two shares")
    length(y) == length(y) || error("X and Y have different lengths")
    c0 = zero(T)
    for (i, j) in enumerate(x)
        c0 += coeffs[j] * y[i]
    end
    return isa(c0, Point) ? c0 : mod(c0, ORDER)
end

function lagrange_interpolate_c0(weights::BarycentricWeightGenerator, x::AbstractVector{Int}, y::AbstractVector{T}) where {T}
    length(x) >= 2 || error("need at least two shares")
    length(y) == length(y) || error("X and Y have different lengths")
    num, denom = zero(T), zero(BN)
    for (i, j) in enumerate(x)
        # optimisation: normally inv is done when calculating weights
        #w = invmod(weights[j], ORDER)
        w = invmod(weights[j], ORDER)
        #@info weights[j], w
        num += w * y[i]
        denom += w
    end
    c0 = invmod(denom, ORDER) * num
    return isa(c0, Point) ? c0 : mod(c0, ORDER)
end

lagrange_interpolate_c0(::Type{T}, x::AbstractVector{Int}, y::AbstractVector{S}) where {S,T} = lagrange_interpolate_c0(T(x), x, y)
lagrange_interpolate_c0(x::AbstractVector{Int}, y::AbstractVector{T}) where {T} = lagrange_interpolate_c0(LagrangeCoeffGenerator, x, y)

