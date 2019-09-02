using .Curve: BN, FP, EP, EP2, LIB, Limb
using .Util: Point
using .Config: PRIME, ORDER, @ID


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

function lagrange_interpolate_c0(coeffs::LagrangeCoeffGenerator, shares::AbstractDict{@ID,V})  where {V<:Union{BN,EP,EP2}}
    length(shares) >= 2 || error("need at least two shares")
    c0 = zero(V)
    for (x, y) in shares
        c0 += coeffs[x] * y
    end
    return isa(c0, Point) ? c0 : mod(c0, ORDER)
end

function lagrange_interpolate_c0(weights::BarycentricWeightGenerator, shares::AbstractDict{@ID,V}) where {V<:Union{BN,EP,EP2}}
    length(shares) >= 2 || error("need at least two shares")
    num, denom = zero(V), zero(BN)
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

lagrange_interpolate_c0(shares::AbstractDict) =
    lagrange_interpolate_c0(LagrangeCoeffGenerator(keys(shares)), shares)
