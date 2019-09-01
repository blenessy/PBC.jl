using .Curve: BN
using .Config: ORDER

struct LagrangeCoeffGenerator{T}
    coeffs::Dict{T,BN}
    order::BN
    LagrangeCoeffGenerator(::Type{T}) where {T <: Signed} = new{T}(Dict{T,BN}(), ORDER)
    # calculate the weights ahead of time
    function LagrangeCoeffGenerator(keys)
        lc = LagrangeCoeffGenerator(eltype(keys))
        for x in keys
            push!(lc, x);
        end
        return lc
    end
end

Base.length(lc::LagrangeCoeffGenerator) = length(lc.coeffs)
Base.getindex(lc::LagrangeCoeffGenerator, i::T) where {T <: Signed} = getindex(lc.coeffs, i)

# NOTE: not thread safe
function Base.push!(lc::LagrangeCoeffGenerator, i::T) where {T <: Signed}
    coeff = get(lc.coeffs, i, nothing)
    if coeff === nothing
        # update existing coeffs
        bi = BN(i) # move to the field OUTSIDE of the loop
        for (k, c) in lc.coeffs
            lc.coeffs[k] = mod(c * invmod(i - k, lc.order) * bi, lc.order)
        end
        # update new coeff
        coeff = one(BN)
        for (k, _) in lc.coeffs
            coeff = mod(coeff * invmod(k - i, lc.order) * k, lc.order)
        end
        lc.coeffs[i] = coeff
    end
    return coeff
end

function Base.delete!(lc::LagrangeCoeffGenerator, i::T) where {T <: Signed}
    if length(lc.coeffs) != length(delete!(lc.coeffs, i))
        # update existing coeffs
        invi = invmod(i, lc.order)
        for (k, c) in lc.coeffs
            lc.coeffs[k] = mod(c * invi * (i - k), lc.order)
        end
    end
end
