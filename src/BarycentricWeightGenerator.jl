using .Config: ORDER
using .Curve: BN

struct BarycentricWeightGenerator
    weights::Dict{Int64,BN}
    order::BN
    BarycentricWeightGenerator() = new(Dict{Int64,BN}(), ORDER)
    # calculate the weights ahead of time
    function BarycentricWeightGenerator(keys)
        lc = BarycentricWeightGenerator()
        for x in keys
            push!(lc, x);
        end
        return lc
    end
end

Base.length(lc::BarycentricWeightGenerator) = length(lc.weights)
Base.getindex(lc::BarycentricWeightGenerator, i::Int64) = getindex(lc.weights, i)

# NOTE: not thread safe
function Base.push!(lc::BarycentricWeightGenerator, i::Int64)
    # return the existing if found
    coeff = get(lc.weights, i, nothing)
    if coeff === nothing
        # update existing coeffs
        for (k, c) in lc.weights
            lc.weights[k] = mod(c * (i - k), lc.order)
        end
        coeff = mod(-i, lc.order) # optimisation: normally this is not part of the weight
        # update new coeff
        for (k, _) in lc.weights
            coeff = mod(coeff * (k - i), lc.order)
        end
        lc.weights[i] = coeff
    end
    return coeff
end

function Base.delete!(lc::BarycentricWeightGenerator, i::Int64)
    if length(lc.weights) != length(delete!(lc.weights, i))
        # update existing coeffs
        for (k, c) in lc.weights
            lc.weights[k] = mod(c * invmod(i - k, lc.order), lc.order)
        end
    end
end
