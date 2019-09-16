function reduceone(func::Function, args)
    # split arguments into batches with an even number
    n = length(args)
    numreductions = div(n, 2)
    reductions = Vector{eltype(args)}(undef, numreductions + n & 1)
    Threads.@threads for i in 1:numreductions
        j = i << 1
        reductions[i] = func(args[j-1], args[j])
    end
    if isodd(n)
        reductions[end] = args[end]
    end
    return reductions
end

function reduceall(func::Function, args)
    # split arguments into batches with an even number
    reductions = Vector{eltype(args)}()
    for batchargs in Iterators.partition(args, Config.BATCH_SIZE)
        append!(reductions, reduceone(func, batchargs))
        if length(reductions) > Config.BATCH_SIZE
            reductions = reduceone(func, reductions)
        end
    end
    while length(reductions) > 1
        reductions = reduceone(func, reductions)
    end
    return reductions[1]
end

function verify(::Type{SpawnThreads}, sig::Model.Signature, pkhashpairs)
    # NOTE: This is PoC only! It demonstrates that the feasibility/benefits of running thread level parallelism with RelicToolkit 
    lhside_results = Vector(undef, length(pkhashpairs)+1)
    Threads.@threads for i in 0:length(pkhashpairs)
        a, b = iszero(i) ? (Config.G2, sig.sig) : (pkhashpairs[i].first.pk, pkhashpairs[i].second.hash)
        lhside_results[i+1] = Curve.curve_miller(a, b)
    end
    rside = popfirst!(lhside_results)
    lhside = reduceall(*, lhside_results)
    return isone(Curve.field_final_exp(lhside // rside))
end
