import Distributed

function add_processes(count)
    count -= Distributed.nprocs()
    if count > 0
        @info "Starting $count more processes ..."
        Distributed.addprocs(count)
    end
end

function verify(::Type{SpawnProcesses}, sig::Model.Signature, pkhashpairs)
    # kick off workers in parallel
    future_rhside = Distributed.@spawn Curve.curve_miller(Config.G2, sig.sig)
    lhside = Distributed.@distributed (*) for pair in pkhashpairs
        Curve.curve_miller(pair.first.pk, pair.second.hash)
    end
    res = Curve.field_final_exp(fetch(lhside) // fetch(future_rhside))
    return res == one(typeof(res))
end
