import Distributed

function add_processes()
    choice = get(ENV, "PBC_THREADS", "1")
    n = choice == "auto" ? Sys.CPU_THREADS : parse(Int, choice)
    n >= 1 || error("invalid number of threads specified: $n")
    if Distributed.nprocs() < n
        @info "Starting $(n-1) more processes ..."
        Distributed.addprocs(n - 1)
    end
end

function verify(::Type{SpawnProcesses}, sig::Model.Signature, pkhashpairs)
    # kick off workers in parallel
    future_rhside = Distributed.@spawn Curve.curve_miller(Config.GEN, sig.sig)
    lhside = Distributed.@distributed (*) for pair in pkhashpairs
        Curve.curve_miller(pair.first.pk, pair.second.hash)
    end
    res = Curve.field_final_exp(fetch(lhside) // fetch(future_rhside))
    return res == one(typeof(res))
end
