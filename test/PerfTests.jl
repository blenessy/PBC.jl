module PerfTests

using BenchmarkTools
using PBC

BenchmarkTools.DEFAULT_PARAMETERS.samples = 1000
BenchmarkTools.DEFAULT_PARAMETERS.seconds = 10
BenchmarkTools.DEFAULT_PARAMETERS.evals = 1
BenchmarkTools.DEFAULT_PARAMETERS.gctrial = true
BenchmarkTools.DEFAULT_PARAMETERS.gcsample = false
@show BenchmarkTools.DEFAULT_PARAMETERS

Base.rand(::Type{PublicKey}) = PublicKey(rand(PBC.Config.@EP2))
Base.rand(::Type{Signature}) = Signature(rand(PBC.Config.@EP))
Base.rand(::Type{Hash}) = Hash(rand(PBC.Config.@EP))



suite = BenchmarkGroup()
suite["PBC"] = BenchmarkGroup()
suite["PBC"]["rand(PrivateKey)"] = @benchmarkable rand(PrivateKey)
suite["PBC"]["PrivateKey(::Vector{UInt8})"] = @benchmarkable PrivateKey($(rand(UInt8, PBC.Config.PRIVATE_KEY_SIZE)))
suite["PBC"]["PublicKey(::PrivateKey)"] = @benchmarkable PublicKey($(rand(PrivateKey)))
suite["PBC"]["PublicKey(::Vector{UInt8})"] = @benchmarkable PublicKey($(Vector{UInt8}(rand(PublicKey))))
suite["PBC"]["Vector{UInt8}(::PrivateKey)"] = @benchmarkable Vector{UInt8}($(rand(PrivateKey)))
suite["PBC"]["Vector{UInt8}(::PublicKey)"] = @benchmarkable Vector{UInt8}($(rand(PublicKey)))
suite["PBC"]["PBC.sign(::PrivateKey, ::Hash)"] = @benchmarkable PBC.sign($(rand(PrivateKey)), $(rand(Hash)))
suite["PBC"]["PBC.verify(::Signature, ::PublicKey, ::Hash)"] = @benchmarkable PBC.verify($(rand(Signature)), $(rand(PublicKey)), $(rand(Hash)))
suite["PBC"]["isvalid(::PrivateKey)"] = @benchmarkable isvalid($(rand(PrivateKey)))

function format_trial(suite, group, res)
    a = allocs(res)
    gct = BenchmarkTools.prettytime(gctime(res))
    t = BenchmarkTools.prettytime(time(res))
    m = BenchmarkTools.prettymemory(memory(res))
    return "[$suite] $group: $t (alloc: $a, mem: $m, gc: $gct)"
end

# If a cache of tuned parameters already exists, use it, otherwise, tune and cache
# the benchmark parameters. Reusing cached parameters is faster and more reliable
# than re-tuning `suite` every time the file is included.
paramspath = joinpath(@__DIR__, "params.json")
if isfile(paramspath)
    loadparams!(suite, BenchmarkTools.load(paramspath)[1], :evals);
else
    println("First run - tuning params (please be patient) ...")
    tune!(suite)
    BenchmarkTools.save(paramspath, params(suite));
end

# print the results
results = run(suite, verbose = true)
for suiteres in results
    for groupres in suiteres.second
        msg = format_trial(suiteres.first, groupres.first, groupres.second)
        println(msg)
    end
end

end
