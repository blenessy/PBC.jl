"""
This function reduces the input tasks to a single task by applying `func` to each input task pair.
"""
function reducetasks(func, tasks)
    @assert !isempty(tasks)
    todo = collect(tasks)
    while length(todo) > 1
        a, b = popfirst!(todo), popfirst!(todo)
        newtask = Threads.@spawn func(fetch(a), fetch(b))
        push!(todo, newtask)
    end
    return todo[1]
end

function verify(::Type{SpawnThreads}, sig::Model.Signature, pkhashpairs)
    # kick off workers in parallel
    task_rhside = Threads.@spawn Curve.curve_miller(Config.G2, sig.sig)
    tasks_lhside = [Threads.@spawn(Curve.curve_miller(pair.first.pk, pair.second.hash)) for pair in pkhashpairs]
    task_lhside = reducetasks(*, tasks_lhside)
    res = Curve.field_final_exp(fetch(task_lhside) // fetch(task_rhside))
    return res == one(typeof(res))
end
