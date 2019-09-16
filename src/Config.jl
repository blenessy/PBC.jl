const SMALL_SIGNATURES = get(ENV, "PBC_SMALL_SIGNATURES", "n") == "y"
const SMALL_IDENTITIES = get(ENV, "PBC_SMALL_IDENTITIES", "y") == "y"
const NPROCS = get(ENV, "PBC_NPROCS", "") == "auto" ? Sys.CPU_THREADS : parse(Int, get(ENV, "PBC_NPROCS", "1"))
const BATCH_SIZE = Threads.nthreads() * parse(Int, get(ENV, "PBC_BATCH_SCALE_FACTOR", "1024"))

macro EP()
    return SMALL_SIGNATURES ? :(Curve.EP) : :(Curve.EP2)
end
macro EP2()
    return SMALL_SIGNATURES ? :(Curve.EP2) : :(Curve.EP)
end
macro ID()
    return SMALL_IDENTITIES ? :(Int64) : :(Int128)
end

const G1 = Curve.curve_gen(@EP)
const G2 = Curve.curve_gen(@EP2)
const PUBLIC_KEY_SIZE = sizeof(G2.x)
const SIGNATURE_SIZE = sizeof(G1.x)

const PRIME = Curve.fp_prime_get()
const ORDER = Curve.curve_order(@EP)

# Effective number of bits required to store the private key
const PRIVATE_KEY_SIZE_BITS = ceil(Int, log2(BigInt(ORDER)))

# Effective number of bytes required to store the private key
const PRIVATE_KEY_SIZE = ceil(Int, PRIVATE_KEY_SIZE_BITS // 8)

# whether or not we have bits over for encoding LSB(y)
const CAN_STUFF_Y = ceil(Int, log2(BigInt(PRIME))) < (8 * Curve.FP_ST_SIZE)
