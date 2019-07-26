const SMALL_SIGNATURES = get(ENV, "PBC_SMALL_SIGNATURES", "n") == "y"

macro EP()
    return SMALL_SIGNATURES ? :(Curve.EP) : :(Curve.EP2)
end
macro EP2()
    return SMALL_SIGNATURES ? :(Curve.EP2) : :(Curve.EP)
end

const GEN = Curve.curve_gen(@EP2)
const PUBLIC_KEY_SIZE = sizeof(GEN.x)
const SIGNATURE_SIZE = sizeof(Curve.curve_gen(@EP).x)

const PRIME = Curve.fp_prime_get()
const ORDER = Curve.curve_order(@EP)

# Effective number of bits required to store the private key
const PRIVATE_KEY_SIZE_BITS = ceil(Int, log2(BigInt(ORDER)))

# Effective number of bytes required to store the private key
const PRIVATE_KEY_SIZE = ceil(Int, PRIVATE_KEY_SIZE_BITS // 8)

# whether or not we have bits over for encoding LSB(y)
const CAN_STUFF_Y = ceil(Int, log2(BigInt(PRIME))) < (8 * Curve.FP_ST_SIZE)
