module BLS381

export PrivateKey

# Pick the correct lib to use
ENV["RELICLIB"] = "librelic_gmp_pbc_bls381"

using RelicToolkit

const PRIVATE_KEY_SIZE = 32

# "BLS private key seed" in ascii
const HMAC_KEY = UInt8[
    66, 76, 83, 32, 112, 114, 105, 118, 97, 116, 101,
    32, 107, 101, 121, 32, 115, 101, 101, 100]

const ORDER = RelicToolkit.fp_prime_get()

struct PrivateKey
    data::BN
    PrivateKey() = new(BN(rand(FP)))
    function PrivateKey(seed::Vector{UInt8})
        hash = RelicToolkit.md_hmac(seed, HMAC_KEY)
        bn = RelicToolkit.bn_read_bin(hash)
        return new(RelicToolkit.bn_mod_basic!(bn, bn, RelicToolkit.fp_prime_get()))
    end
end

end # module
