module UnitTests

using Test
using PBC

using PBC.Curve: BN, FP, EP, EP2, curve_gen, LIB
using PBC.Config: ORDER
using PBC.Util: index

using PBC.Shamir: evalpoly, LagrangeCoeffGenerator, BarycentricWeightGenerator, lagrange_interpolate_c0


@testset "lagrange_interpolate_c0 - trivial" begin
    for idtype in (EP, EP2)
        ids = (rand(idtype), rand(idtype))
        for c in (BN(1), curve_gen(EP), curve_gen(EP2))
            poly = [c, c] # derive secret coeffs from c
            shares = Dict(index(id)=>evalpoly(poly, index(id)) for id in ids)
            @test lagrange_interpolate_c0(BarycentricWeightGenerator, shares) == c
            @test lagrange_interpolate_c0(LagrangeCoeffGenerator, shares) == c
            @test lagrange_interpolate_c0(shares) == c
        end
    end
end

@testset "Shamir: lagrange_interpolate_c0 - complex" begin
    for idtype in (EP, EP2)
        ids = (rand(idtype), rand(idtype), rand(idtype), rand(idtype), rand(idtype))
        n = length(ids)
        for c in (BN(123), 123 * curve_gen(EP), 123 * curve_gen(EP2))
            poly = [c, 2c, 3c] # derive secret coeffs from c
            shares = Dict(index(id)=>evalpoly(poly, index(id)) for id in ids)
            t = length(poly)
            for i in 1:n-t+1
                r = i:i+t-1
                @test lagrange_interpolate_c0(BarycentricWeightGenerator, shares) == c
                @test lagrange_interpolate_c0(LagrangeCoeffGenerator, shares) == c
                @test lagrange_interpolate_c0(shares) == c
            end
        end
    end
end

@testset "Shamir: LagrangeCoeffGenerator" begin
    coeffs = LagrangeCoeffGenerator()
    # generate first coeff
    @test push!(coeffs, 1) == BN(1)

    # generate second coeff
    @test push!(coeffs, 2) == ORDER - 1
    @test push!(coeffs, 1) == BN(2)

    # generate third share
    @test push!(coeffs, 3) == BN(1)
    @test push!(coeffs, 2) == ORDER - 3
    @test push!(coeffs, 1) == BN(3)

    # delete third share
    delete!(coeffs, 3)
    @test length(coeffs) == 2
    @test push!(coeffs, 2) == ORDER - 1
    @test push!(coeffs, 1) == BN(2)
end

@testset "Shamir: BarycentricWeightGenerator" begin
    weights = BarycentricWeightGenerator()
    # generate first coeff
    @test push!(weights, 1) == ORDER - 1

    # generate second coeff
    @test push!(weights, 2) == BN(2)
    @test push!(weights, 1) == ORDER - 1

    # generate third share
    @test push!(weights, 3) == ORDER - 6
    @test push!(weights, 2) == BN(2)
    @test push!(weights, 1) == ORDER - 2

    # delete third share
    delete!(weights, 3)
    @test length(weights) == 2
    @test push!(weights, 2) == BN(2)
    @test push!(weights, 1) == ORDER - 1
end

@testset "hash of Points" begin
    for i in 1:1000
        p, q = rand(EP), rand(EP2)
        @test !signbit(index(p))
        @test !signbit(index(q))
    end
end

@testset "PrivateKey" begin
    # generate random with default RNG
    @test rand(PrivateKey).sk < PBC.Config.PRIME

    # from bytes
    sk = PrivateKey(UInt8[1, 2, 3])
    @test sk.sk < PBC.Config.PRIME
    @test sk.sk.dp[1] == 1 << 16 | 2 << 8 | 3
    @test !iszero(sk) && isvalid(sk)

    # serialization
    @test length(Vector{UInt8}(sk)) == PBC.Config.PRIVATE_KEY_SIZE
    @test PrivateKey(Vector{UInt8}(sk)) == sk
end

@testset "PublicKey" begin
    # generate from secret
    sk = PrivateKey(UInt8[1, 2, 3])
    pk = PublicKey(sk)
    @test !isinf(pk) && isvalid(pk)

    # serialization
    @test length(Vector{UInt8}(pk)) == PBC.Config.PUBLIC_KEY_SIZE
    @test PublicKey(Vector{UInt8}(pk)) == pk
end

@testset "Hash" begin
    hash = Hash("foo")
    @test !isinf(hash) && isvalid(hash)
end

@testset "sign & verify" begin
    sk = PrivateKey(UInt8[1, 2, 3])
    sig = PBC.sign(sk, "foo")
    @test !isinf(sig) && isvalid(sig)
    @test PBC.verify(sig, PublicKey(sk), "foo")
    @test !PBC.verify(sig, PublicKey(sk), "bar")
end

@testset "simple aggregation" begin
    sk1, sk2, sk3 = PrivateKey(UInt8[1, 2, 3]), PrivateKey(UInt8[2, 3, 4]), PrivateKey(UInt8[3, 4, 5])
    pk1, pk2, pk3 = PublicKey(sk1), PublicKey(sk2), PublicKey(sk3)
    sig1, sig2, sig3 = PBC.sign(sk1, "foo"), PBC.sign(sk2, "foo"), PBC.sign(sk3, "foo")
    @test PBC.verify(sig1 + sig2, pk1 + pk2, "foo")
    @test !PBC.verify(sig2, pk1 + pk2, "foo")
    @test pk1 - pk1 + pk2 == pk1 + pk2 - pk1
    @test PBC.verify(sig2, pk1 - pk1 + pk2, "foo")
end

@testset "advanced aggregation" begin
    sk1, sk2, sk3 = PrivateKey(UInt8[1, 2, 3]), PrivateKey(UInt8[2, 3, 4]), PrivateKey(UInt8[3, 4, 5])
    pk1, pk2, pk3 = PublicKey(sk1), PublicKey(sk2), PublicKey(sk3)
    msg1, msg2, msg3 = "foo", "bar", "baz"
    sig1, sig2, sig3 = PBC.sign(sk1, msg1), PBC.sign(sk2, msg2), PBC.sign(sk3, msg3)
    @test PBC.verify(sig1 + sig2, (pk1 => Hash(msg1), pk2 => Hash(msg2)))
    @test !PBC.verify(sig1 + sig2, (pk1 => Hash(msg1),))
end

@testset "invalid aggregation" begin
    sk = PrivateKey(UInt8[1, 2, 3])
    @test_throws ErrorException PBC.verify(PBC.sign(sk, "foo"), [])
end

@testset "Shamir: evalpoly" begin
    for c in (BN(123), curve_gen(EP), curve_gen(EP2))
        poly = [c, 2c, 3c]
        @test evalpoly(poly, 0) == c
        @test evalpoly(poly, 1) == c + 2c + 3c
        @test evalpoly(poly, 2) == c + 2c * 2 + 3c * 2^2
    end
end

end