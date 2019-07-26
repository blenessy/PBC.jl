module UnitTests

using Test
using PBC

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


end