module UnitTests

using Test
using BLS381

const ORDER = big"0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"

@testset "PrivateKey" begin
    @test PrivateKey().data < BLS381.ORDER
    @test !iszero(PrivateKey().data)

    pk = PrivateKey(UInt8[1, 2, 3])
    @test pk.data < BLS381.ORDER
    @test pk.data == 112780983386942064477039392768719636661707621010135109825218843405688688614395
end

end