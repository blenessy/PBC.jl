using .Curve: BN, EP, EP2, EPX, Limb, md_sha256
using .Config: PRIVATE_KEY_SIZE_BITS, ORDER, G1, G2, CAN_STUFF_Y

const Point = EPX

function decode(::Type{T}, bytes::Vector{UInt8}) where {T <: Point}
    tmp = UInt8[
        0x2 | (bytes[1] & 0x80) >> 7,
        bytes[1] & 0x7f,
        bytes[2:end]...
    ]
    return T(tmp)
end

function encode(point::Point)
    bufsize = sizeof(point.x) + 1
    buf = Vector{UInt8}(point)
    @assert CAN_STUFF_Y # other case not implemented
    buf[2] |= (buf[1] & 0x1) << 7
    deleteat!(buf, 1)
    return buf
end

function gensk()
    # Throw away keys that are outside of the allowed key space
    # (mod break the uniform key distribution)
    while true
        sk = rand(BN, bits=PRIVATE_KEY_SIZE_BITS)
        if sk < ORDER
            return sk
        end
    end
end

#hash2curve(msg::Vector{UInt8}) = Curve.curve_map(Config.@EP, msg)
hash2curve(msg::Vector{UInt8}) = BN(md_sha256(msg)) * G1

sign(sk::BN, p::Point) = sk * p
genpk(sk::BN) = sk * G2

