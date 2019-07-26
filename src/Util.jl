const Point = Curve.EPX

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
    @assert Config.CAN_STUFF_Y # other case not implemented
    buf[2] |= (buf[1] & 0x1) << 7
    deleteat!(buf, 1)
    return buf
end

hash2curve(msg::Vector{UInt8}) = Curve.curve_map(Config.@EP, msg)

sign(sk::Curve.BN, p::Point) = sk * p
genpk(sk::Curve.BN) = sk * Config.GEN
