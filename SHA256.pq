// SHA256

let
    HashFunction = (input as text) as text =>
    let
        U32 = (x as number) as number =>
            Number.Mod(Number.RoundDown(x), 4294967296),

        Not32 = (x as number) as number =>
            Number.BitwiseXor(U32(x), 4294967295),

        ROTR = (x as number, n as number) as number =>
            Number.BitwiseOr(
                Number.BitwiseShiftRight(
                    Number.BitwiseAnd(x, 4294967295),
                    n
                ),
                Number.BitwiseAnd(
                    Number.BitwiseShiftLeft(x, 32 - n),
                    4294967295
                )
            ),

        SHR = (x as number, n as number) as number =>
            Number.BitwiseShiftRight(U32(x), n),

        Ch = (x as number, y as number, z as number) as number =>
            Number.BitwiseXor(
                Number.BitwiseAnd(x, y),
                Number.BitwiseAnd(Not32(x), z)
            ),

        Maj = (x as number, y as number, z as number) as number =>
            Number.BitwiseXor(
                Number.BitwiseXor(
                    Number.BitwiseAnd(x, y),
                    Number.BitwiseAnd(x, z)
                ),
                Number.BitwiseAnd(y, z)
            ),

        BigSigma0 = (x as number) as number =>
            Number.BitwiseXor(Number.BitwiseXor(ROTR(x, 2), ROTR(x, 13)), ROTR(x, 22)),

        BigSigma1 = (x as number) as number =>
            Number.BitwiseXor(Number.BitwiseXor(ROTR(x, 6), ROTR(x, 11)), ROTR(x, 25)),

        SmallSigma0 = (x as number) as number =>
            Number.BitwiseXor(Number.BitwiseXor(ROTR(x, 7), ROTR(x, 18)), SHR(x, 3)),

        SmallSigma1 = (x as number) as number =>
            Number.BitwiseXor(Number.BitwiseXor(ROTR(x, 17), ROTR(x, 19)), SHR(x, 10)),

        Bytes = Binary.ToList(Text.ToBinary(input, TextEncoding.Utf8)),
        BitLength = List.Count(Bytes) * 8,

        WithOneBit = Bytes & {128},
        PaddingLength = Number.Mod(56 - Number.Mod(List.Count(WithOneBit), 64) + 64, 64),
        Padding = List.Repeat({0}, PaddingLength),

        LengthBytes =
            List.Transform(
                List.Reverse({0..7}),
                each Number.Mod(Number.IntegerDivide(BitLength, Number.Power(256, _)), 256)
            ),

        Message = WithOneBit & Padding & LengthBytes,

        K = {
            1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,
            3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,
            3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,
            2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,
            666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,
            2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,
            430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,
            1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298
        },

        InitialHash = {
            1779033703,3144134277,1013904242,2773480762,
            1359893119,2600822924,528734635,1541459225
        },

        Chunks =
            List.Transform(
                List.Split(Message, 64),
                each List.Transform(
                    List.Split(_, 4),
                    each U32(_{0} * 16777216 + _{1} * 65536 + _{2} * 256 + _{3})
                )
            ),

        FinalHash =
            List.Accumulate(
                Chunks,
                InitialHash,
                (hash, chunk) =>
                    let
                        W =
                            List.Accumulate(
                                {16..63},
                                chunk,
                                (state, i) =>
                                    state & {
                                        U32(
                                            SmallSigma1(state{i - 2}) +
                                            state{i - 7} +
                                            SmallSigma0(state{i - 15}) +
                                            state{i - 16}
                                        )
                                    }
                            ),

                        StartState = [
                            a = hash{0}, b = hash{1}, c = hash{2}, d = hash{3},
                            e = hash{4}, f = hash{5}, g = hash{6}, h = hash{7}
                        ],

                        Compressed =
                            List.Accumulate(
                                {0..63},
                                StartState,
                                (s, i) =>
                                    let
                                        t1 = U32(s[h] + BigSigma1(s[e]) + Ch(s[e], s[f], s[g]) + K{i} + W{i}),
                                        t2 = U32(BigSigma0(s[a]) + Maj(s[a], s[b], s[c]))
                                    in
                                        [
                                            a = U32(t1 + t2),
                                            b = s[a],
                                            c = s[b],
                                            d = s[c],
                                            e = U32(s[d] + t1),
                                            f = s[e],
                                            g = s[f],
                                            h = s[g]
                                        ]
                            ),

                        NewHash = {
                            U32(hash{0} + Compressed[a]),
                            U32(hash{1} + Compressed[b]),
                            U32(hash{2} + Compressed[c]),
                            U32(hash{3} + Compressed[d]),
                            U32(hash{4} + Compressed[e]),
                            U32(hash{5} + Compressed[f]),
                            U32(hash{6} + Compressed[g]),
                            U32(hash{7} + Compressed[h])
                        }
                    in
                        NewHash
            ),

            ToHex8 = (n as number) as text =>
                Text.Combine(
                    List.Transform(
                        List.Reverse({0..7}),
                        each Text.Middle(
                            "0123456789abcdef",
                            Number.Mod(Number.IntegerDivide(n, Number.Power(16, _)), 16),
                            1
                        )
                    ),
                    ""
                ),


        Result = Text.Combine(List.Transform(FinalHash, each ToHex8(_)), "")
    in
        Result
in
    HashFunction
