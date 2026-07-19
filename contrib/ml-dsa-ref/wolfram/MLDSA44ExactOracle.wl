BeginPackage["MLDSA44ExactOracle`"];

MLDSA44Parameters::usage =
  "MLDSA44Parameters[] returns the exact FIPS 204 ML-DSA-44 constants used by this model.";
MLDSA44CenteredMod::usage =
  "MLDSA44CenteredMod[x, m] returns the representative r with -Ceiling[m/2] < r <= Floor[m/2].";
MLDSA44BitReverse8::usage =
  "MLDSA44BitReverse8[i] reverses the eight bits of an integer from 0 through 255.";
MLDSA44ZetaTable::usage =
  "MLDSA44ZetaTable[] returns the 255 FIPS 204 NTT twiddle factors.";
MLDSA44NTT::usage =
  "MLDSA44NTT[p] applies FIPS 204 Algorithm 41 to a 256-coefficient polynomial.";
MLDSA44DirectNTT::usage =
  "MLDSA44DirectNTT[p] evaluates the defining FIPS 204 NTT equation directly.";
MLDSA44InverseNTT::usage =
  "MLDSA44InverseNTT[w] applies FIPS 204 Algorithm 42.";
MLDSA44PointwiseMultiply::usage =
  "MLDSA44PointwiseMultiply[a, b] multiplies two NTT representations coefficient-wise.";
MLDSA44NegacyclicMultiply::usage =
  "MLDSA44NegacyclicMultiply[a, b] multiplies in Z_q[X]/(X^256 + 1) by direct convolution.";
MLDSA44Power2Round::usage =
  "MLDSA44Power2Round[r] applies FIPS 204 Algorithm 35 for d = 13.";
MLDSA44Decompose::usage =
  "MLDSA44Decompose[r] applies FIPS 204 Algorithm 36 for ML-DSA-44.";
MLDSA44HighBits::usage =
  "MLDSA44HighBits[r] returns the high part from MLDSA44Decompose[r].";
MLDSA44LowBits::usage =
  "MLDSA44LowBits[r] returns the low part from MLDSA44Decompose[r].";
MLDSA44MakeHint::usage =
  "MLDSA44MakeHint[z, r] applies FIPS 204 Algorithm 39.";
MLDSA44UseHint::usage =
  "MLDSA44UseHint[h, r] applies FIPS 204 Algorithm 40.";
MLDSA44HintBitPack::usage =
  "MLDSA44HintBitPack[h] applies FIPS 204 Algorithm 20 to four binary polynomials.";
MLDSA44HintBitUnpack::usage =
  "MLDSA44HintBitUnpack[y] applies the strict FIPS 204 Algorithm 21 decoder or returns $Failed.";
MLDSA44MontgomeryReduce::usage =
  "MLDSA44MontgomeryReduce[a] applies FIPS 204 Algorithm 49 using exact integers.";

Begin["`Private`"];

$q = 8380417;
$n = 256;
$d = 13;
$zeta = 1753;
$k = 4;
$l = 4;
$eta = 2;
$tau = 39;
$beta = 78;
$gamma1 = 2^17;
$gamma2 = Quotient[$q - 1, 88];
$omega = 80;
$alpha = 2 $gamma2;
$highModulus = Quotient[$q - 1, $alpha];
$inverseN = 8347681;
$montgomeryQInverse = 58728449;
$montgomeryRadix = 2^32;

MLDSA44Parameters[] := <|
  "name" -> "ML-DSA-44",
  "q" -> $q,
  "n" -> $n,
  "d" -> $d,
  "zeta" -> $zeta,
  "k" -> $k,
  "l" -> $l,
  "eta" -> $eta,
  "tau" -> $tau,
  "beta" -> $beta,
  "gamma1" -> $gamma1,
  "gamma2" -> $gamma2,
  "omega" -> $omega,
  "alpha" -> $alpha,
  "high_modulus" -> $highModulus,
  "inverse_n" -> $inverseN,
  "montgomery_q_inverse" -> $montgomeryQInverse,
  "public_key_bytes" -> 1312,
  "private_key_bytes" -> 2560,
  "signature_bytes" -> 2420
|>;

MLDSA44CenteredMod[x_Integer, modulus_Integer?Positive] :=
  Mod[x + Ceiling[modulus/2] - 1, modulus] - Ceiling[modulus/2] + 1;
MLDSA44CenteredMod[___] := $Failed;

MLDSA44BitReverse8[i_Integer] /; 0 <= i < 256 :=
  FromDigits[Reverse[IntegerDigits[i, 2, 8]], 2];
MLDSA44BitReverse8[___] := $Failed;

$zetaTable = Table[
  PowerMod[$zeta, MLDSA44BitReverse8[m], $q],
  {m, 1, $n - 1}
];

MLDSA44ZetaTable[] := $zetaTable;

validPolynomialQ[p_] :=
  ListQ[p] && Length[p] == $n && VectorQ[p, IntegerQ];

validHintQ[h_] :=
  MatrixQ[h, Function[x, x === 0 || x === 1]] &&
    Dimensions[h] == {$k, $n};

validByteVectorQ[y_] :=
  VectorQ[y, Function[x, IntegerQ[x] && 0 <= x <= 255]];

MLDSA44NTT[p_?validPolynomialQ] := Module[
  {w = Mod[p, $q], m = 0, length = 128, start, j, z, u, v, t},
  While[length >= 1,
    start = 0;
    While[start < $n,
      m = m + 1;
      z = $zetaTable[[m]];
      Do[
        u = w[[j + 1]];
        v = w[[j + length + 1]];
        t = Mod[z v, $q];
        w[[j + 1]] = Mod[u + t, $q];
        w[[j + length + 1]] = Mod[u - t, $q],
        {j, start, start + length - 1}
      ];
      start = start + 2 length;
    ];
    length = Quotient[length, 2];
  ];
  w
];
MLDSA44NTT[___] := $Failed;

MLDSA44DirectNTT[p_?validPolynomialQ] := Module[
  {coefficients = Reverse[Mod[p, $q]], root},
  Table[
    root = PowerMod[$zeta, 2 MLDSA44BitReverse8[i] + 1, $q];
    Fold[
      Function[{accumulator, coefficient},
        Mod[accumulator root + coefficient, $q]
      ],
      0,
      coefficients
    ],
    {i, 0, $n - 1}
  ]
];
MLDSA44DirectNTT[___] := $Failed;

MLDSA44InverseNTT[input_?validPolynomialQ] := Module[
  {w = Mod[input, $q], m = 256, length = 1, start, j, z, u, v},
  While[length < $n,
    start = 0;
    While[start < $n,
      m = m - 1;
      z = Mod[-$zetaTable[[m]], $q];
      Do[
        u = w[[j + 1]];
        v = w[[j + length + 1]];
        w[[j + 1]] = Mod[u + v, $q];
        w[[j + length + 1]] = Mod[z (u - v), $q],
        {j, start, start + length - 1}
      ];
      start = start + 2 length;
    ];
    length = 2 length;
  ];
  Mod[$inverseN w, $q]
];
MLDSA44InverseNTT[___] := $Failed;

MLDSA44PointwiseMultiply[a_?validPolynomialQ, b_?validPolynomialQ] :=
  Mod[a b, $q];
MLDSA44PointwiseMultiply[___] := $Failed;

MLDSA44NegacyclicMultiply[a_?validPolynomialQ, b_?validPolynomialQ] := Module[
  {result = ConstantArray[0, $n], i, j, index, term},
  Do[
    index = i + j;
    term = a[[i + 1]] b[[j + 1]];
    If[index < $n,
      result[[index + 1]] = result[[index + 1]] + term,
      result[[index - $n + 1]] = result[[index - $n + 1]] - term
    ],
    {i, 0, $n - 1},
    {j, 0, $n - 1}
  ];
  Mod[result, $q]
];
MLDSA44NegacyclicMultiply[___] := $Failed;

MLDSA44Power2Round[r_Integer] := Module[{rPositive, r0},
  rPositive = Mod[r, $q];
  r0 = MLDSA44CenteredMod[rPositive, 2^$d];
  {Quotient[rPositive - r0, 2^$d], r0}
];
MLDSA44Power2Round[___] := $Failed;

MLDSA44Decompose[r_Integer] := Module[{rPositive, r0},
  rPositive = Mod[r, $q];
  r0 = MLDSA44CenteredMod[rPositive, $alpha];
  If[rPositive - r0 == $q - 1,
    {0, r0 - 1},
    {Quotient[rPositive - r0, $alpha], r0}
  ]
];
MLDSA44Decompose[___] := $Failed;

MLDSA44HighBits[r_Integer] := First[MLDSA44Decompose[r]];
MLDSA44HighBits[___] := $Failed;

MLDSA44LowBits[r_Integer] := Last[MLDSA44Decompose[r]];
MLDSA44LowBits[___] := $Failed;

MLDSA44MakeHint[z_Integer, r_Integer] :=
  Boole[MLDSA44HighBits[r] != MLDSA44HighBits[r + z]];
MLDSA44MakeHint[___] := $Failed;

MLDSA44UseHint[h_Integer, r_Integer] /; h === 0 || h === 1 := Module[
  {decomposition, r1, r0},
  decomposition = MLDSA44Decompose[r];
  r1 = First[decomposition];
  r0 = Last[decomposition];
  If[h == 0,
    r1,
    If[r0 > 0,
      Mod[r1 + 1, $highModulus],
      Mod[r1 - 1, $highModulus]
    ]
  ]
];
MLDSA44UseHint[___] := $Failed;

MLDSA44HintBitPack[h_?validHintQ] := If[
  Total[Flatten[h]] > $omega,
  $Failed,
  Module[
    {encoded = ConstantArray[0, $omega + $k], index = 0, positions, i, position},
    Do[
      positions = Flatten[Position[h[[i]], 1]] - 1;
      Do[
        position = positions[[j]];
        encoded[[index + 1]] = position;
        index = index + 1,
        {j, Length[positions]}
      ];
      encoded[[$omega + i]] = index,
      {i, 1, $k}
    ];
    encoded
  ]
];
MLDSA44HintBitPack[___] := $Failed;

MLDSA44HintBitUnpack[encoded_List] := Catch[
  Module[
    {h, index = 0, count, segment, i, j},
    If[Length[encoded] != $omega + $k || !validByteVectorQ[encoded],
      Throw[$Failed, hintDecodeFailure]
    ];
    h = ConstantArray[0, {$k, $n}];
    Do[
      count = encoded[[$omega + i]];
      If[count < index || count > $omega,
        Throw[$Failed, hintDecodeFailure]
      ];
      segment = If[count > index,
        Take[encoded, {index + 1, count}],
        {}
      ];
      If[
        Length[segment] > 1 &&
          !TrueQ[And @@ Thread[Rest[segment] > Most[segment]]],
        Throw[$Failed, hintDecodeFailure]
      ];
      Do[
        h[[i, segment[[j]] + 1]] = 1,
        {j, Length[segment]}
      ];
      index = count,
      {i, 1, $k}
    ];
    If[
      index < $omega && AnyTrue[Take[encoded, {index + 1, $omega}], # != 0 &],
      Throw[$Failed, hintDecodeFailure]
    ];
    h
  ],
  hintDecodeFailure
];
MLDSA44HintBitUnpack[___] := $Failed;

MLDSA44MontgomeryReduce[a_Integer] /; Abs[a] <= 2^31 $q := Module[{t},
  t = MLDSA44CenteredMod[a $montgomeryQInverse, $montgomeryRadix];
  Quotient[a - t $q, $montgomeryRadix]
];
MLDSA44MontgomeryReduce[___] := $Failed;

End[];
EndPackage[];
