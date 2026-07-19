oracleDirectory = DirectoryName[$InputFileName];
If[!NameQ["MLDSA44ExactOracle`MLDSA44Parameters"],
  Get[FileNameJoin[{oracleDirectory, "MLDSA44ExactOracle.wl"}]]
];

parameters = MLDSA44Parameters[];
q = parameters["q"];
n = parameters["n"];
d = parameters["d"];
zeta = parameters["zeta"];
gamma2 = parameters["gamma2"];
alpha = parameters["alpha"];
omega = parameters["omega"];

polynomialA = Table[Mod[j^3 + 7 j + 11, q], {j, 0, n - 1}];
polynomialB = Table[Mod[5 j^2 + 3 j + 19, q], {j, 0, n - 1}];

boundaryResidues = DeleteDuplicates[Mod[
  Flatten[Table[
    k alpha + delta,
    {k, 0, Quotient[q - 1, alpha]},
    {delta, {
      -gamma2 - 1, -gamma2, -gamma2 + 1, -1, 0, 1,
      gamma2 - 1, gamma2, gamma2 + 1
    }}
  ]],
  q
]];

hintOffsets = {-gamma2 + 1, -1, 0, 1, gamma2 - 1};

validHint = ConstantArray[0, {parameters["k"], n}];
Scan[(validHint[[1, # + 1]] = 1) &, {0, 3, 255}];
Scan[(validHint[[2, # + 1]] = 1) &, {1, 2}];
Scan[(validHint[[3, # + 1]] = 1) &, {42}];
Scan[(validHint[[4, # + 1]] = 1) &, {7, 9, 10, 200}];
packedHint = MLDSA44HintBitPack[validHint];

VerificationTest[
  Lookup[
    parameters,
    {
      "q", "n", "d", "zeta", "k", "l", "eta", "tau", "beta",
      "gamma1", "gamma2", "omega", "alpha", "high_modulus",
      "inverse_n", "montgomery_q_inverse", "public_key_bytes",
      "private_key_bytes", "signature_bytes"
    }
  ],
  {
    8380417, 256, 13, 1753, 4, 4, 2, 39, 78, 131072, 95232, 80,
    190464, 44, 8347681, 58728449, 1312, 2560, 2420
  },
  TestID -> "FIPS 204 ML-DSA-44 constants"
]

VerificationTest[
  {
    PrimeQ[q],
    Mod[q - 1, 512],
    PowerMod[zeta, 256, q],
    PowerMod[zeta, 512, q],
    Mod[n parameters["inverse_n"], q],
    Mod[q parameters["montgomery_q_inverse"], 2^32]
  },
  {True, 0, q - 1, 1, 1, 1},
  TestID -> "Prime field, primitive root, inverse, and Montgomery facts"
]

VerificationTest[
  Take[MLDSA44ZetaTable[], 15],
  {
    4808194, 3765607, 3761513, 5178923, 5496691,
    5234739, 5178987, 7778734, 3542485, 2682288,
    2129892, 3764867, 7375178, 557458, 7159240
  },
  TestID -> "Appendix B leading zeta values"
]

VerificationTest[
  MLDSA44NTT[polynomialA],
  MLDSA44DirectNTT[polynomialA],
  TestID -> "Algorithm 41 agrees with the defining NTT equation"
]

VerificationTest[
  MLDSA44InverseNTT[MLDSA44NTT[polynomialA]],
  polynomialA,
  TestID -> "Algorithms 41 and 42 round trip a dense polynomial"
]

VerificationTest[
  MLDSA44InverseNTT[
    MLDSA44PointwiseMultiply[
      MLDSA44NTT[polynomialA],
      MLDSA44NTT[polynomialB]
    ]
  ],
  MLDSA44NegacyclicMultiply[polynomialA, polynomialB],
  TestID -> "NTT pointwise product equals direct negacyclic convolution"
]

VerificationTest[
  {
    MLDSA44CenteredMod[-5, 10],
    MLDSA44CenteredMod[5, 10],
    MLDSA44CenteredMod[6, 10],
    MLDSA44CenteredMod[-4, 10]
  },
  {5, 5, -4, -4},
  TestID -> "Centered reduction uses the FIPS half-open interval"
]

VerificationTest[
  And @@ Table[
    With[{parts = MLDSA44Power2Round[r]},
      Mod[First[parts] 2^d + Last[parts], q] == Mod[r, q] &&
        -2^(d - 1) < Last[parts] <= 2^(d - 1) &&
        0 <= First[parts] <= 1023
    ],
    {r, boundaryResidues}
  ],
  True,
  TestID -> "Power2Round reconstructs boundary residues within exact bounds"
]

VerificationTest[
  MLDSA44Decompose /@ {
    0,
    gamma2,
    gamma2 + 1,
    q - gamma2 - 1,
    q - gamma2,
    q - 1
  },
  {
    {0, 0},
    {0, gamma2},
    {1, -gamma2 + 1},
    {43, gamma2},
    {0, -gamma2},
    {0, -1}
  },
  TestID -> "Decompose handles the q minus one special boundary"
]

VerificationTest[
  And @@ Table[
    With[{parts = MLDSA44Decompose[r]},
      Mod[First[parts] alpha + Last[parts], q] == Mod[r, q] &&
        0 <= First[parts] < parameters["high_modulus"] &&
        -gamma2 <= Last[parts] <= gamma2
    ],
    {r, boundaryResidues}
  ],
  True,
  TestID -> "Decompose reconstructs boundary residues within exact bounds"
]

VerificationTest[
  And @@ Flatten[Table[
    MLDSA44UseHint[MLDSA44MakeHint[z, r], r] == MLDSA44HighBits[r + z],
    {r, boundaryResidues},
    {z, hintOffsets}
  ]],
  True,
  TestID -> "MakeHint and UseHint agree across 1335 boundary cases"
]

VerificationTest[
  MLDSA44HintBitUnpack[packedHint],
  validHint,
  TestID -> "HintBitPack and HintBitUnpack strict round trip"
]

VerificationTest[
  Module[{malformed = packedHint},
    malformed[[2]] = malformed[[1]];
    MLDSA44HintBitUnpack[malformed]
  ],
  $Failed,
  TestID -> "HintBitUnpack rejects repeated positions"
]

VerificationTest[
  Module[{malformed = packedHint},
    malformed[[omega + 2]] = malformed[[omega + 1]] - 1;
    MLDSA44HintBitUnpack[malformed]
  ],
  $Failed,
  TestID -> "HintBitUnpack rejects decreasing cumulative counts"
]

VerificationTest[
  Module[{malformed = packedHint},
    malformed[[omega + 1]] = omega + 1;
    MLDSA44HintBitUnpack[malformed]
  ],
  $Failed,
  TestID -> "HintBitUnpack rejects cumulative counts above omega"
]

VerificationTest[
  Module[{malformed = packedHint, used = packedHint[[omega + parameters["k"]]]},
    malformed[[used + 1]] = 1;
    MLDSA44HintBitUnpack[malformed]
  ],
  $Failed,
  TestID -> "HintBitUnpack rejects nonzero padding"
]

VerificationTest[
  And @@ Table[
    With[{reduced = MLDSA44MontgomeryReduce[a]},
      IntegerQ[reduced] &&
        Mod[reduced 2^32 - a, q] == 0 &&
        Abs[reduced] <= q
    ],
    {a, {
      -2^31 q, -2^31 q + 1, -q^2, -q, -1, 0,
      1, q, q^2, 2^31 q - 1, 2^31 q
    }}
  ],
  True,
  TestID -> "MontgomeryReduce boundary congruence and output bound"
]

VerificationTest[
  {
    MLDSA44NTT[ConstantArray[0, n - 1]],
    MLDSA44HintBitUnpack[ConstantArray[0, omega + parameters["k"] - 1]],
    MLDSA44MontgomeryReduce[2^31 q + 1]
  },
  {$Failed, $Failed, $Failed},
  TestID -> "Model rejects values outside its bounded contracts"
]
