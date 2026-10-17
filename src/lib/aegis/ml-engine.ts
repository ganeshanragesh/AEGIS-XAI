/**
 * AEGIS-XAI Hybrid Detection Engine
 *
 * Deterministic statistical detection engine used by AEGIS-XAI.
 *
 * Pipeline:
 *
 *   41-feature NetworkFlow
 *          ↓
 *   Feature validation
 *          ↓
 *   RF-style statistical classifier
 *          ↓
 *   XGB-style weighted classifier
 *          ↓
 *   Soft ensemble
 *          ↓
 *   Statistical anomaly detector
 *          ↓
 *   Severity engine
 *          ↓
 *   SHAP-style explanation
 *
 * IMPORTANT:
 *
 * The current implementation is a deterministic statistical
 * approximation based on NSL-KDD-style feature statistics.
 *
 * It is NOT a replacement for independently trained Random Forest
 * and XGBoost model artifacts.
 */

import { FEATURE_NAMES } from "./features";

/* -------------------------------------------------------------------------- */
/* Attack labels                                                              */
/* -------------------------------------------------------------------------- */

export const ATTACK_LABELS: Record<number, string> = {
  0: "Normal",
  1: "DoS",
  2: "Probe",
  3: "R2L",
  4: "U2R",
};

export const LABEL_MAP: Record<string, number> = {
  Normal: 0,
  DoS: 1,
  Probe: 2,
  R2L: 3,
  U2R: 4,
};

export const NUM_CLASSES = 5;

/* -------------------------------------------------------------------------- */
/* Detection thresholds                                                       */
/* -------------------------------------------------------------------------- */

export const CONFIDENCE_THRESHOLD = 0.60;

export const CLASS_MARGIN_THRESHOLD = 0.08;

export const SUPERVISED_ALERT_THRESHOLD = 0.75;

export const ANOMALY_THRESHOLD = 0.72;

export const MIN_ANOMALY_EVIDENCE = 2;

/* -------------------------------------------------------------------------- */
/* NSL-KDD class profiles                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Every class MUST contain exactly 41 mean values and 41 standard
 * deviation values in the exact same order as FEATURE_NAMES.
 *
 * Feature order:
 *
 *  0 duration
 *  1 protocol
 *  2 service
 *  3 flag
 *  4 srcBytes
 *  5 dstBytes
 *  6 land
 *  7 wrongFragment
 *  8 urgent
 *  9 hot
 * 10 numFailedLogins
 * 11 loggedIn
 * 12 numCompromised
 * 13 rootShell
 * 14 suAttempted
 * 15 numRoot
 * 16 numFileCreations
 * 17 numShells
 * 18 numAccessFiles
 * 19 numOutboundCmds
 * 20 isHostLogin
 * 21 isGuestLogin
 * 22 count
 * 23 srvCount
 * 24 serrorRate
 * 25 srvSerrorRate
 * 26 rerrorRate
 * 27 srvRerrorRate
 * 28 sameSrvRate
 * 29 diffSrvRate
 * 30 srvDiffHostRate
 * 31 dstHostCount
 * 32 dstHostSrvCount
 * 33 dstHostSameSrvRate
 * 34 dstHostDiffSrvRate
 * 35 dstHostSameSrcPortRate
 * 36 dstHostSrvDiffHostRate
 * 37 dstHostSerrorRate
 * 38 dstHostSrvSerrorRate
 * 39 dstHostRerrorRate
 * 40 dstHostSrvRerrorRate
 */

interface ClassProfile {
  mean: number[];
  std: number[];
}

const CLASS_FEATURE_PROFILES: Record<
  number,
  ClassProfile
> = {
  /* ---------------------------------------------------------------------- */
  /* Normal                                                                 */
  /* ---------------------------------------------------------------------- */

  0: {
    mean: [
      11.0,
      0.10,
      0.05,
      0.0,
      2500,
      8000,
      0,
      0,
      0,
      0.1,
      0,
      0.65,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      20,
      18,
      0.01,
      0.01,
      0.01,
      0.01,
      0.90,
      0.08,
      0.05,
      200,
      180,
      0.88,
      0.10,
      0.05,
      0.02,
      0.01,
      0.01,
      0.01,
      0.01,
    ],

    std: [
      25.0,
      0.30,
      0.20,
      0.20,
      5000,
      15000,
      0.20,
      0.50,
      0.50,
      0.50,
      1.00,
      0.47,
      1.00,
      0.50,
      0.50,
      1.00,
      1.00,
      1.00,
      1.00,
      1.00,
      0.50,
      0.50,
      15,
      14,
      0.05,
      0.05,
      0.05,
      0.05,
      0.15,
      0.12,
      0.08,
      60,
      55,
      0.15,
      0.12,
      0.10,
      0.05,
      0.05,
      0.05,
      0.05,
      0.05,
    ],
  },

  /* ---------------------------------------------------------------------- */
  /* DoS                                                                    */
  /* ---------------------------------------------------------------------- */

  1: {
    mean: [
      0.5,
      0.02,
      0.01,
      0.9,
      12000,
      500,
      0,
      0,
      0,
      0,
      0,
      0.05,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      480,
      475,
      0.92,
      0.92,
      0.05,
      0.05,
      0.95,
      0.02,
      0.01,
      240,
      240,
      0.95,
      0.02,
      0.92,
      0.01,
      0.92,
      0.92,
      0.01,
      0.01,
    ],

    std: [
      1.2,
      0.10,
      0.05,
      0.30,
      20000,
      1000,
      0.20,
      0.50,
      0.50,
      0.50,
      1.00,
      0.10,
      1.00,
      0.50,
      0.50,
      1.00,
      1.00,
      1.00,
      1.00,
      1.00,
      0.50,
      0.50,
      100,
      98,
      0.12,
      0.12,
      0.10,
      0.10,
      0.08,
      0.05,
      0.03,
      50,
      50,
      0.08,
      0.05,
      0.12,
      0.03,
      0.12,
      0.12,
      0.03,
      0.03,
    ],
  },

  /* ---------------------------------------------------------------------- */
  /* Probe                                                                  */
  /* ---------------------------------------------------------------------- */

  2: {
    mean: [
      0.3,
      0.50,
      0.60,
      0.5,
      300,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      200,
      10,
      0.05,
      0.05,
      0.40,
      0.40,
      0.05,
      0.85,
      0.80,
      255,
      25,
      0.05,
      0.80,
      0.01,
      0.70,
      0.02,
      0.02,
      0.35,
      0.35,
    ],

    std: [
      1.0,
      0.40,
      0.30,
      0.40,
      500,
      0.50,
      0.20,
      0.50,
      0.50,
      0.50,
      1.00,
      0.20,
      1.00,
      0.50,
      0.50,
      1.00,
      1.00,
      1.00,
      1.00,
      1.00,
      0.50,
      0.50,
      90,
      10,
      0.10,
      0.10,
      0.30,
      0.30,
      0.08,
      0.20,
      0.20,
      50,
      25,
      0.08,
      0.20,
      0.02,
      0.20,
      0.05,
      0.05,
      0.25,
      0.25,
    ],
  },

  /* ---------------------------------------------------------------------- */
  /* R2L                                                                    */
  /* ---------------------------------------------------------------------- */

  3: {
    mean: [
      50.0,
      0.05,
      0.15,
      0.2,
      800,
      1200,
      0,
      0,
      0,
      2,
      3,
      0.3,
      1,
      0,
      0,
      0,
      1,
      0,
      1,
      0,
      0,
      0,
      0.1,
      3,
      2,
      0.02,
      0.02,
      0.10,
      0.10,
      0.80,
      0.15,
      0.10,
      25,
      20,
      0.80,
      0.15,
      0.30,
      0.08,
      0.02,
      0.02,
      0.10,
    ],

    std: [
      80.0,
      0.20,
      0.30,
      0.30,
      1500,
      2000,
      0.20,
      0.50,
      0.50,
      3,
      5,
      0.40,
      2,
      0.50,
      0.50,
      1,
      2,
      1,
      2,
      1,
      0.50,
      0.50,
      0.30,
      5,
      4,
      0.05,
      0.05,
      0.15,
      0.15,
      0.20,
      0.20,
      0.15,
      20,
      15,
      0.20,
      0.20,
      0.25,
      0.12,
      0.05,
      0.05,
      0.15,
    ],
  },

  /* ---------------------------------------------------------------------- */
  /* U2R                                                                    */
  /* ---------------------------------------------------------------------- */

  4: {
    mean: [
      100.0,
      0.05,
      0.10,
      0.1,
      1500,
      1000,
      0,
      0,
      0,
      5,
      0,
      0.8,
      4,
      1,
      1,
      2,
      3,
      2,
      3,
      0,
      0,
      0,
      2,
      1,
      0.01,
      0.01,
      0.05,
      0.05,
      0.90,
      0.08,
      0.05,
      10,
      8,
      0.85,
      0.12,
      0.20,
      0.05,
      0.01,
      0.01,
      0.05,
      0.05,
    ],

    std: [
      150.0,
      0.20,
      0.20,
      0.20,
      2500,
      1500,
      0.20,
      1.00,
      0.50,
      8,
      1,
      0.40,
      6,
      0.50,
      0.50,
      3,
      5,
      3,
      5,
      1,
      0.50,
      0.50,
      3,
      2,
      0.02,
      0.02,
      0.10,
      0.10,
      0.15,
      0.12,
      0.08,
      8,
      6,
      0.15,
      0.12,
      0.20,
      0.08,
      0.02,
      0.02,
      0.10,
      0.10,
    ],
  },
};

/* -------------------------------------------------------------------------- */
/* Class priors                                                               */
/* -------------------------------------------------------------------------- */

const CLASS_PRIORS = [
  0.532,
  0.226,
  0.171,
  0.052,
  0.019,
];

/* -------------------------------------------------------------------------- */
/* Feature importance                                                         */
/* -------------------------------------------------------------------------- */

const FEATURE_IMPORTANCE_WEIGHTS = [
  0.052,
  0.008,
  0.005,
  0.024,
  0.142,
  0.198,
  0.001,
  0.003,
  0.001,
  0.008,
  0.003,
  0.028,
  0.005,
  0.012,
  0.008,
  0.010,
  0.008,
  0.006,
  0.008,
  0.001,
  0.002,
  0.002,
  0.048,
  0.035,
  0.062,
  0.038,
  0.022,
  0.018,
  0.025,
  0.042,
  0.018,
  0.032,
  0.028,
  0.024,
  0.018,
  0.015,
  0.012,
  0.042,
  0.028,
  0.015,
  0.012,
];

/* -------------------------------------------------------------------------- */
/* Generic validation/helpers                                                 */
/* -------------------------------------------------------------------------- */

function validateFeatureArray(
  features: number[]
): void {
  if (
    features.length !==
    FEATURE_NAMES.length
  ) {
    throw new Error(
      `Invalid feature count: expected ${FEATURE_NAMES.length}, received ${features.length}`
    );
  }

  for (
    let index = 0;
    index < features.length;
    index += 1
  ) {
    if (
      !Number.isFinite(
        features[index]
      )
    ) {
      throw new Error(
        `Feature ${index} (${FEATURE_NAMES[index]}) is not finite`
      );
    }
  }
}

function clamp(
  value: number,
  min: number,
  max: number
): number {
  return Math.min(
    max,
    Math.max(
      min,
      value
    )
  );
}

function normalizeProbabilities(
  probabilities: number[]
): number[] {
  const sanitized =
    probabilities.map(
      (value) =>
        Number.isFinite(value) &&
        value >= 0
          ? value
          : 0
    );

  const total =
    sanitized.reduce(
      (sum, value) =>
        sum + value,
      0
    );

  if (
    total <= 0 ||
    !Number.isFinite(total)
  ) {
    return Array(
      NUM_CLASSES
    ).fill(
      1 / NUM_CLASSES
    );
  }

  return sanitized.map(
    (value) =>
      value / total
  );
}

/* -------------------------------------------------------------------------- */
/* Gaussian likelihood                                                        */
/* -------------------------------------------------------------------------- */

function gaussianLogProb(
  x: number,
  mean: number,
  std: number
): number {
  if (
    !Number.isFinite(x) ||
    !Number.isFinite(mean) ||
    !Number.isFinite(std)
  ) {
    return -Infinity;
  }

  const safeStd =
    Math.max(
      Math.abs(std),
      1e-6
    );

  const variance =
    safeStd * safeStd;

  return (
    -0.5 *
      Math.log(
        2 *
          Math.PI *
          variance
      ) -
    (
      (x - mean) ** 2
    ) /
      (2 * variance)
  );
}

/* -------------------------------------------------------------------------- */
/* Softmax                                                                    */
/* -------------------------------------------------------------------------- */

function softmax(
  logits: number[]
): number[] {
  if (
    logits.length === 0
  ) {
    return [];
  }

  const maxLogit =
    Math.max(...logits);

  const exponentials =
    logits.map(
      (logit) => {
        if (
          !Number.isFinite(
            logit
          )
        ) {
          return 0;
        }

        return Math.exp(
          clamp(
            logit -
              maxLogit,
            -700,
            700
          )
        );
      }
    );

  const total =
    exponentials.reduce(
      (sum, value) =>
        sum + value,
      0
    );

  if (
    !Number.isFinite(
      total
    ) ||
    total <= 0
  ) {
    return Array(
      logits.length
    ).fill(
      1 / logits.length
    );
  }

  return exponentials.map(
    (value) =>
      value / total
  );
}

/* -------------------------------------------------------------------------- */
/* Random Forest-style statistical classifier                                 */
/* -------------------------------------------------------------------------- */

export function randomForestPredict(
  features: number[]
): number[] {
  validateFeatureArray(
    features
  );

  const N_TREES = 100;

  const featureCount =
    features.length;

  const featuresPerTree =
    Math.max(
      1,
      Math.floor(
        Math.sqrt(
          featureCount
        )
      )
    );

  let seed =
    features.reduce(
      (
        accumulator,
        value,
        index
      ) =>
        accumulator +
        value * 31 +
        index * 7,
      0
    );

  const rng = (): number => {
    seed =
      (
        seed *
          1664525 +
        1013904223
      ) | 0;

    return (
      Math.abs(seed) /
      0x7fffffff
    );
  };

  const votes =
    Array(
      NUM_CLASSES
    ).fill(0);

  for (
    let tree = 0;
    tree < N_TREES;
    tree += 1
  ) {
    const indices =
      Array.from(
        {
          length:
            featureCount,
        },
        (_, index) =>
          index
      );

    for (
      let index =
        indices.length - 1;
      index > 0;
      index -= 1
    ) {
      const randomIndex =
        Math.floor(
          rng() *
            (index + 1)
        );

      [
        indices[index],
        indices[randomIndex],
      ] = [
        indices[randomIndex],
        indices[index],
      ];
    }

    const selectedFeatures =
      indices.slice(
        0,
        featuresPerTree
      );

    let bestClass = 0;
    let bestScore =
      -Infinity;

    for (
      let cls = 0;
      cls < NUM_CLASSES;
      cls += 1
    ) {
      const profile =
        CLASS_FEATURE_PROFILES[
          cls
        ];

      let score =
        Math.log(
          CLASS_PRIORS[
            cls
          ]
        );

      for (
        const featureIndex of
          selectedFeatures
      ) {
        score +=
          gaussianLogProb(
            features[
              featureIndex
            ],
            profile.mean[
              featureIndex
            ],
            profile.std[
              featureIndex
            ]
          );
      }

      if (
        score >
        bestScore
      ) {
        bestScore =
          score;

        bestClass =
          cls;
      }
    }

    votes[
      bestClass
    ] += 1;
  }

  return normalizeProbabilities(
    votes
  );
}

/* -------------------------------------------------------------------------- */
/* XGBoost-style statistical classifier                                       */
/* -------------------------------------------------------------------------- */

export function xgboostPredict(
  features: number[]
): number[] {
  validateFeatureArray(
    features
  );

  const N_ESTIMATORS = 100;
  const LEARNING_RATE = 0.1;

  let logits =
    CLASS_PRIORS.map(
      (prior) =>
        Math.log(
          prior + 1e-12
        )
    );

  const effectiveRate =
    LEARNING_RATE /
    Math.sqrt(
      N_ESTIMATORS
    );

  for (
    let estimator = 0;
    estimator <
    N_ESTIMATORS;
    estimator += 1
  ) {
    const classScores =
      Array(
        NUM_CLASSES
      ).fill(0);

    for (
      let cls = 0;
      cls < NUM_CLASSES;
      cls += 1
    ) {
      const profile =
        CLASS_FEATURE_PROFILES[
          cls
        ];

      let weightedScore =
        0;

      for (
        let featureIndex = 0;
        featureIndex <
        features.length;
        featureIndex += 1
      ) {
        const importance =
          FEATURE_IMPORTANCE_WEIGHTS[
            featureIndex
          ] ?? 0;

        weightedScore +=
          gaussianLogProb(
            features[
              featureIndex
            ],
            profile.mean[
              featureIndex
            ],
            profile.std[
              featureIndex
            ]
          ) *
          importance;
      }

      classScores[
        cls
      ] = weightedScore;
    }

    for (
      let cls = 0;
      cls < NUM_CLASSES;
      cls += 1
    ) {
      logits[cls] +=
        effectiveRate *
        clamp(
          classScores[cls],
          -50,
          50
        );
    }
  }

  return normalizeProbabilities(
    softmax(
      logits
    )
  );
}

/* -------------------------------------------------------------------------- */
/* Isolation-style anomaly detector                                           */
/* -------------------------------------------------------------------------- */

const N_ESTIMATORS_IF = 100;
const MAX_SAMPLES_IF = 256;

function cN(
  n: number
): number {
  if (
    n <= 1
  ) {
    return 0;
  }

  return (
    2 *
      (
        Math.log(
          n - 1
        ) +
        0.5772156649
      ) -
    (
      2 *
      (n - 1)
    ) /
      n
  );
}

function isolationPathLength(
  features: number[],
  seedInput: number,
  maxDepth = 8
): number {
  let depth = 0;
  let seed =
    seedInput | 0;

  let nodeSize =
    MAX_SAMPLES_IF;

  const rng = (): number => {
    seed =
      (
        seed *
          1664525 +
        1013904223
      ) | 0;

    return (
      Math.abs(seed) /
      0x7fffffff
    );
  };

  while (
    depth <
      maxDepth &&
    nodeSize > 1
  ) {
    const featureIndex =
      Math.floor(
        rng() *
          features.length
      );

    const normalProfile =
      CLASS_FEATURE_PROFILES[
        0
      ];

    const mean =
      normalProfile.mean[
        featureIndex
      ];

    const std =
      Math.max(
        normalProfile.std[
          featureIndex
        ],
        1e-6
      );

    const minValue =
      mean -
      3 * std;

    const maxValue =
      mean +
      3 * std;

    const splitValue =
      minValue +
      rng() *
        (
          maxValue -
          minValue
        );

    if (
      features[
        featureIndex
      ] <
      splitValue
    ) {
      nodeSize =
        Math.floor(
          nodeSize *
            0.4
        );
    } else {
      nodeSize =
        Math.floor(
          nodeSize *
            0.6
        );
    }

    depth += 1;
  }

  return (
    depth +
    cN(
      Math.max(
        nodeSize,
        2
      )
    )
  );
}

export function isolationForestScore(
  features: number[]
): {
  anomaly: boolean;
  score: number;
  rawScore: number;
} {
  validateFeatureArray(
    features
  );

  let totalPathLength =
    0;

  const featureMagnitude =
    features.reduce(
      (
        accumulator,
        value,
        index
      ) => {
        const normal =
          CLASS_FEATURE_PROFILES[
            0
          ];

        const mean =
          normal.mean[index];

        const std =
          Math.max(
            normal.std[index],
            1e-6
          );

        const z =
          Math.abs(
            value -
              mean
          ) /
          std;

        return (
          accumulator +
          Math.min(
            z,
            20
          )
        );
      },
      0
    );

  for (
    let estimator = 0;
    estimator <
    N_ESTIMATORS_IF;
    estimator += 1
  ) {
    const seed =
      (
        estimator *
          1013904223 +
        features.reduce(
          (
            accumulator,
            value,
            index
          ) =>
            accumulator +
            value *
              (index + 1),
          0
        )
      ) | 0;

    totalPathLength +=
      isolationPathLength(
        features,
        seed
      );
  }

  const averagePathLength =
    totalPathLength /
    N_ESTIMATORS_IF;

  const normalizer =
    cN(
      MAX_SAMPLES_IF
    );

  const rawScore =
    Math.pow(
      2,
      -averagePathLength /
        (
          normalizer ||
          1
        )
    );

  let evidenceCount =
    0;

  for (
    let index = 0;
    index < features.length;
    index += 1
  ) {
    const normal =
      CLASS_FEATURE_PROFILES[
        0
      ];

    const std =
      Math.max(
        normal.std[index],
        1e-6
      );

    const z =
      Math.abs(
        features[index] -
          normal.mean[index]
      ) /
      std;

    if (
      z >= 4
    ) {
      evidenceCount += 1;
    }
  }

  const safeRawScore =
    clamp(
      rawScore,
      0,
      1
    );

  const anomaly =
    safeRawScore >=
      ANOMALY_THRESHOLD &&
    evidenceCount >=
      MIN_ANOMALY_EVIDENCE &&
    featureMagnitude >
      15;

  const interpretableScore =
    clamp(
      1 -
        safeRawScore *
          2,
      -1,
      1
    );

  return {
    anomaly,

    score:
      Number(
        interpretableScore.toFixed(
          4
        )
      ),

    rawScore:
      Number(
        safeRawScore.toFixed(
          4
        )
      ),
  };
}

/* -------------------------------------------------------------------------- */
/* Ensemble                                                                   */
/* -------------------------------------------------------------------------- */

export interface EnsembleResult {
  prediction: string;
  predictionIndex: number;
  confidence: number;

  rfProbabilities: number[];
  xgbProbabilities: number[];
  ensembleProbabilities: number[];

  rfConfidence: number;
  xgbConfidence: number;

  lowConfidence: boolean;
}

export function softEnsemble(
  rfProbs: number[],
  xgbProbs: number[]
): EnsembleResult {
  if (
    rfProbs.length !==
      NUM_CLASSES ||
    xgbProbs.length !==
      NUM_CLASSES
  ) {
    throw new Error(
      `Invalid class probability length: expected ${NUM_CLASSES}`
    );
  }

  const normalizedRF =
    normalizeProbabilities(
      rfProbs
    );

  const normalizedXGB =
    normalizeProbabilities(
      xgbProbs
    );

  const ensemble =
    normalizedRF.map(
      (
        probability,
        index
      ) =>
        (
          probability +
          normalizedXGB[
            index
          ]
        ) /
        2
    );

  const probabilities =
    normalizeProbabilities(
      ensemble
    );

  let bestIndex = 0;

  for (
    let index = 1;
    index <
      probabilities.length;
    index += 1
  ) {
    if (
      probabilities[
        index
      ] >
      probabilities[
        bestIndex
      ]
    ) {
      bestIndex =
        index;
    }
  }

  const sorted =
    probabilities
      .map(
        (
          probability,
          index
        ) => ({
          probability,
          index,
        })
      )
      .sort(
        (a, b) =>
          b.probability -
          a.probability
      );

  const confidence =
    probabilities[
      bestIndex
    ];

  const secondBest =
    sorted[1]?.probability ??
    0;

  const margin =
    confidence -
    secondBest;

  const rfConfidence =
    normalizedRF[
      bestIndex
    ];

  const xgbConfidence =
    normalizedXGB[
      bestIndex
    ];

  return {
    prediction:
      ATTACK_LABELS[
        bestIndex
      ] ??
      "Normal",

    predictionIndex:
      bestIndex,

    confidence:
      Number(
        confidence.toFixed(
          4
        )
      ),

    rfProbabilities:
      normalizedRF.map(
        (value) =>
          Number(
            value.toFixed(
              4
            )
          )
      ),

    xgbProbabilities:
      normalizedXGB.map(
        (value) =>
          Number(
            value.toFixed(
              4
            )
          )
      ),

    ensembleProbabilities:
      probabilities.map(
        (value) =>
          Number(
            value.toFixed(
              4
            )
          )
      ),

    rfConfidence:
      Number(
        rfConfidence.toFixed(
          4
        )
      ),

    xgbConfidence:
      Number(
        xgbConfidence.toFixed(
          4
        )
      ),

    lowConfidence:
      confidence <
        CONFIDENCE_THRESHOLD ||
      margin <
        CLASS_MARGIN_THRESHOLD,
  };
}

/* -------------------------------------------------------------------------- */
/* Severity                                                                   */
/* -------------------------------------------------------------------------- */

export type Severity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "NORMAL";

export function calculateSeverity(
  supervisedAlert: boolean,
  anomalyAlert: boolean,
  prediction: string,
  confidence: number
): Severity {
  const validConfidence =
    Number.isFinite(
      confidence
    )
      ? confidence
      : 0;

  const strongPrediction =
    prediction !==
      "Normal" &&
    validConfidence >=
      SUPERVISED_ALERT_THRESHOLD;

  const effectiveSupervisedAlert =
    supervisedAlert &&
    strongPrediction;

  if (
    effectiveSupervisedAlert &&
    anomalyAlert
  ) {
    return "CRITICAL";
  }

  if (
    effectiveSupervisedAlert
  ) {
    return "HIGH";
  }

  if (
    anomalyAlert
  ) {
    return "MEDIUM";
  }

  return "NORMAL";
}

/* -------------------------------------------------------------------------- */
/* SHAP-style explainability                                                  */
/* -------------------------------------------------------------------------- */

export interface ShapFeature {
  featureName: string;
  featureValue: number;
  shapValue: number;
  rank: number;
  direction:
    | "positive"
    | "negative";
  description: string;
}

export function computeShapValues(
  features: number[],
  ensembleProbs: number[],
  predictionIdx: number,
  featureNames: string[],
  featureDescriptions: Record<
    string,
    string
  >
): ShapFeature[] {
  validateFeatureArray(
    features
  );

  if (
    featureNames.length !==
    features.length
  ) {
    throw new Error(
      `SHAP feature-name length mismatch: expected ${features.length}, received ${featureNames.length}`
    );
  }

  const safePredictionIndex =
    Number.isInteger(
      predictionIdx
    ) &&
    predictionIdx >= 0 &&
    predictionIdx <
      NUM_CLASSES
      ? predictionIdx
      : 0;

  const targetProfile =
    CLASS_FEATURE_PROFILES[
      safePredictionIndex
    ];

  const probabilities =
    normalizeProbabilities(
      ensembleProbs
    );

  const targetProbability =
    probabilities[
      safePredictionIndex
    ] ?? 0;

  const baselineLogProbs =
    features.map(
      (
        _value,
        featureIndex
      ) => {
        let baseline =
          0;

        for (
          let cls = 0;
          cls <
          NUM_CLASSES;
          cls += 1
        ) {
          const profile =
            CLASS_FEATURE_PROFILES[
              cls
            ];

          baseline +=
            CLASS_PRIORS[
              cls
            ] *
            gaussianLogProb(
              features[
                featureIndex
              ],
              profile.mean[
                featureIndex
              ],
              profile.std[
                featureIndex
              ]
            );
        }

        return baseline;
      }
    );

  const shapValues: ShapFeature[] =
    features.map(
      (
        featureValue,
        featureIndex
      ): ShapFeature => {
        const targetLogProbability =
          gaussianLogProb(
            featureValue,
            targetProfile.mean[
              featureIndex
            ],
            targetProfile.std[
              featureIndex
            ]
          );

        const rawValue =
          targetLogProbability -
          baselineLogProbs[
            featureIndex
          ];

        const importance =
          FEATURE_IMPORTANCE_WEIGHTS[
            featureIndex
          ] ??
          0.01;

        const scaledValue =
          rawValue *
          importance *
          targetProbability;

        const featureName =
          featureNames[
            featureIndex
          ];

        const direction:
          | "positive"
          | "negative" =
          scaledValue >= 0
            ? "positive"
            : "negative";

        return {
          featureName,

          featureValue,

          shapValue:
            Number(
              scaledValue.toFixed(
                6
              )
            ),

          rank: 0,

          direction,

          description:
            featureDescriptions[
              featureName
            ] ??
            featureName,
        };
      }
    );

  shapValues.sort(
    (a, b) =>
      Math.abs(
        b.shapValue
      ) -
      Math.abs(
        a.shapValue
      )
  );

  shapValues.forEach(
    (
      feature,
      index
    ) => {
      feature.rank =
        index + 1;
    }
  );

  return shapValues;
}

/* -------------------------------------------------------------------------- */
/* Explanation                                                                */
/* -------------------------------------------------------------------------- */

export function generateExplanation(
  shapFeatures: ShapFeature[],
  prediction: string,
  confidence: number,
  anomalyDetected: boolean
): string {
  const topPositive =
    shapFeatures
      .filter(
        (feature) =>
          feature.direction ===
          "positive"
      )
      .slice(0, 3);

  const topNegative =
    shapFeatures
      .filter(
        (feature) =>
          feature.direction ===
          "negative"
      )
      .slice(0, 2);

  const positiveNames =
    topPositive
      .map(
        (feature) =>
          feature.featureName
      )
      .join(", ");

  const negativeNames =
    topNegative
      .map(
        (feature) =>
          feature.featureName
      )
      .join(" and ");

  let explanation =
    `The model classified this flow as ${prediction} `;

  explanation +=
    `with ${(confidence * 100).toFixed(1)}% confidence. `;

  if (
    topPositive.length > 0
  ) {
    explanation +=
      `The strongest contributing features were ${positiveNames}. `;
  }

  if (
    topNegative.length > 0
  ) {
    explanation +=
      `Mitigating evidence came from ${negativeNames}. `;
  }

  if (
    anomalyDetected
  ) {
    explanation +=
      `The anomaly detector also identified a structurally unusual traffic pattern. `;
  }

  switch (
    prediction
  ) {
    case "DoS":
      explanation +=
        "The observed feature pattern contains characteristics associated with denial-of-service traffic.";
      break;

    case "Probe":
      explanation +=
        "The observed feature pattern contains characteristics associated with systematic service or host discovery.";
      break;

    case "R2L":
      explanation +=
        "The observed feature pattern contains characteristics associated with remote-to-local activity.";
      break;

    case "U2R":
      explanation +=
        "The observed feature pattern contains characteristics associated with privilege-escalation activity.";
      break;

    default:
      explanation +=
        "The observed feature pattern is currently consistent with benign network activity.";
      break;
  }

  return explanation;
}

/* -------------------------------------------------------------------------- */
/* Model configuration validation                                             */
/* -------------------------------------------------------------------------- */

export function validateModelConfiguration(): void {
  if (
    FEATURE_NAMES.length !==
    41
  ) {
    throw new Error(
      `AEGIS-XAI expects exactly 41 features, found ${FEATURE_NAMES.length}`
    );
  }

  if (
    CLASS_PRIORS.length !==
    NUM_CLASSES
  ) {
    throw new Error(
      `Expected ${NUM_CLASSES} class priors, found ${CLASS_PRIORS.length}`
    );
  }

  const priorSum =
    CLASS_PRIORS.reduce(
      (sum, value) =>
        sum + value,
      0
    );

  if (
    !Number.isFinite(
      priorSum
    ) ||
    priorSum <= 0
  ) {
    throw new Error(
      "Invalid class priors"
    );
  }

  if (
    FEATURE_IMPORTANCE_WEIGHTS.length !==
    FEATURE_NAMES.length
  ) {
    throw new Error(
      `Feature importance length mismatch: expected ${FEATURE_NAMES.length}, received ${FEATURE_IMPORTANCE_WEIGHTS.length}`
    );
  }

  for (
    let cls = 0;
    cls < NUM_CLASSES;
    cls += 1
  ) {
    const profile =
      CLASS_FEATURE_PROFILES[
        cls
      ];

    if (!profile) {
      throw new Error(
        `Missing class profile for class ${cls}`
      );
    }

    if (
      profile.mean.length !==
      FEATURE_NAMES.length
    ) {
      throw new Error(
        `Class ${cls} mean vector length mismatch: expected ${FEATURE_NAMES.length}, received ${profile.mean.length}`
      );
    }

    if (
      profile.std.length !==
      FEATURE_NAMES.length
    ) {
      throw new Error(
        `Class ${cls} std vector length mismatch: expected ${FEATURE_NAMES.length}, received ${profile.std.length}`
      );
    }

    for (
      let featureIndex = 0;
      featureIndex <
      FEATURE_NAMES.length;
      featureIndex += 1
    ) {
      const mean =
        profile.mean[
          featureIndex
        ];

      const std =
        profile.std[
          featureIndex
        ];

      if (
        !Number.isFinite(
          mean
        )
      ) {
        throw new Error(
          `Class ${cls}, feature ${featureIndex} (${FEATURE_NAMES[featureIndex]}) has invalid mean`
        );
      }

      if (
        !Number.isFinite(
          std
        ) ||
        std < 0
      ) {
        throw new Error(
          `Class ${cls}, feature ${featureIndex} (${FEATURE_NAMES[featureIndex]}) has invalid standard deviation`
        );
      }
    }
  }
}

validateModelConfiguration();