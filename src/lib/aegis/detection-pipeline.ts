/**
 * AEGIS-XAI Detection Pipeline
 *
 * Central detection pipeline:
 *
 *   Network Flow
 *       ↓
 *   Feature Extraction
 *       ↓
 *   Random Forest + XGBoost
 *       ↓
 *   Soft Ensemble
 *       ↓
 *   Isolation Forest
 *       ↓
 *   Evidence / Model Agreement Gate
 *       ↓
 *   Severity Engine
 *       ↓
 *   SHAP-style Explanation
 *       ↓
 *   MITRE ATT&CK Mapping
 *       ↓
 *   Detection Result
 *
 * Important:
 *
 * A classifier prediction is NOT automatically a security alert.
 *
 * A supervised alert requires:
 *   - a non-Normal prediction
 *   - sufficient ensemble confidence
 *   - RF/XGBoost agreement
 *   - sufficient class separation
 *
 * The pipeline also preserves the individual RF and XGBoost
 * probability vectors so downstream persistence can store
 * truthful model-level evidence.
 */

import {
  extractFeatureVector,
  FEATURE_NAMES,
  FEATURE_DESCRIPTIONS,
  type NetworkFlow,
} from "./features";

import {
  randomForestPredict,
  xgboostPredict,
  softEnsemble,
  isolationForestScore,
  calculateSeverity,
  computeShapValues,
  generateExplanation,
  type Severity,
  type ShapFeature,
  type EnsembleResult,
} from "./ml-engine";

import {
  getMitreMapping,
  type MitreMapping,
} from "./mitre";

import { generateEventId } from "./event-id";

/* -------------------------------------------------------------------------- */
/* Detection policy                                                           */
/* -------------------------------------------------------------------------- */

const EXPECTED_CLASS_COUNT = 5;

/**
 * Minimum ensemble confidence for a supervised alert.
 */
const SUPERVISED_CONFIDENCE_THRESHOLD = 0.75;

/**
 * Minimum winning-class margin over the runner-up.
 */
const CLASS_MARGIN_THRESHOLD = 0.08;

/* -------------------------------------------------------------------------- */
/* Detection result                                                           */
/* -------------------------------------------------------------------------- */

export interface DetectionResult {
  /**
   * Exact NetworkFlow analyzed by the detection engine.
   */
  flow: NetworkFlow;

  /* Identity */
  eventId: string;
  timestamp: Date;

  /* Network attributes */
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  service: string;
  duration: number;
  srcBytes: number;
  dstBytes: number;

  /* Final ensemble prediction */
  prediction: string;
  predictionIndex: number;
  confidence: number;

  /* Individual model confidence */
  rfConfidence: number;
  xgbConfidence: number;

  /**
   * Exact Random Forest probability vector.
   */
  rfProbs: number[];

  /**
   * Exact XGBoost probability vector.
   */
  xgbProbs: number[];

  /**
   * Soft-ensemble probability vector.
   */
  ensembleProbs: number[];

  /**
   * Winning class index selected independently by RF.
   */
  rfPredictionIndex: number;

  /**
   * Winning class index selected independently by XGBoost.
   */
  xgbPredictionIndex: number;

  /**
   * True when RF and XGBoost selected the same class.
   */
  modelAgreement: boolean;

  /**
   * Difference between the highest and second-highest
   * ensemble probabilities.
   */
  classMargin: number;

  /**
   * True only when the supervised evidence gate passes.
   */
  supervisedAlert: boolean;

  /**
   * True when ensemble confidence is below the configured
   * supervised threshold.
   */
  lowConfidence: boolean;

  /* Anomaly detection */
  anomalyDetected: boolean;
  anomalyScore: number;
  anomalyRawScore: number;

  /* Final severity */
  severity: Severity;

  /* Explainability */
  shapFeatures: ShapFeature[];
  explanation: string;

  /* Performance */
  inferenceTimeMs: number;
  shapTimeMs: number;

  /* MITRE ATT&CK */
  mitre: MitreMapping;

  /* Exact model input */
  featureVector: number[];
}

/* -------------------------------------------------------------------------- */
/* Pipeline metrics                                                           */
/* -------------------------------------------------------------------------- */

export interface PipelineMetrics {
  totalProcessed: number;
  totalAlerts: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  normalCount: number;
  avgInferenceMs: number;
  avgShapMs: number;
}

let pipelineMetrics: PipelineMetrics = {
  totalProcessed: 0,
  totalAlerts: 0,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 0,
  normalCount: 0,
  avgInferenceMs: 0,
  avgShapMs: 0,
};

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Return the index containing the largest probability.
 */
function argMax(
  values: number[]
): number {
  if (values.length === 0) {
    return -1;
  }

  let bestIndex = 0;

  for (
    let index = 1;
    index < values.length;
    index += 1
  ) {
    if (
      values[index] >
      values[bestIndex]
    ) {
      bestIndex = index;
    }
  }

  return bestIndex;
}

/**
 * Calculate the difference between the highest and
 * second-highest probabilities.
 */
function calculateClassMargin(
  probabilities: number[]
): number {
  if (probabilities.length < 2) {
    return 0;
  }

  const sorted = [...probabilities].sort(
    (a, b) => b - a
  );

  const winner =
    Number.isFinite(sorted[0])
      ? sorted[0]
      : 0;

  const runnerUp =
    Number.isFinite(sorted[1])
      ? sorted[1]
      : 0;

  return Number(
    Math.max(
      0,
      winner - runnerUp
    ).toFixed(4)
  );
}

/**
 * Validate the raw outputs from both supervised models.
 */
function validateModelProbabilities(
  rfProbs: number[],
  xgbProbs: number[]
): void {
  if (
    rfProbs.length !==
      EXPECTED_CLASS_COUNT ||
    xgbProbs.length !==
      EXPECTED_CLASS_COUNT
  ) {
    throw new Error(
      `Invalid classifier output length. ` +
      `Expected ${EXPECTED_CLASS_COUNT} classes, ` +
      `received RF=${rfProbs.length}, ` +
      `XGB=${xgbProbs.length}.`
    );
  }

  for (
    const probability of [
      ...rfProbs,
      ...xgbProbs,
    ]
  ) {
    if (
      !Number.isFinite(
        probability
      ) ||
      probability < 0 ||
      probability > 1
    ) {
      throw new Error(
        `Invalid classifier probability: ${probability}`
      );
    }
  }
}

/**
 * Determine whether the supervised classifier has enough
 * evidence to create an alert.
 *
 * IMPORTANT:
 *
 * A model prediction alone is not an alert.
 *
 * All of the following must hold:
 *
 *   1. Prediction is not Normal
 *   2. Ensemble confidence >= threshold
 *   3. Ensemble is not marked low-confidence
 *   4. RF and XGBoost agree
 *   5. Winning class has sufficient margin
 */
function determineSupervisedAlert(
  ensemble: EnsembleResult,
  rfProbs: number[],
  xgbProbs: number[]
): {
  rfPredictionIndex: number;
  xgbPredictionIndex: number;
  modelAgreement: boolean;
  classMargin: number;
  supervisedAlert: boolean;
} {
  const rfPredictionIndex =
    argMax(
      rfProbs
    );

  const xgbPredictionIndex =
    argMax(
      xgbProbs
    );

  const modelAgreement =
    rfPredictionIndex >= 0 &&
    xgbPredictionIndex >= 0 &&
    rfPredictionIndex ===
      xgbPredictionIndex;

  const classMargin =
    calculateClassMargin(
      ensemble.ensembleProbabilities
    );

  const strongConfidence =
    Number.isFinite(
      ensemble.confidence
    ) &&
    ensemble.confidence >=
      SUPERVISED_CONFIDENCE_THRESHOLD;

  const notNormal =
    ensemble.prediction !==
    "Normal";

  const strongMargin =
    classMargin >=
    CLASS_MARGIN_THRESHOLD;

  const supervisedAlert =
    notNormal &&
    strongConfidence &&
    !ensemble.lowConfidence &&
    modelAgreement &&
    strongMargin;

  return {
    rfPredictionIndex,
    xgbPredictionIndex,
    modelAgreement,
    classMargin,
    supervisedAlert,
  };
}

/**
 * Validate that the feature vector exactly matches the
 * configured feature schema.
 */
function validateFeatureVector(
  featureVector: number[]
): void {
  if (
    featureVector.length !==
    FEATURE_NAMES.length
  ) {
    throw new Error(
      `Feature vector length mismatch: ` +
      `expected ${FEATURE_NAMES.length}, ` +
      `received ${featureVector.length}.`
    );
  }

  for (
    const value of featureVector
  ) {
    if (
      !Number.isFinite(value)
    ) {
      throw new Error(
        `Feature vector contains a non-finite value: ${value}`
      );
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Public metrics                                                             */
/* -------------------------------------------------------------------------- */

export function getPipelineMetrics():
  PipelineMetrics {
  return {
    ...pipelineMetrics,
  };
}

export function resetPipelineMetrics():
  void {
  pipelineMetrics = {
    totalProcessed: 0,
    totalAlerts: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    normalCount: 0,
    avgInferenceMs: 0,
    avgShapMs: 0,
  };
}

/* -------------------------------------------------------------------------- */
/* Main detection pipeline                                                    */
/* -------------------------------------------------------------------------- */

export function runDetectionPipeline(
  flow: NetworkFlow
): DetectionResult {
  const detectionTimestamp =
    new Date();

  /* ---------------------------------------------------------------------- */
  /* Layer 2: Feature extraction                                           */
  /* ---------------------------------------------------------------------- */

  const featureVector =
    extractFeatureVector(
      flow
    );

  validateFeatureVector(
    featureVector
  );

  /* ---------------------------------------------------------------------- */
  /* Layer 3a: Supervised classification                                    */
  /* ---------------------------------------------------------------------- */

  const inferenceStart =
    performance.now();

  const rfProbs =
    randomForestPredict(
      featureVector
    );

  const xgbProbs =
    xgboostPredict(
      featureVector
    );

  validateModelProbabilities(
    rfProbs,
    xgbProbs
  );

  const ensemble =
    softEnsemble(
      rfProbs,
      xgbProbs
    );

  /* ---------------------------------------------------------------------- */
  /* Layer 3b: Anomaly detection                                           */
  /* ---------------------------------------------------------------------- */

  const anomalyResult =
    isolationForestScore(
      featureVector
    );

  const inferenceTimeMs =
    performance.now() -
    inferenceStart;

  /* ---------------------------------------------------------------------- */
  /* Layer 4: Evidence gate + severity                                     */
  /* ---------------------------------------------------------------------- */

  const {
    rfPredictionIndex,
    xgbPredictionIndex,
    modelAgreement,
    classMargin,
    supervisedAlert,
  } =
    determineSupervisedAlert(
      ensemble,
      ensemble.rfProbabilities,
      ensemble.xgbProbabilities
    );

  const anomalyAlert =
    anomalyResult.anomaly;

  const severity =
    calculateSeverity(
      supervisedAlert,
      anomalyAlert,
      ensemble.prediction,
      ensemble.confidence
    );

  /* ---------------------------------------------------------------------- */
  /* Layer 5: Explainability                                                */
  /* ---------------------------------------------------------------------- */

  const shapStart =
    performance.now();

  const shapFeatures =
    computeShapValues(
      featureVector,
      ensemble.ensembleProbabilities,
      ensemble.predictionIndex,
      FEATURE_NAMES as string[],
      FEATURE_DESCRIPTIONS
    );

  const explanation =
    generateExplanation(
      shapFeatures,
      ensemble.prediction,
      ensemble.confidence,
      anomalyAlert
    );

  const shapTimeMs =
    performance.now() -
    shapStart;

  /* ---------------------------------------------------------------------- */
  /* Layer 6: MITRE ATT&CK                                                  */
  /* ---------------------------------------------------------------------- */

  /*
   * Only attach the classifier's attack mapping when the final
   * security decision is non-NORMAL.
   *
   * This prevents:
   *
   *   Prediction = Probe
   *   Severity   = NORMAL
   *
   * from being presented as though a confirmed Probe attack occurred.
   */
  const mitre =
    getMitreMapping(
      severity === "NORMAL"
        ? "Normal"
        : ensemble.prediction
    );

  /* ---------------------------------------------------------------------- */
  /* Process metrics                                                        */
  /* ---------------------------------------------------------------------- */

  const previousTotal =
    pipelineMetrics.totalProcessed;

  pipelineMetrics.totalProcessed =
    previousTotal + 1;

  pipelineMetrics.avgInferenceMs =
    (
      pipelineMetrics.avgInferenceMs *
        previousTotal +
      inferenceTimeMs
    ) /
    pipelineMetrics.totalProcessed;

  pipelineMetrics.avgShapMs =
    (
      pipelineMetrics.avgShapMs *
        previousTotal +
      shapTimeMs
    ) /
    pipelineMetrics.totalProcessed;

  if (
    severity !== "NORMAL"
  ) {
    pipelineMetrics.totalAlerts +=
      1;
  }

  switch (
    severity
  ) {
    case "CRITICAL":
      pipelineMetrics.criticalCount +=
        1;
      break;

    case "HIGH":
      pipelineMetrics.highCount +=
        1;
      break;

    case "MEDIUM":
      pipelineMetrics.mediumCount +=
        1;
      break;

    case "NORMAL":
      pipelineMetrics.normalCount +=
        1;
      break;
  }

  /* ---------------------------------------------------------------------- */
  /* Final result                                                           */
  /* ---------------------------------------------------------------------- */

  return {
    flow,

    eventId:
      generateEventId(),

    timestamp:
      detectionTimestamp,

    sourceIp:
      flow.sourceIp,

    destinationIp:
      flow.destinationIp,

    sourcePort:
      flow.sourcePort,

    destinationPort:
      flow.destinationPort,

    protocol:
      flow.protocol,

    service:
      flow.service,

    duration:
      flow.duration,

    srcBytes:
      flow.srcBytes,

    dstBytes:
      flow.dstBytes,

    /* Final ensemble prediction */
    prediction:
      ensemble.prediction,

    predictionIndex:
      ensemble.predictionIndex,

    confidence:
      ensemble.confidence,

    /* Model confidence */
    rfConfidence:
      ensemble.rfConfidence,

    xgbConfidence:
      ensemble.xgbConfidence,

    /* Preserve every probability vector */
    rfProbs:
      ensemble.rfProbabilities,

    xgbProbs:
      ensemble.xgbProbabilities,

    ensembleProbs:
      ensemble.ensembleProbabilities,

    /* Individual model decisions */
    rfPredictionIndex,

    xgbPredictionIndex,

    modelAgreement,

    classMargin,

    supervisedAlert,

    lowConfidence:
      ensemble.lowConfidence,

    /* Anomaly */
    anomalyDetected:
      anomalyAlert,

    anomalyScore:
      anomalyResult.score,

    anomalyRawScore:
      anomalyResult.rawScore,

    /* Severity */
    severity,

    /* Explainability */
    shapFeatures,

    explanation,

    /* Performance */
    inferenceTimeMs:
      Number(
        inferenceTimeMs.toFixed(3)
      ),

    shapTimeMs:
      Number(
        shapTimeMs.toFixed(3)
      ),

    /* MITRE */
    mitre,

    /* Exact feature input */
    featureVector,
  };
}

/* -------------------------------------------------------------------------- */
/* Human-readable summary                                                     */
/* -------------------------------------------------------------------------- */

export function formatDetectionSummary(
  result: DetectionResult
): string {
  return [
    `[${result.eventId}]`,

    result.timestamp.toISOString(),

    `${result.sourceIp}:${result.sourcePort} → ` +
      `${result.destinationIp}:${result.destinationPort}`,

    `Protocol: ${
      result.protocol.toUpperCase()
    }`,

    `Prediction: ${
      result.prediction
    }`,

    `Confidence: ${
      (result.confidence * 100).toFixed(1)
    }%`,

    `RF: ${
      (result.rfConfidence * 100).toFixed(1)
    }%`,

    `XGB: ${
      (result.xgbConfidence * 100).toFixed(1)
    }%`,

    `ModelAgreement: ${
      result.modelAgreement
        ? "YES"
        : "NO"
    }`,

    `Margin: ${
      result.classMargin.toFixed(3)
    }`,

    `SupervisedAlert: ${
      result.supervisedAlert
        ? "YES"
        : "NO"
    }`,

    `Anomaly: ${
      result.anomalyDetected
        ? "YES"
        : "NO"
    }`,

    `Severity: ${
      result.severity
    }`,

    `MITRE: ${
      result.mitre.tacticId
    } - ${
      result.mitre.tacticName
    }`,
  ].join(" | ");
}