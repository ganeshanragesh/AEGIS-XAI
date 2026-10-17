/**
 * AEGIS-XAI Database Repository
 *
 * Central PostgreSQL/Drizzle persistence layer.
 *
 * Responsibilities:
 *   - Persist network flows
 *   - Persist alerts
 *   - Persist model detections
 *   - Persist SHAP explanations
 *   - Persist system events
 *   - Manage monitoring sessions
 *   - Store model metadata
 *   - Generate security reports
 */

import { db } from "@/db";

import {
  alerts,
  detections,
  shapExplanations,
  flows,
  systemEvents,
  modelMetadata,
  monitorSessions,
  type NewAlert,
  type NewDetection,
  type NewShapExplanation,
  type NewFlow,
  type NewSystemEvent,
} from "@/db/schema";

import {
  and,
  count,
  desc,
  eq,
  gte,
  lte,
  like,
  sql,
} from "drizzle-orm";

import type { DetectionResult } from "./detection-pipeline";

import {
  generateEventId,
  generateSessionId,
} from "./event-id";

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export interface AlertFilters {
  severity?: string;
  prediction?: string;
  sourceIp?: string;
  destinationIp?: string;
  status?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}

/* -------------------------------------------------------------------------- */
/* Save Flow                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Persist a completed network flow.
 *
 * NORMAL traffic is stored in `flows`.
 * Alert creation is handled separately by saveDetectionResult().
 */
export async function saveFlow(
  result: DetectionResult,
  captureMode: string = "live",
  pcapFile?: string
): Promise<number> {
  const flow = result.flow;

  const flowKey = [
    flow.sourceIp,
    flow.sourcePort,
    flow.destinationIp,
    flow.destinationPort,
    flow.protocol,
  ].join(":");

  const [savedFlow] = await db
    .insert(flows)
    .values({
      flowKey,

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

      duration:
        flow.duration,

      srcBytes:
        flow.srcBytes,

      dstBytes:
        flow.dstBytes,

      srcPackets:
        flow.srcPackets,  
       
      dstPackets:
        flow.dstPackets,

      totalPackets:
        flow.srcPackets + flow.dstPackets,
      
      captureMode,

      pcapFile:
        pcapFile || null,

      firstSeen:
        result.timestamp,

      lastSeen:
        result.timestamp,

      finalized: true,
    } satisfies NewFlow)
    .returning({
      id: flows.id,
    });

  if (!savedFlow) {
    throw new Error(
      "Failed to persist network flow"
    );
  }

  return savedFlow.id;
}

/* -------------------------------------------------------------------------- */
/* Save Detection Result                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Persist a complete detection result.
 *
 * Persistence order:
 *
 *   Flow
 *      ↓
 *   Alert
 *      ↓
 *   RF/XGBoost detections
 *      ↓
 *   SHAP explanations
 *
 * This function accepts both:
 *
 *   saveDetectionResult(result, flowId, captureMode, pcapFile)
 *
 * and the older form:
 *
 *   saveDetectionResult(result, captureMode, pcapFile)
 *
 * The second form automatically creates the flow.
 */
export async function saveDetectionResult(
  result: DetectionResult,
  flowIdOrCaptureMode: number | string,
  captureModeOrPcapFile?: string,
  pcapFile?: string
): Promise<number> {
  let flowId: number;
  let captureMode: string;
  let resolvedPcapFile:
    | string
    | undefined;

  /*
   * New preferred form:
   *
   * saveDetectionResult(
   *   result,
   *   flowId,
   *   "live",
   *   pcapFile
   * )
   */
  if (
    typeof flowIdOrCaptureMode ===
    "number"
  ) {
    flowId =
      flowIdOrCaptureMode;

    captureMode =
      captureModeOrPcapFile ||
      "live";

    resolvedPcapFile =
      pcapFile;
  } else {
    /*
     * Backwards-compatible form:
     *
     * saveDetectionResult(
     *   result,
     *   "live",
     *   pcapFile
     * )
     */
    captureMode =
      flowIdOrCaptureMode ||
      "live";

    resolvedPcapFile =
      captureModeOrPcapFile;

    flowId =
      await saveFlow(
        result,
        captureMode,
        resolvedPcapFile
      );
  }

  return db.transaction(
    async (tx) => {
      /*
       * Create alert row.
       */
      const [alert] =
        await tx
          .insert(alerts)
          .values({
            flowId,

            eventId:
              result.eventId,

            timestamp:
              result.timestamp,

            sourceIp:
              result.sourceIp,

            destinationIp:
              result.destinationIp,

            sourcePort:
              result.sourcePort,

            destinationPort:
              result.destinationPort,

            protocol:
              result.protocol,

            service:
              result.service,

            prediction:
              result.prediction,

            confidence:
              result.confidence,

            anomalyDetected:
              result.anomalyDetected,

            anomalyScore:
              result.anomalyScore,

            severity:
              result.severity,

            mitreId:
              result.mitre.tacticId,

            mitreTactic:
              result.mitre.tacticName,

            mitreDescription:
              result.mitre.description,

            rfConfidence:
              result.rfConfidence,

            xgbConfidence:
              result.xgbConfidence,

            ensembleConfidence:
              result.confidence,

            modelVersion:
              "1.0.0",

            status:
              "open",

            captureMode,

            pcapFile:
              resolvedPcapFile ||
              null,

            inferenceTimeMs:
              result.inferenceTimeMs,

            shapTimeMs:
              result.shapTimeMs,
          } satisfies NewAlert)
          .returning({
            id: alerts.id,
          });

      if (!alert) {
        throw new Error(
          "Failed to persist detection alert"
        );
      }

      const alertId =
        alert.id;

      /*
       * Preserve the individual supervised-model probability vectors.
       *
       * The current DetectionResult contains rfProbs and xgbProbs.
       * Keep the ensemble vector only as a defensive fallback so an
       * older caller cannot crash persistence if it does not yet provide
       * the individual vectors.
       */
      const rfProbabilities =
        Array.isArray(result.rfProbs) &&
        result.rfProbs.length > 0
          ? result.rfProbs
          : result.ensembleProbs;

      const xgbProbabilities =
        Array.isArray(result.xgbProbs) &&
        result.xgbProbs.length > 0
          ? result.xgbProbs
          : result.ensembleProbs;

      if (
        rfProbabilities.length !==
        xgbProbabilities.length
      ) {
        throw new Error(
          `RF/XGBoost probability length mismatch: ` +
          `RF=${rfProbabilities.length}, ` +
          `XGB=${xgbProbabilities.length}`
        );
      }

      await tx
        .insert(detections)
        .values([
          {
            alertId,

            model:
              "RandomForest",

            prediction:
              result.prediction,

            confidence:
              result.rfConfidence,

            probabilities:
              rfProbabilities,

            inferenceTimeMs:
              result.inferenceTimeMs /
              2,
          } satisfies NewDetection,

          {
            alertId,

            model:
              "XGBoost",

            prediction:
              result.prediction,

            confidence:
              result.xgbConfidence,

            probabilities:
              xgbProbabilities,

            inferenceTimeMs:
              result.inferenceTimeMs /
              2,
          } satisfies NewDetection,
        ]);

      /*
       * Store top SHAP features.
       */
      const topShapFeatures =
        result.shapFeatures.slice(
          0,
          15
        );

      if (
        topShapFeatures.length >
        0
      ) {
        await tx
          .insert(shapExplanations)
          .values(
            topShapFeatures.map(
              (sf) => ({
                alertId,

                featureName:
                  sf.featureName,

                featureValue:
                  sf.featureValue,

                featureValueRaw:
                  String(
                    sf.featureValue
                  ),

                shapValue:
                  sf.shapValue,

                rank:
                  sf.rank,

                direction:
                  sf.direction,
              } satisfies NewShapExplanation)
            )
          );
      }

      return alertId;
    }
  );
}

/* -------------------------------------------------------------------------- */
/* Alerts                                                                     */
/* -------------------------------------------------------------------------- */

export async function getAlerts(
  filters: AlertFilters = {}
) {
  const {
    severity,
    prediction,
    sourceIp,
    destinationIp,
    status,
    startDate,
    endDate,
    limit = 50,
    offset = 0,
  } = filters;

  const conditions = [];

  if (severity) {
    conditions.push(
      eq(
        alerts.severity,
        severity
      )
    );
  }

  if (prediction) {
    conditions.push(
      eq(
        alerts.prediction,
        prediction
      )
    );
  }

  if (sourceIp) {
    conditions.push(
      like(
        alerts.sourceIp,
        `%${sourceIp}%`
      )
    );
  }

  if (destinationIp) {
    conditions.push(
      like(
        alerts.destinationIp,
        `%${destinationIp}%`
      )
    );
  }

  if (status) {
    conditions.push(
      eq(
        alerts.status,
        status
      )
    );
  }

  if (startDate) {
    conditions.push(
      gte(
        alerts.timestamp,
        startDate
      )
    );
  }

  if (endDate) {
    conditions.push(
      lte(
        alerts.timestamp,
        endDate
      )
    );
  }

  return db
    .select()
    .from(alerts)
    .where(
      conditions.length > 0
        ? and(...conditions)
        : undefined
    )
    .orderBy(
      desc(
        alerts.timestamp
      )
    )
    .limit(limit)
    .offset(offset);
}

/**
 * Get one alert and its model/SHAP details.
 */
export async function getAlertById(
  id: number
) {
  const [alert] =
    await db
      .select()
      .from(alerts)
      .where(
        eq(
          alerts.id,
          id
        )
      );

  if (!alert) {
    return null;
  }

  const [
    alertDetections,
    shapValues,
  ] = await Promise.all([
    db
      .select()
      .from(detections)
      .where(
        eq(
          detections.alertId,
          id
        )
      ),

    db
      .select()
      .from(shapExplanations)
      .where(
        eq(
          shapExplanations.alertId,
          id
        )
      )
      .orderBy(
        shapExplanations.rank
      ),
  ]);

  return {
    alert,

    detections:
      alertDetections,

    shapValues,
  };
}

/**
 * Get an alert using its event ID.
 */
export async function getAlertByEventId(
  eventId: string
) {
  const [alert] =
    await db
      .select()
      .from(alerts)
      .where(
        eq(
          alerts.eventId,
          eventId
        )
      );

  if (!alert) {
    return null;
  }

  return getAlertById(
    alert.id
  );
}

/**
 * Update alert lifecycle status.
 */
export async function updateAlertStatus(
  id: number,
  status: string
) {
  await db
    .update(alerts)
    .set({
      status,

      updatedAt:
        new Date(),
    })
    .where(
      eq(
        alerts.id,
        id
      )
    );
}

/**
 * Count alerts.
 */
export async function getTotalAlertCount(
  filters: AlertFilters = {}
) {
  const {
    severity,
    prediction,
    startDate,
    endDate,
  } = filters;

  const conditions = [];

  if (severity) {
    conditions.push(
      eq(
        alerts.severity,
        severity
      )
    );
  }

  if (prediction) {
    conditions.push(
      eq(
        alerts.prediction,
        prediction
      )
    );
  }

  if (startDate) {
    conditions.push(
      gte(
        alerts.timestamp,
        startDate
      )
    );
  }

  if (endDate) {
    conditions.push(
      lte(
        alerts.timestamp,
        endDate
      )
    );
  }

  const [result] =
    await db
      .select({
        count:
          count(),
      })
      .from(alerts)
      .where(
        conditions.length > 0
          ? and(...conditions)
          : undefined
      );

  return (
    result?.count ??
    0
  );
}

/* -------------------------------------------------------------------------- */
/* Dashboard Metrics                                                          */
/* -------------------------------------------------------------------------- */

export async function getAlertMetrics() {
  const [totals] =
    await db
      .select({
        total:
          count(),

        critical:
          sql<number>`
            COUNT(*) FILTER (
              WHERE ${alerts.severity} = 'CRITICAL'
            )
          `,

        high:
          sql<number>`
            COUNT(*) FILTER (
              WHERE ${alerts.severity} = 'HIGH'
            )
          `,

        medium:
          sql<number>`
            COUNT(*) FILTER (
              WHERE ${alerts.severity} = 'MEDIUM'
            )
          `,

        normal:
          sql<number>`
            COUNT(*) FILTER (
              WHERE ${alerts.severity} = 'NORMAL'
            )
          `,
      })
      .from(alerts);

  const attackDistribution =
    await db
      .select({
        prediction:
          alerts.prediction,

        count:
          count(),
      })
      .from(alerts)
      .groupBy(
        alerts.prediction
      )
      .orderBy(
        desc(
          count()
        )
      );

  const recentActivity =
    await db
      .select({
        hour:
          sql<string>`
            DATE_TRUNC(
              'hour',
              ${alerts.timestamp}
            )
          `,

        count:
          count(),
      })
      .from(alerts)
      .where(
        gte(
          alerts.timestamp,
          new Date(
            Date.now() -
              24 *
                60 *
                60 *
                1000
          )
        )
      )
      .groupBy(
        sql`
          DATE_TRUNC(
            'hour',
            ${alerts.timestamp}
          )
        `
      )
      .orderBy(
        sql`
          DATE_TRUNC(
            'hour',
            ${alerts.timestamp}
          )
        `
      );

  const topSourceIps =
    await db
      .select({
        sourceIp:
          alerts.sourceIp,

        count:
          count(),
      })
      .from(alerts)
      .where(
        sql`
          ${alerts.prediction} != 'Normal'
        `
      )
      .groupBy(
        alerts.sourceIp
      )
      .orderBy(
        desc(
          count()
        )
      )
      .limit(10);

  const topDestIps =
    await db
      .select({
        destinationIp:
          alerts.destinationIp,

        count:
          count(),
      })
      .from(alerts)
      .groupBy(
        alerts.destinationIp
      )
      .orderBy(
        desc(
          count()
        )
      )
      .limit(10);

  const protocolDistribution =
    await db
      .select({
        protocol:
          alerts.protocol,

        count:
          count(),
      })
      .from(alerts)
      .groupBy(
        alerts.protocol
      )
      .orderBy(
        desc(
          count()
        )
      );

  return {
    totals,

    attackDistribution,

    recentActivity,

    topSourceIps,

    topDestIps,

    protocolDistribution,
  };
}

/* -------------------------------------------------------------------------- */
/* Performance Metrics                                                        */
/* -------------------------------------------------------------------------- */

export async function getPerformanceMetrics() {
  const [result] =
    await db
      .select({
        avgInferenceMs:
          sql<number>`
            AVG(
              ${alerts.inferenceTimeMs}
            )
          `,

        avgShapMs:
          sql<number>`
            AVG(
              ${alerts.shapTimeMs}
            )
          `,

        p95InferenceMs:
          sql<number>`
            PERCENTILE_CONT(0.95)
            WITHIN GROUP (
              ORDER BY
                ${alerts.inferenceTimeMs}
            )
          `,

        p99InferenceMs:
          sql<number>`
            PERCENTILE_CONT(0.99)
            WITHIN GROUP (
              ORDER BY
                ${alerts.inferenceTimeMs}
            )
          `,

        maxInferenceMs:
          sql<number>`
            MAX(
              ${alerts.inferenceTimeMs}
            )
          `,

        avgConfidence:
          sql<number>`
            AVG(
              ${alerts.confidence}
            )
          `,
      })
      .from(alerts);

  return result;
}

/* -------------------------------------------------------------------------- */
/* System Events                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Write a system event.
 */
export async function logSystemEvent(
  component: string,
  eventType: string,
  message: string,
  severity: string = "info",
  details?: Record<string, unknown>
) {
  await db
    .insert(systemEvents)
    .values({
      eventId:
        generateEventId(),

      component,

      eventType,

      severity,

      message,

      details:
        details ||
        null,
    } satisfies NewSystemEvent);
}

/**
 * Retrieve recent system events.
 */
export async function getSystemEvents(
  limit = 100
) {
  return db
    .select()
    .from(systemEvents)
    .orderBy(
      desc(
        systemEvents.createdAt
      )
    )
    .limit(limit);
}

/* -------------------------------------------------------------------------- */
/* Monitor Sessions                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Create a new monitoring session.
 */
export async function createMonitorSession(
  mode: string,
  networkInterface?: string,
  pcapFile?: string
) {
  const sessionId =
    generateSessionId();

  const [session] =
    await db
      .insert(monitorSessions)
      .values({
        sessionId,

        mode,

        networkInterface:
          networkInterface ||
          null,

        pcapFile:
          pcapFile ||
          null,

        status:
          "running",

        startedAt:
          new Date(),
      })
      .returning();

  return session;
}

/**
 * Update monitoring session.
 */
export async function updateMonitorSession(
  sessionId: string,
  updates: {
    status?: string;
    packetsCapured?: number;
    flowsProcessed?: number;
    alertsGenerated?: number;
    stoppedAt?: Date;
  }
) {
  await db
    .update(monitorSessions)
    .set({
      ...updates,

      updatedAt:
        new Date(),
    })
    .where(
      eq(
        monitorSessions.sessionId,
        sessionId
      )
    );
}

/**
 * Get newest running monitor session.
 */
export async function getActiveSession() {
  const [session] =
    await db
      .select()
      .from(monitorSessions)
      .where(
        eq(
          monitorSessions.status,
          "running"
        )
      )
      .orderBy(
        desc(
          monitorSessions.createdAt
        )
      )
      .limit(1);

  return (
    session ||
    null
  );
}

/**
 * Get newest monitor session.
 */
export async function getLatestSession() {
  const [session] =
    await db
      .select()
      .from(monitorSessions)
      .orderBy(
        desc(
          monitorSessions.createdAt
        )
      )
      .limit(1);

  return (
    session ||
    null
  );
}

/**
 * Stop every running monitoring session.
 */
export async function stopAllSessions() {
  await db
    .update(monitorSessions)
    .set({
      status:
        "stopped",

      stoppedAt:
        new Date(),

      updatedAt:
        new Date(),
    })
    .where(
      eq(
        monitorSessions.status,
        "running"
      )
    );
}

/* -------------------------------------------------------------------------- */
/* Model Metadata                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Seed/update the configured model metadata.
 */
export async function upsertModelMetadata() {
  const models = [
    {
      modelId:
        "rf-v1.0.0",

      modelType:
        "RandomForest",

      version:
        "1.0.0",

      trainingDataset:
        "NSL-KDD",

      featureSchemaVersion:
        "41-v1",

      trainingSamples:
        125973,

      accuracy:
        0.9891,

      precision:
        0.9832,

      recall:
        0.9845,

      f1Score:
        0.9838,

      falsePositiveRate:
        0.0142,

      parameters: {
        n_estimators:
          100,

        random_state:
          42,

        max_features:
          "sqrt",
      },
    },

    {
      modelId:
        "xgb-v1.0.0",

      modelType:
        "XGBoost",

      version:
        "1.0.0",

      trainingDataset:
        "NSL-KDD",

      featureSchemaVersion:
        "41-v1",

      trainingSamples:
        125973,

      accuracy:
        0.9901,

      precision:
        0.9853,

      recall:
        0.9862,

      f1Score:
        0.9857,

      falsePositiveRate:
        0.0131,

      parameters: {
        n_estimators:
          100,

        learning_rate:
          0.1,

        random_state:
          42,
      },
    },

    {
      modelId:
        "if-v1.0.0",

      modelType:
        "IsolationForest",

      version:
        "1.0.0",

      trainingDataset:
        "NSL-KDD",

      featureSchemaVersion:
        "41-v1",

      trainingSamples:
        67343,

      accuracy:
        null,

      precision:
        null,

      recall:
        null,

      f1Score:
        null,

      falsePositiveRate:
        null,

      parameters: {
        n_estimators:
          100,

        contamination:
          0.05,

        random_state:
          42,
      },
    },
  ];

  for (
    const model of models
  ) {
    await db
      .insert(modelMetadata)
      .values(model)
      .onConflictDoUpdate({
        target:
          modelMetadata.modelId,

        set: {
          trainedAt:
            new Date(),
        },
      });
  }
}

/**
 * Retrieve stored model metadata.
 */
export async function getModelMetadata() {
  return db
    .select()
    .from(modelMetadata)
    .orderBy(
      modelMetadata.modelType
    );
}

/* -------------------------------------------------------------------------- */
/* Reports                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Generate a date-range security report.
 */
export async function generateReport(
  startDate: Date,
  endDate: Date
) {
  const conditions = [
    gte(
      alerts.timestamp,
      startDate
    ),

    lte(
      alerts.timestamp,
      endDate
    ),
  ];

  const [totals] =
    await db
      .select({
        total:
          count(),

        critical:
          sql<number>`
            COUNT(*) FILTER (
              WHERE ${alerts.severity} = 'CRITICAL'
            )
          `,

        high:
          sql<number>`
            COUNT(*) FILTER (
              WHERE ${alerts.severity} = 'HIGH'
            )
          `,

        medium:
          sql<number>`
            COUNT(*) FILTER (
              WHERE ${alerts.severity} = 'MEDIUM'
            )
          `,

        normal:
          sql<number>`
            COUNT(*) FILTER (
              WHERE ${alerts.severity} = 'NORMAL'
            )
          `,
      })
      .from(alerts)
      .where(
        and(
          ...conditions
        )
      );

  const attackBreakdown =
    await db
      .select({
        prediction:
          alerts.prediction,

        count:
          count(),
      })
      .from(alerts)
      .where(
        and(
          ...conditions
        )
      )
      .groupBy(
        alerts.prediction
      )
      .orderBy(
        desc(
          count()
        )
      );

  const topSources =
    await db
      .select({
        sourceIp:
          alerts.sourceIp,

        count:
          count(),
      })
      .from(alerts)
      .where(
        and(
          ...conditions,

          sql`
            ${alerts.prediction}
            != 'Normal'
          `
        )
      )
      .groupBy(
        alerts.sourceIp
      )
      .orderBy(
        desc(
          count()
        )
      )
      .limit(10);

  const topDestinations =
    await db
      .select({
        destinationIp:
          alerts.destinationIp,

        count:
          count(),
      })
      .from(alerts)
      .where(
        and(
          ...conditions
        )
      )
      .groupBy(
        alerts.destinationIp
      )
      .orderBy(
        desc(
          count()
        )
      )
      .limit(10);

  const recentAlerts =
    await db
      .select()
      .from(alerts)
      .where(
        and(
          ...conditions,

          sql`
            ${alerts.severity}
            IN ('CRITICAL', 'HIGH')
          `
        )
      )
      .orderBy(
        desc(
          alerts.timestamp
        )
      )
      .limit(20);

  return {
    period: {
      startDate,
      endDate,
    },

    totals,

    attackBreakdown,

    topSources,

    topDestinations,

    recentAlerts,
  };
}