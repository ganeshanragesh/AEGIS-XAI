import {
  pgTable,
  serial,
  text,
  real,
  boolean,
  integer,
  timestamp,
  jsonb,
  varchar,
  index,
} from "drizzle-orm/pg-core";

// ─── Flows ───────────────────────────────────────────────────────────────────
export const flows = pgTable(
  "flows",
  {
    id: serial("id").primaryKey(),
    flowKey: varchar("flow_key", { length: 256 }).notNull(),
    sourceIp: varchar("source_ip", { length: 45 }).notNull(),
    destinationIp: varchar("destination_ip", { length: 45 }).notNull(),
    sourcePort: integer("source_port").notNull(),
    destinationPort: integer("destination_port").notNull(),
    protocol: varchar("protocol", { length: 10 }).notNull(),
    duration: real("duration").notNull().default(0),
    srcBytes: integer("src_bytes").notNull().default(0),
    dstBytes: integer("dst_bytes").notNull().default(0),
    srcPackets: integer("src_packets").notNull().default(0),
    dstPackets: integer("dst_packets").notNull().default(0),
    totalPackets: integer("total_packets").notNull().default(0),
    service: varchar("service", { length: 64 }).default("other"),
    flag: varchar("flag", { length: 16 }).default("SF"),
    land: boolean("land").default(false),
    wrongFragment: integer("wrong_fragment").default(0),
    urgent: integer("urgent").default(0),
    hot: integer("hot").default(0),
    numFailedLogins: integer("num_failed_logins").default(0),
    loggedIn: boolean("logged_in").default(false),
    numCompromised: integer("num_compromised").default(0),
    rootShell: boolean("root_shell").default(false),
    suAttempted: boolean("su_attempted").default(false),
    numRoot: integer("num_root").default(0),
    numFileCreations: integer("num_file_creations").default(0),
    numShells: integer("num_shells").default(0),
    numAccessFiles: integer("num_access_files").default(0),
    numOutboundCmds: integer("num_outbound_cmds").default(0),
    isHostLogin: boolean("is_host_login").default(false),
    isGuestLogin: boolean("is_guest_login").default(false),
    count: integer("count").default(1),
    srvCount: integer("srv_count").default(1),
    serrorRate: real("serror_rate").default(0),
    srvSerrorRate: real("srv_serror_rate").default(0),
    rerrorRate: real("rerror_rate").default(0),
    srvRerrorRate: real("srv_rerror_rate").default(0),
    sameSrvRate: real("same_srv_rate").default(1),
    diffSrvRate: real("diff_srv_rate").default(0),
    srvDiffHostRate: real("srv_diff_host_rate").default(0),
    dstHostCount: integer("dst_host_count").default(1),
    dstHostSrvCount: integer("dst_host_srv_count").default(1),
    dstHostSameSrvRate: real("dst_host_same_srv_rate").default(1),
    dstHostDiffSrvRate: real("dst_host_diff_srv_rate").default(0),
    dstHostSameSrcPortRate: real("dst_host_same_src_port_rate").default(0),
    dstHostSrvDiffHostRate: real("dst_host_srv_diff_host_rate").default(0),
    dstHostSerrorRate: real("dst_host_serror_rate").default(0),
    dstHostSrvSerrorRate: real("dst_host_srv_serror_rate").default(0),
    dstHostRerrorRate: real("dst_host_rerror_rate").default(0),
    dstHostSrvRerrorRate: real("dst_host_srv_rerror_rate").default(0),
    captureMode: varchar("capture_mode", { length: 16 }).default("live"),
    pcapFile: varchar("pcap_file", { length: 512 }),
    firstSeen: timestamp("first_seen").defaultNow(),
    lastSeen: timestamp("last_seen").defaultNow(),
    finalized: boolean("finalized").default(false),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (t) => [index("flows_flow_key_idx").on(t.flowKey), index("flows_created_at_idx").on(t.createdAt)]
);

// ─── Alerts ──────────────────────────────────────────────────────────────────
export const alerts = pgTable(
  "alerts",
  {
    id: serial("id").primaryKey(),
    eventId: varchar("event_id", { length: 64 }).notNull().unique(),
    flowId: integer("flow_id").references(() => flows.id),
    timestamp: timestamp("timestamp").defaultNow(),
    sourceIp: varchar("source_ip", { length: 45 }).notNull(),
    destinationIp: varchar("destination_ip", { length: 45 }).notNull(),
    sourcePort: integer("source_port").notNull(),
    destinationPort: integer("destination_port").notNull(),
    protocol: varchar("protocol", { length: 10 }).notNull(),
    service: varchar("service", { length: 64 }),
    prediction: varchar("prediction", { length: 32 }).notNull(),
    confidence: real("confidence").notNull(),
    anomalyDetected: boolean("anomaly_detected").default(false),
    anomalyScore: real("anomaly_score"),
    severity: varchar("severity", { length: 16 }).notNull(),
    mitreId: varchar("mitre_id", { length: 16 }),
    mitreTactic: varchar("mitre_tactic", { length: 128 }),
    mitreDescription: text("mitre_description"),
    rfConfidence: real("rf_confidence"),
    xgbConfidence: real("xgb_confidence"),
    ensembleConfidence: real("ensemble_confidence"),
    modelVersion: varchar("model_version", { length: 32 }).default("1.0.0"),
    status: varchar("status", { length: 16 }).default("open"),
    captureMode: varchar("capture_mode", { length: 16 }).default("live"),
    pcapFile: varchar("pcap_file", { length: 512 }),
    inferenceTimeMs: real("inference_time_ms"),
    shapTimeMs: real("shap_time_ms"),
    createdAt: timestamp("created_at").defaultNow(),
    updatedAt: timestamp("updated_at").defaultNow(),
  },
  (t) => [
    index("alerts_event_id_idx").on(t.eventId),
    index("alerts_severity_idx").on(t.severity),
    index("alerts_prediction_idx").on(t.prediction),
    index("alerts_timestamp_idx").on(t.timestamp),
    index("alerts_source_ip_idx").on(t.sourceIp),
  ]
);

// ─── Detections ───────────────────────────────────────────────────────────────
export const detections = pgTable(
  "detections",
  {
    id: serial("id").primaryKey(),
    alertId: integer("alert_id")
      .notNull()
      .references(() => alerts.id),
    model: varchar("model", { length: 32 }).notNull(),
    prediction: varchar("prediction", { length: 32 }).notNull(),
    confidence: real("confidence").notNull(),
    probabilities: jsonb("probabilities"),
    inferenceTimeMs: real("inference_time_ms"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (t) => [index("detections_alert_id_idx").on(t.alertId)]
);

// ─── SHAP Explanations ────────────────────────────────────────────────────────
export const shapExplanations = pgTable(
  "shap_explanations",
  {
    id: serial("id").primaryKey(),
    alertId: integer("alert_id")
      .notNull()
      .references(() => alerts.id),
    featureName: varchar("feature_name", { length: 64 }).notNull(),
    featureValue: real("feature_value"),
    featureValueRaw: text("feature_value_raw"),
    shapValue: real("shap_value").notNull(),
    rank: integer("rank").notNull(),
    direction: varchar("direction", { length: 8 }).notNull(),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (t) => [index("shap_alert_id_idx").on(t.alertId)]
);

// ─── System Events ────────────────────────────────────────────────────────────
export const systemEvents = pgTable(
  "system_events",
  {
    id: serial("id").primaryKey(),
    eventId: varchar("event_id", { length: 64 }).notNull(),
    component: varchar("component", { length: 64 }).notNull(),
    eventType: varchar("event_type", { length: 64 }).notNull(),
    severity: varchar("severity", { length: 16 }).notNull().default("info"),
    message: text("message").notNull(),
    details: jsonb("details"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (t) => [index("system_events_component_idx").on(t.component), index("system_events_created_at_idx").on(t.createdAt)]
);

// ─── Model Metadata ───────────────────────────────────────────────────────────
export const modelMetadata = pgTable("model_metadata", {
  id: serial("id").primaryKey(),
  modelId: varchar("model_id", { length: 64 }).notNull().unique(),
  modelType: varchar("model_type", { length: 32 }).notNull(),
  version: varchar("version", { length: 32 }).notNull(),
  trainingDataset: varchar("training_dataset", { length: 128 }),
  featureSchemaVersion: varchar("feature_schema_version", { length: 32 }),
  trainingSamples: integer("training_samples"),
  accuracy: real("accuracy"),
  precision: real("precision"),
  recall: real("recall"),
  f1Score: real("f1_score"),
  falsePositiveRate: real("false_positive_rate"),
  parameters: jsonb("parameters"),
  trainedAt: timestamp("trained_at").defaultNow(),
  createdAt: timestamp("created_at").defaultNow(),
});

// ─── Monitor Sessions ─────────────────────────────────────────────────────────
export const monitorSessions = pgTable("monitor_sessions", {
  id: serial("id").primaryKey(),
  sessionId: varchar("session_id", { length: 64 }).notNull().unique(),
  mode: varchar("mode", { length: 16 }).notNull().default("live"),
  networkInterface: varchar("network_interface", { length: 64 }),
  pcapFile: varchar("pcap_file", { length: 512 }),
  status: varchar("status", { length: 16 }).notNull().default("stopped"),
  packetsCapured: integer("packets_captured").default(0),
  flowsProcessed: integer("flows_processed").default(0),
  alertsGenerated: integer("alerts_generated").default(0),
  startedAt: timestamp("started_at"),
  stoppedAt: timestamp("stopped_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// ─── Type exports ─────────────────────────────────────────────────────────────
export type Flow = typeof flows.$inferSelect;
export type NewFlow = typeof flows.$inferInsert;
export type Alert = typeof alerts.$inferSelect;
export type NewAlert = typeof alerts.$inferInsert;
export type Detection = typeof detections.$inferSelect;
export type NewDetection = typeof detections.$inferInsert;
export type ShapExplanation = typeof shapExplanations.$inferSelect;
export type NewShapExplanation = typeof shapExplanations.$inferInsert;
export type SystemEvent = typeof systemEvents.$inferSelect;
export type NewSystemEvent = typeof systemEvents.$inferInsert;
export type ModelMetadata = typeof modelMetadata.$inferSelect;
export type NewModelMetadata = typeof modelMetadata.$inferInsert;
export type MonitorSession = typeof monitorSessions.$inferSelect;
export type NewMonitorSession = typeof monitorSessions.$inferInsert;
