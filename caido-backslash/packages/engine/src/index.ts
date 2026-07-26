/**
 * Public surface of the host-agnostic engine.
 *
 * Nothing in this package imports a Caido type. A host supplies a {@link RequestProvider}, a clock
 * and a randomness source; everything else is pure and testable offline against recorded bytes.
 */

// ---- host boundary ----
export type {
  EngineDeps,
  EngineRequest,
  EngineResponse,
  LoggerFn,
  LogLevel,
  NowFn,
  RandomSource,
  RequestProvider,
  SendOptions,
  SendOutcome,
  SleepFn,
  TransportFailure,
} from "./transport/types.ts";
export { header } from "./transport/types.ts";

// ---- response admission ----
export type { Admission, AdmissionOptions, AdmissionTally, SoftFailReason } from "./transport/admission.ts";
export {
  MAX_RETRY_AFTER_MS,
  admit,
  isUsable,
  newTally,
  parseRetryAfter,
  record,
  unusableRate,
} from "./transport/admission.ts";

// ---- throttling and halt supervision ----
export type {
  HaltReason,
  SendRecord,
  ProbeResult,
  ProbeTransport,
  ProbeTransportStats,
  ThrottleConfig,
  ThrottleState,
} from "./transport/throttle.ts";
export { DEFAULT_THROTTLE, createProbeTransport, isHalted } from "./transport/throttle.ts";

export type {
  ObserveContext,
  ObserveOutcome,
  ObserveSend,
  Observer,
  ObserverPlan,
} from "./transport/observe.ts";
export {
  buildObservationRequest,
  composeObservers,
  createRedirectObserver,
  createUrlObserver,
} from "./transport/observe.ts";

export type { Located, Origin, ResolveResult } from "./transport/url.ts";
export {
  formatLocated,
  formatOrigin,
  parseObservationUrl,
  removeDotSegments,
  resolveLocation,
  sameOrigin,
} from "./transport/url.ts";

export type { MeasureDeps, Measurement } from "./detect/measure.ts";
export { measure } from "./detect/measure.ts";

// ---- request layer ----
export type {
  AssembleOptions,
  BodyRestriction,
  Edit,
  HeaderField,
  Range,
  RequestTemplate,
} from "./request/template.ts";
export {
  MalformedRequestError,
  asciiBytes,
  assemble,
  findHeader,
  headerValue,
  locate,
  rangeLength,
  sliceText,
} from "./request/template.ts";

export type { Codec, EncodeResult, RefusalReason, WireForm } from "./request/codecs.ts";
export {
  COOKIE_VALUE_CODEC,
  CTL_ONLY,
  FORM_VALUE_CODEC,
  IDENTITY,
  JSON_ESCAPE,
  PATH_SEGMENT_CODEC,
  QUERY_NAME_CODEC,
  QUERY_VALUE_CODEC,
  encodePair,
} from "./request/codecs.ts";

export type {
  DeferredSurface,
  EnumerateOptions,
  Slot,
  SlotEnumeration,
  SurfaceFamily,
  SurfaceKind,
} from "./request/slots.ts";
export { enumerateSlots, looksPositional } from "./request/slots.ts";

export type { JsonSite, JsonSiteKind, JsonScanResult } from "./request/json.ts";
export { scanJson } from "./request/json.ts";

// ---- response featurisation ----
export type { BodyScan, ScanOptions } from "./response/scan.ts";
export {
  BIGRAM_BUCKETS,
  SCAN_CAP_BYTES,
  bigramCosine,
  findBodyStart,
  scanBody,
  scanWindows,
} from "./response/scan.ts";

export type { CanaryFrame, EchoAnalysis, EchoState, Span } from "./response/echo.ts";
export {
  EchoTransform,
  LEFT_ONLY_SLACK,
  capSpan,
  classifyTransform,
  locateEcho,
  mergeSpans,
  subtractSpans,
} from "./response/echo.ts";

export type { KeywordAutomaton } from "./response/keywords.ts";
export { KEYWORDS, buildKeywordAutomaton, defaultKeywordAutomaton, matchPatterns } from "./response/keywords.ts";

export {
  CLASS_COUNT,
  CLASS_TABLE,
  SKELETON_TABLE,
  SPECIAL_CLASSES,
  ByteClass,
  SkeletonClass,
  classDelta,
  classProfile,
  fnv1a,
} from "./response/classes.ts";

// ---- detection ----
export type { FeatureClass, FeatureDiff, FeatureSpec, FeatureVector, FeaturiseOptions } from "./detect/features.ts";
export { COUNTER_SPECS, SIMILARITY_THRESHOLD, differingFeatures, featurise } from "./detect/features.ts";

export type { ArmBuilder, Canary, LadderDeps, LadderOutcome, ProbeArms } from "./detect/ladder.ts";
export { M_ESTABLISH, M_FILTER, M_SCREEN, applyDeltaVeto, runLadder } from "./detect/ladder.ts";

export type {
  DiagnosticKind,
  SuiteDiagnostic,
  SuiteEvents,
  SuiteFinding,
  SuiteOptions,
  SuiteSummary,
  TargetCoordinates,
} from "./detect/runner.ts";
export { PayloadNotDeliverable, runSuite } from "./detect/runner.ts";

export type { Confidence, ControlArm, ControlName, Side, VetoResult } from "./detect/attribution.ts";
export {
  CONTROL_REPLICATES,
  applyControlVetoes,
  buildBd,
  buildControlArms,
  buildDs,
  buildDz,
  buildZ0,
  gradeConfidence,
  readFeature,
  sideOf,
} from "./detect/attribution.ts";

// ---- probe catalogue ----
export type {
  ConcatParams,
  DelimiterParams,
  InsertionMode,
  LanguageProbe,
  LengthParity,
  ProbePair,
  ProbeStage,
  ProbeTemplate,
  ValueParams,
  WrapParams,
} from "./probes/types.ts";
export {
  ALL_STATIC_PROBES,
  ARITHMETIC_PROBES,
  CONCATENATION_TEMPLATE,
  CONCATENATORS,
  DELIMITER_FALLBACK_PROBES,
  DELIMITER_PROBES,
  ESCAPE_SEQUENCE_PROBES,
  FILLER,
  INTERPOLATION_PROBES,
  INTERPOLATION_TRIAGE,
  INTERPOLATION_WRAPPERS,
  JSON_KEY_TEMPLATE,
  JSON_VALUE_TEMPLATE,
  LANGUAGE_PROBES,
  MAGIC_VALUES,
  MONGO_TEMPLATE,
  NGINX_ALIAS_TEMPLATE,
  ORDER_BY_PROBES,
  PATH_PROBES,
  TRANSFORM_DECODE_PAYLOADS,
  TRANSFORM_METACHARACTERS,
  TRIAGE_FUZZ,
  TRIAGE_FUZZ_ALT,
  corruptMagicValue,
} from "./probes/catalogue.ts";
export { equalisePair, padNumericLiteral, padWithFiller } from "./probes/pad.ts";
