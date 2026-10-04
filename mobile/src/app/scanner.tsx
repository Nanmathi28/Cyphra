import { CameraView, useCameraPermissions, type BarcodeScanningResult } from 'expo-camera';
import { Link } from 'expo-router';
import { useCallback, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Linking,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { BrandMark } from '../components/BrandMark';
import { ScanGlyph } from '../components/ScanGlyph';
import { analyzeUrl, NivaraApiError, type UrlAnalysisResponse } from '../api/nivaraApi';
import { analyzeQrOnlyIfUrl, classifyQrContent, type ClassifiedQr } from '../qr/qrContent';
import { colors } from '../theme/colors';

type ScanState = 'scanning' | 'empty' | 'camera-error' | 'review' | 'analyzing' | 'analysis-result' | 'analysis-error';

export default function ScannerScreen() {
  const [permission, requestPermission] = useCameraPermissions();
  const [scanState, setScanState] = useState<ScanState>('scanning');
  const [decodedText, setDecodedText] = useState('');
  const [analysisUrl, setAnalysisUrl] = useState('');
  const [classifiedContent, setClassifiedContent] = useState<ClassifiedQr | null>(null);
  const [analysisError, setAnalysisError] = useState('');
  const [analysisErrorKind, setAnalysisErrorKind] = useState<NivaraApiError['kind'] | null>(null);
  const [analysis, setAnalysis] = useState<UrlAnalysisResponse | null>(null);
  const [cameraError, setCameraError] = useState('');
  const handledScan = useRef(false);

  const submitUrl = useCallback(async (url: string) => {
    setScanState('analyzing');
    setAnalysisError('');
    setAnalysisErrorKind(null);
    try {
      const response = await analyzeQrOnlyIfUrl(classifyQrContent(url), analyzeUrl);
      if (!response) throw new Error('Only a validated web address can be submitted for analysis.');
      setAnalysis(response);
      setScanState('analysis-result');
    } catch (error) {
      setAnalysisError(
        error instanceof NivaraApiError
          ? error.message
          : 'The URL could not be analyzed because of an unexpected error.',
      );
      setAnalysisErrorKind(error instanceof NivaraApiError ? error.kind : null);
      setScanState('analysis-error');
    }
  }, []);

  const handleBarcodeScanned = useCallback((scan: BarcodeScanningResult) => {
    if (handledScan.current) return;
    handledScan.current = true;

    const content = typeof scan.data === 'string' ? scan.data : '';
    setDecodedText(content);
    const classified = classifyQrContent(content);
    setClassifiedContent(classified);
    if (classified.kind === 'empty') {
      setScanState('empty');
      return;
    }
    if (classified.kind !== 'url' || !classified.url) {
      setScanState('review');
      return;
    }
    if (classified.url.length > 8192 || /[\u0000-\u001f\u007f]/.test(classified.url)) {
      setClassifiedContent({ ...classified, kind: 'unsupported', title: 'Address cannot be analyzed', message: classified.url.length > 8192 ? 'This address is longer than the backend accepts (8,192 characters).' : 'This address contains control characters and cannot be analyzed.' });
      setScanState('review');
      return;
    }
    setAnalysisUrl(classified.url);
    void submitUrl(classified.url);
  }, [submitUrl]);

  const startAgain = () => {
    handledScan.current = false;
    setDecodedText('');
    setAnalysisUrl('');
    setClassifiedContent(null);
    setAnalysisError('');
    setAnalysisErrorKind(null);
    setAnalysis(null);
    setCameraError('');
    setScanState('scanning');
  };

  const handleCameraError = (event: { message: string }) => {
    handledScan.current = true;
    setCameraError(event.message || 'The camera could not be started.');
    setScanState('camera-error');
  };

  const openSettings = async () => {
    try {
      await Linking.openSettings();
    } catch {
      setCameraError('Open your device settings and allow NIVARA to use the camera.');
    }
  };

  return (
    <SafeAreaView style={styles.safeArea} edges={['top', 'bottom']}>
      <View style={styles.content}>
        <View style={styles.header}>
          <View style={styles.brand}>
            <BrandMark />
            <View>
              <Text style={styles.wordmark}>NIVARA</Text>
              <Text style={styles.brandCaption}>QR DESTINATION SAFETY</Text>
            </View>
          </View>
          <Link href="/" asChild>
            <Pressable accessibilityRole="button" accessibilityLabel="Return home" style={styles.homeButton}>
              <Text style={styles.homeButtonText}>HOME</Text>
            </Pressable>
          </Link>
        </View>

        <ScrollView contentContainerStyle={styles.scrollContent} showsVerticalScrollIndicator={false}>
          <View style={styles.intro}>
            <Text style={styles.eyebrow}>CAMERA SCANNER</Text>
            <Text style={styles.title}>
              {scanState === 'analysis-result' ? 'Review security analysis' : scanState === 'analyzing' ? 'Analyzing destination' : scanState === 'review' && classifiedContent ? classifiedContent.title : 'Point at a QR code'}
            </Text>
            <Text style={styles.description}>
              Keep the code inside the frame. Web addresses are sent to NIVARA for analysis; other QR formats are displayed for review only. NIVARA never opens links or takes actions automatically.
            </Text>
          </View>

          {!permission ? (
            <StatusPanel title="Checking camera permission" message="Please wait while NIVARA checks camera access." />
          ) : !permission.granted ? (
            <StatusPanel
              title={permission.canAskAgain ? 'Camera permission needed' : 'Camera access is off'}
              message={
                permission.canAskAgain
                  ? 'Allow camera access to scan a QR code. NIVARA only uses the camera on this scanner screen.'
                  : 'Camera permission was denied. Enable camera access for NIVARA in your device settings to scan.'
              }
              actionLabel={permission.canAskAgain ? 'Allow camera' : 'Open settings'}
              onAction={permission.canAskAgain ? requestPermission : openSettings}
            />
          ) : scanState === 'camera-error' ? (
            <StatusPanel
              title="Camera unavailable"
              message={cameraError || 'The camera could not be started. Check that it is available and try again.'}
              actionLabel="Try again"
              onAction={startAgain}
            />
          ) : scanState === 'analysis-result' && analysis ? (
            <AnalysisPanel response={analysis} decodedText={decodedText} onScanAgain={startAgain} />
          ) : scanState === 'analyzing' ? (
            <View style={styles.statusPanel}>
              <ActivityIndicator size="large" color={colors.blue} />
              <Text style={styles.statusTitle}>Analyzing destination</Text>
              <Text style={styles.statusMessage}>Checking URL signals and available backend evidence. This may take a few seconds.</Text>
            </View>
          ) : scanState === 'analysis-error' ? (
            <StatusPanel
              title={analysisErrorKind === 'timeout' ? 'Backend request timed out' : analysisErrorKind === 'network' ? 'Backend unreachable' : 'Analysis could not be completed'}
              message={`${analysisError} No safety verdict is available.`}
              actionLabel="Try analysis again"
              onAction={() => { if (analysisUrl) void submitUrl(analysisUrl); }}
              secondaryLabel="Scan again"
              onSecondary={startAgain}
            />
          ) : scanState === 'review' && classifiedContent ? (
            <QrReviewPanel content={classifiedContent} onScanAgain={startAgain} />
          ) : scanState === 'empty' ? (
            <StatusPanel
              title="No readable content found"
              message="The camera detected a QR code but it did not contain readable text. Try scanning again with the code clearly in view."
              actionLabel="Scan again"
              onAction={startAgain}
            />
          ) : (
            <View style={styles.cameraCard}>
              <View style={styles.cameraPreview}>
                <CameraView
                  style={StyleSheet.absoluteFill}
                  facing="back"
                  barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
                  onBarcodeScanned={handleBarcodeScanned}
                  onMountError={handleCameraError}
                />
                <View pointerEvents="none" style={styles.frameLayer}>
                  <View style={[styles.frameCorner, styles.topLeft]} />
                  <View style={[styles.frameCorner, styles.topRight]} />
                  <View style={[styles.frameCorner, styles.bottomLeft]} />
                  <View style={[styles.frameCorner, styles.bottomRight]} />
                  <View style={styles.frameCenter}><BrandMark /></View>
                </View>
              </View>
              <View style={styles.cameraInstruction}>
                <View style={styles.liveDot} />
                <Text style={styles.instructionText}>Align the QR code within the frame</Text>
              </View>
            </View>
          )}

          <View style={styles.privacyNote}>
            <Text style={styles.privacyTitle}>YOUR CHOICE, EVERY STEP</Text>
            <Text style={styles.privacyText}>NIVARA will not open scanned links. A verdict is shown only when the backend returns a usable decision; unavailable evidence is shown as limited.</Text>
          </View>
        </ScrollView>
      </View>
    </SafeAreaView>
  );
}

function StatusPanel({
  title,
  message,
  actionLabel,
  onAction,
  secondaryLabel,
  onSecondary,
}: {
  title: string;
  message: string;
  actionLabel?: string;
  onAction?: () => void | Promise<unknown>;
  secondaryLabel?: string;
  onSecondary?: () => void | Promise<unknown>;
}) {
  return (
    <View style={styles.statusPanel}>
      <View style={styles.statusMark}><ScanGlyph color={colors.accent} /></View>
      <Text style={styles.statusTitle}>{title}</Text>
      <Text style={styles.statusMessage}>{message}</Text>
      {actionLabel && onAction ? <ActionButton label={actionLabel} onPress={onAction} /> : null}
      {secondaryLabel && onSecondary ? <ActionButton label={secondaryLabel} onPress={onSecondary} secondary /> : null}
    </View>
  );
}

function QrReviewPanel({ content, onScanAgain }: { content: ClassifiedQr; onScanAgain: () => void }) {
  const payment = content.kind === 'upi';
  return (
    <View style={styles.reviewCard}>
      <View style={styles.reviewIcon}><ScanGlyph color={colors.accent} /></View>
      <Text style={styles.reviewTitle}>{content.title}</Text>
      <Text style={styles.reviewKind}>{content.kind === 'unsupported' ? 'UNSUPPORTED FORMAT' : `${content.kind.toUpperCase()} QR CONTENT`}</Text>
      {content.message ? <Text style={[styles.reviewMessage, payment && styles.paymentWarning]}>{content.message}</Text> : null}
      {content.fields.map((field) => (
        <View key={field.label} style={styles.reviewField}>
          <Text style={styles.reviewLabel}>{field.label}</Text>
          <Text selectable style={styles.reviewValue}>{field.value}</Text>
          {field.sensitive ? <Text style={styles.sensitiveHint}>Partially masked for privacy</Text> : null}
        </View>
      ))}
      {content.kind === 'text' || content.kind === 'unsupported' ? (
        <Text selectable style={styles.rawContent}>{content.raw}</Text>
      ) : null}
      {payment ? (
        <Text style={styles.noPaymentAction}>Review only · No payment has been initiated</Text>
      ) : null}
      <ActionButton label="Scan again" onPress={onScanAgain} />
    </View>
  );
}

function AnalysisPanel({
  response,
  decodedText,
  onScanAgain,
}: {
  response: UrlAnalysisResponse;
  decodedText: string;
  onScanAgain: () => void;
}) {
  const decision = response.risk_decision;
  if (!decision) {
    return <StatusPanel title="No risk decision returned" message="The backend response did not contain a risk decision. No safety verdict is available." actionLabel="Scan again" onAction={onScanAgain} />;
  }

  const evidence = decision.evidence_summary;
  const evidenceIncomplete = response.analysis_status === 'unavailable' || decision.evidence_quality !== 'complete';
  const mustWithholdSafe = evidenceIncomplete && decision.risk_level.toUpperCase() === 'SAFE';
  const shownRisk = mustWithholdSafe ? 'INCOMPLETE' : decision.risk_level;
  const shownAction = mustWithholdSafe ? 'CAUTION' : decision.action;
  const threatStatus = evidence.threat_intelligence?.status || 'not provided';
  const providers = evidence.threat_intelligence?.providers || response.threat_intelligence?.providers || [];
  const mlEvidence = evidence.ml;
  const mlDescription = mlEvidence?.status === 'available'
    ? `${mlEvidence.predicted_class || 'Prediction available'}${typeof mlEvidence.confidence === 'number' ? ` · ${(mlEvidence.confidence * 100).toFixed(1)}% confidence` : ''}`
    : mlEvidence?.status === 'unavailable' || response.ml?.status === 'unavailable'
      ? 'Unavailable; no classifier evidence was returned.'
      : 'Status not provided by the backend.';
  const redirect = evidence.redirect;
  const urlEvidence = evidence.url_security;
  const suspiciousKeywords = response.security_indicators?.suspicious_keywords;

  return (
    <View style={styles.analysisCard}>
      <View style={styles.decisionHeader}>
        <View style={[styles.riskPill, mustWithholdSafe && styles.riskPillIncomplete]}>
          <Text style={styles.riskPillText}>{shownRisk}</Text>
        </View>
        <Text style={styles.actionText}>ACTION: {shownAction}</Text>
      </View>
      <Text style={styles.coverageText}>
        {evidenceIncomplete
          ? `Evidence coverage is ${decision.evidence_quality || 'incomplete'}. Treat this result with caution.`
          : `Evidence coverage: ${decision.evidence_quality}.`}
      </Text>
      {mustWithholdSafe ? (
        <Text style={styles.incompleteWarning}>
          The backend returned {decision.risk_level} / {decision.action}, but evidence was incomplete. NIVARA is withholding a safe outcome.
        </Text>
      ) : null}

      <Text style={styles.sectionLabel}>SCANNED URL</Text>
      <Text selectable style={styles.decodedText}>{decodedText}</Text>
      {response.normalized_url && response.normalized_url !== decodedText ? (
        <Text selectable style={styles.normalizedText}>Analyzed as: {response.normalized_url}</Text>
      ) : null}

      <Text style={styles.sectionLabel}>EVIDENCE SOURCES</Text>
      <EvidenceRow label="URL security" value={urlEvidence?.status || 'not provided'} detail={urlEvidence?.scheme ? `Scheme: ${urlEvidence.scheme}` : undefined} />
      <EvidenceRow label="URL classifier" value={mlEvidence?.status || 'not provided'} detail={mlDescription} />
      <EvidenceRow
        label="Redirect check"
        value={redirect?.status || 'not provided'}
        detail={typeof response.redirect_analysis?.redirect_count === 'number' ? `${response.redirect_analysis.redirect_count} redirect(s)` : undefined}
      />
      <EvidenceRow label="Threat intelligence" value={threatStatus} detail={providers.length ? providers.map((item) => `${item.provider || 'Provider'}: ${item.status || 'unknown'}`).join(' · ') : 'No provider details returned.'} />
      {Array.isArray(suspiciousKeywords) && suspiciousKeywords.length > 0 ? (
        <EvidenceRow label="URL indicators" value="Keywords observed" detail={suspiciousKeywords.map(String).join(', ')} />
      ) : null}

      <Text style={styles.sectionLabel}>WHY THIS DECISION</Text>
      {decision.reasons.length ? decision.reasons.map((reason, index) => (
        <View key={`${reason.code}-${index}`} style={styles.reasonRow}>
          <Text style={styles.reasonCode}>{reason.code}</Text>
          <Text style={styles.reasonMessage}>{reason.message}</Text>
        </View>
      )) : <Text style={styles.emptyEvidence}>The backend returned no decision reasons.</Text>}

      <Text style={styles.policyText}>
        Policy {decision.decision_policy_version} · Decision confidence {Math.round(decision.decision_confidence * 100)}%
      </Text>
      <ActionButton label="Scan again" onPress={onScanAgain} />
    </View>
  );
}

function EvidenceRow({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <View style={styles.evidenceRow}>
      <View style={styles.evidenceHeading}>
        <Text style={styles.evidenceLabel}>{label}</Text>
        <Text style={styles.evidenceValue}>{value.toUpperCase()}</Text>
      </View>
      {detail ? <Text style={styles.evidenceDetail}>{detail}</Text> : null}
    </View>
  );
}

function ActionButton({ label, onPress, secondary = false }: { label: string; onPress: () => void | Promise<unknown>; secondary?: boolean }) {
  return (
    <Pressable
      accessibilityRole="button"
      onPress={() => { void onPress(); }}
      style={({ pressed }) => [styles.actionButton, secondary && styles.secondaryButton, pressed && styles.actionPressed]}
    >
      <Text style={[styles.actionButtonText, secondary && styles.secondaryButtonText]}>{label}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: colors.background },
  content: { flex: 1, width: '100%', maxWidth: 560, alignSelf: 'center', paddingHorizontal: 24, paddingTop: 14 },
  header: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  brand: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  wordmark: { color: colors.text, fontSize: 18, fontWeight: '800', letterSpacing: 2.4 },
  brandCaption: { marginTop: 3, color: colors.textSubtle, fontSize: 9, fontWeight: '700', letterSpacing: 1.15 },
  homeButton: { borderWidth: 1, borderColor: colors.border, borderRadius: 14, paddingHorizontal: 13, paddingVertical: 9 },
  homeButtonText: { color: colors.accent, fontSize: 10, fontWeight: '800', letterSpacing: 1 },
  scrollContent: { paddingTop: 34, paddingBottom: 24 },
  intro: { marginBottom: 20 },
  eyebrow: { color: colors.blue, fontSize: 10, fontWeight: '800', letterSpacing: 1.4 },
  title: { marginTop: 8, color: colors.text, fontSize: 28, lineHeight: 35, fontWeight: '700', letterSpacing: -0.6 },
  description: { marginTop: 8, color: colors.textMuted, fontSize: 13, lineHeight: 20 },
  cameraCard: { overflow: 'hidden', borderWidth: 1, borderColor: colors.border, borderRadius: 22, backgroundColor: colors.surface },
  cameraPreview: { height: 390, overflow: 'hidden', backgroundColor: '#020912' },
  frameLayer: { ...StyleSheet.absoluteFill, alignItems: 'center', justifyContent: 'center' },
  frameCorner: { position: 'absolute', width: 40, height: 40, borderColor: colors.blue },
  topLeft: { top: '22%', left: '12%', borderTopWidth: 4, borderLeftWidth: 4, borderTopLeftRadius: 9 },
  topRight: { top: '22%', right: '12%', borderTopWidth: 4, borderRightWidth: 4, borderTopRightRadius: 9 },
  bottomLeft: { bottom: '22%', left: '12%', borderBottomWidth: 4, borderLeftWidth: 4, borderBottomLeftRadius: 9 },
  bottomRight: { bottom: '22%', right: '12%', borderBottomWidth: 4, borderRightWidth: 4, borderBottomRightRadius: 9 },
  frameCenter: { opacity: 0.75, transform: [{ scale: 1.4 }] },
  cameraInstruction: { minHeight: 54, flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 9, paddingHorizontal: 15 },
  liveDot: { width: 7, height: 7, borderRadius: 4, backgroundColor: colors.blue },
  instructionText: { color: colors.textMuted, fontSize: 12, fontWeight: '600' },
  analysisCard: { padding: 18, borderWidth: 1, borderColor: colors.border, borderRadius: 22, backgroundColor: colors.surface },
  decisionHeader: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: 12 },
  riskPill: { maxWidth: '58%', paddingHorizontal: 13, paddingVertical: 8, borderRadius: 14, backgroundColor: colors.blueTint },
  riskPillIncomplete: { borderWidth: 1, borderColor: '#E6A84A', backgroundColor: '#392D1A' },
  riskPillText: { color: colors.accent, fontSize: 12, fontWeight: '900', letterSpacing: 0.8 },
  actionText: { flexShrink: 1, color: colors.text, fontSize: 11, fontWeight: '800', textAlign: 'right', letterSpacing: 0.6 },
  coverageText: { marginTop: 12, color: colors.textMuted, fontSize: 12, lineHeight: 18 },
  incompleteWarning: { marginTop: 10, padding: 11, borderRadius: 11, backgroundColor: '#392D1A', color: '#FFD99A', fontSize: 11, lineHeight: 17 },
  sectionLabel: { marginTop: 21, marginBottom: 8, color: colors.accent, fontSize: 9, fontWeight: '900', letterSpacing: 1.15 },
  normalizedText: { marginTop: 8, color: colors.textSubtle, fontSize: 11, lineHeight: 16 },
  evidenceRow: { paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: colors.border },
  evidenceHeading: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: 10 },
  evidenceLabel: { flex: 1, color: colors.text, fontSize: 12, fontWeight: '700' },
  evidenceValue: { flexShrink: 1, color: colors.accent, fontSize: 9, fontWeight: '800', textAlign: 'right', letterSpacing: 0.45 },
  evidenceDetail: { marginTop: 5, color: colors.textMuted, fontSize: 10, lineHeight: 15 },
  reasonRow: { marginTop: 8, padding: 11, borderWidth: 1, borderColor: colors.border, borderRadius: 11, backgroundColor: colors.background },
  reasonCode: { color: colors.accent, fontSize: 9, fontWeight: '800', letterSpacing: 0.5 },
  reasonMessage: { marginTop: 4, color: colors.textMuted, fontSize: 11, lineHeight: 16 },
  emptyEvidence: { color: colors.textSubtle, fontSize: 11, lineHeight: 16 },
  policyText: { marginTop: 14, color: colors.textSubtle, fontSize: 9, lineHeight: 14, textAlign: 'center' },
  decodedText: { marginTop: 18, maxHeight: 220, padding: 14, overflow: 'hidden', borderWidth: 1, borderColor: colors.border, borderRadius: 13, backgroundColor: colors.background, color: colors.text, fontSize: 14, lineHeight: 21 },
  statusPanel: { alignItems: 'center', padding: 24, borderWidth: 1, borderColor: colors.border, borderRadius: 22, backgroundColor: colors.surface },
  statusMark: { width: 52, height: 52, alignItems: 'center', justifyContent: 'center', borderRadius: 17, backgroundColor: colors.blueTint },
  statusTitle: { marginTop: 17, color: colors.text, fontSize: 18, fontWeight: '700', textAlign: 'center' },
  statusMessage: { marginTop: 8, color: colors.textMuted, fontSize: 14, lineHeight: 21, textAlign: 'center' },
  actionButton: { minHeight: 50, alignItems: 'center', justifyContent: 'center', marginTop: 20, paddingHorizontal: 22, borderRadius: 14, backgroundColor: colors.blue },
  secondaryButton: { borderWidth: 1, borderColor: colors.border, backgroundColor: colors.surfaceRaised },
  actionButtonText: { color: colors.background, fontSize: 14, fontWeight: '800' },
  secondaryButtonText: { color: colors.text },
  actionPressed: { opacity: 0.78 },
  reviewCard: { padding: 18, borderWidth: 1, borderColor: colors.border, borderRadius: 22, backgroundColor: colors.surface },
  reviewIcon: { width: 48, height: 48, alignItems: 'center', justifyContent: 'center', borderRadius: 15, backgroundColor: colors.blueTint },
  reviewTitle: { marginTop: 16, color: colors.text, fontSize: 21, lineHeight: 27, fontWeight: '700' },
  reviewKind: { marginTop: 5, color: colors.accent, fontSize: 10, fontWeight: '900', letterSpacing: 1 },
  reviewMessage: { marginTop: 14, color: colors.textMuted, fontSize: 13, lineHeight: 20 },
  paymentWarning: { padding: 12, borderWidth: 1, borderColor: '#A97932', borderRadius: 12, backgroundColor: '#352A1C', color: '#FFE0AD' },
  reviewField: { marginTop: 13, paddingTop: 11, borderTopWidth: 1, borderTopColor: colors.border },
  reviewLabel: { color: colors.textMuted, fontSize: 11, fontWeight: '700' },
  reviewValue: { marginTop: 4, color: colors.text, fontSize: 14, lineHeight: 21 },
  sensitiveHint: { marginTop: 3, color: colors.textSubtle, fontSize: 10 },
  rawContent: { marginTop: 14, padding: 12, borderRadius: 11, backgroundColor: colors.background, color: colors.text, fontSize: 13, lineHeight: 19 },
  noPaymentAction: { marginTop: 14, color: '#FFE0AD', fontSize: 11, fontWeight: '800', textAlign: 'center' },
  privacyNote: { marginTop: 20, padding: 15, borderWidth: 1, borderColor: colors.border, borderRadius: 15, backgroundColor: colors.blueTint },
  privacyTitle: { color: colors.accent, fontSize: 9, fontWeight: '800', letterSpacing: 1.1 },
  privacyText: { marginTop: 6, color: colors.textMuted, fontSize: 11, lineHeight: 17 },
});
