import { Link } from 'expo-router';
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { BrandMark } from '../components/BrandMark';
import { ScanGlyph } from '../components/ScanGlyph';
import { colors } from '../theme/colors';

export default function HomeScreen() {
  return (
    <SafeAreaView style={styles.safeArea} edges={['top', 'bottom']}>
      <ScrollView
        contentContainerStyle={styles.content}
        showsVerticalScrollIndicator={false}
      >
        <View style={styles.header}>
          <View style={styles.brand}>
            <BrandMark />
            <View>
              <Text style={styles.wordmark}>NIVARA</Text>
              <Text style={styles.brandCaption}>QR DESTINATION SAFETY</Text>
            </View>
          </View>
          <View style={styles.demoTag}>
            <View style={styles.demoDot} />
            <Text style={styles.demoLabel}>DEMO</Text>
          </View>
        </View>

        <View style={styles.hero}>
          <View style={styles.eyebrow}>
            <View style={styles.eyebrowLine} />
            <Text style={styles.eyebrowText}>PAUSE BEFORE YOU PROCEED</Text>
          </View>
          <Text style={styles.title}>Know where a QR code leads.</Text>
          <Text style={styles.description}>
            NIVARA is designed to help you review a QR destination for security
            risks before choosing to open it.
          </Text>
        </View>

        <View style={styles.scanCard}>
          <View style={styles.cardGlow} />
          <View style={styles.cardHeader}>
            <View style={styles.cardIcon}>
              <ScanGlyph />
            </View>
            <View style={styles.cardBadge}>
              <Text style={styles.cardBadgeText}>QUICK CHECK</Text>
            </View>
          </View>
          <Text style={styles.cardTitle}>Check the destination first</Text>
          <Text style={styles.cardDescription}>
            Scan a code to begin reviewing its destination. You stay in control
            before opening any link.
          </Text>
          <Link href="/scanner" asChild>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Scan QR Code"
              style={({ pressed }) => [
                styles.scanButton,
                pressed && styles.scanButtonPressed,
              ]}
            >
              <ScanGlyph />
              <Text style={styles.scanButtonText}>Scan QR Code</Text>
              <Text style={styles.scanButtonArrow} accessible={false}>
                {'>'}
              </Text>
            </Pressable>
          </Link>
          <Text style={styles.disclaimer}>
            QR scanning uses your camera. Scanned links are not opened automatically.
          </Text>
        </View>

        <View style={styles.features}>
          <FeatureRow
            number="01"
            title="Destination awareness"
            description="Review where a QR code points before you continue."
          />
          <View style={styles.featureDivider} />
          <FeatureRow
            number="02"
            title="Clear security signals"
            description="Understand the signs that may call for caution."
          />
        </View>

        <View style={styles.footer}>
          <View style={styles.footerRule} />
          <Text style={styles.footerText}>A SAFER MOMENT TO CHECK</Text>
          <View style={styles.footerRule} />
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

function FeatureRow({
  number,
  title,
  description,
}: {
  number: string;
  title: string;
  description: string;
}) {
  return (
    <View style={styles.featureRow}>
      <Text style={styles.featureNumber}>{number}</Text>
      <View style={styles.featureCopy}>
        <Text style={styles.featureTitle}>{title}</Text>
        <Text style={styles.featureDescription}>{description}</Text>
      </View>
      <View style={styles.featureArrow}>
        <Text style={styles.featureArrowText} accessible={false}>
          {'>'}
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: colors.background,
  },
  content: {
    width: '100%',
    maxWidth: 560,
    alignSelf: 'center',
    paddingHorizontal: 24,
    paddingTop: 14,
    paddingBottom: 28,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  brand: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  wordmark: {
    color: colors.text,
    fontSize: 18,
    fontWeight: '800',
    letterSpacing: 2.4,
  },
  brandCaption: {
    marginTop: 3,
    color: colors.textSubtle,
    fontSize: 9,
    fontWeight: '700',
    letterSpacing: 1.15,
  },
  demoTag: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 7,
    paddingHorizontal: 10,
    paddingVertical: 7,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 20,
    backgroundColor: colors.surface,
  },
  demoDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: colors.blue,
  },
  demoLabel: {
    color: colors.textMuted,
    fontSize: 9,
    fontWeight: '800',
    letterSpacing: 1,
  },
  hero: {
    marginTop: 44,
    marginBottom: 27,
  },
  eyebrow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 9,
    marginBottom: 16,
  },
  eyebrowLine: {
    width: 22,
    height: 2,
    borderRadius: 1,
    backgroundColor: colors.blue,
  },
  eyebrowText: {
    color: colors.blue,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 1.25,
  },
  title: {
    maxWidth: 440,
    color: colors.text,
    fontSize: 38,
    lineHeight: 44,
    fontWeight: '700',
    letterSpacing: -1.2,
  },
  description: {
    maxWidth: 450,
    marginTop: 15,
    color: colors.textMuted,
    fontSize: 15,
    lineHeight: 23,
  },
  scanCard: {
    overflow: 'hidden',
    padding: 20,
    borderRadius: 22,
    borderWidth: 1,
    borderColor: '#255078',
    backgroundColor: colors.surface,
  },
  cardGlow: {
    position: 'absolute',
    width: 180,
    height: 180,
    top: -105,
    right: -80,
    borderRadius: 90,
    backgroundColor: '#153A5C',
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  cardIcon: {
    width: 48,
    height: 48,
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 15,
    backgroundColor: colors.blue,
  },
  cardBadge: {
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderWidth: 1,
    borderColor: '#315A7D',
    borderRadius: 12,
    backgroundColor: '#11263A',
  },
  cardBadgeText: {
    color: colors.accent,
    fontSize: 9,
    fontWeight: '800',
    letterSpacing: 1.05,
  },
  cardTitle: {
    marginTop: 19,
    color: colors.text,
    fontSize: 20,
    lineHeight: 26,
    fontWeight: '700',
  },
  cardDescription: {
    marginTop: 7,
    color: colors.textMuted,
    fontSize: 13,
    lineHeight: 20,
  },
  scanButton: {
    minHeight: 56,
    marginTop: 21,
    paddingHorizontal: 17,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 12,
    borderRadius: 15,
    backgroundColor: colors.blue,
  },
  scanButtonPressed: {
    opacity: 0.82,
    transform: [{ scale: 0.99 }],
  },
  scanButtonText: {
    flex: 1,
    color: colors.background,
    fontSize: 15,
    fontWeight: '800',
    letterSpacing: 0.1,
  },
  scanButtonArrow: {
    color: colors.background,
    fontSize: 21,
    lineHeight: 24,
    fontWeight: '700',
  },
  disclaimer: {
    marginTop: 12,
    color: colors.textSubtle,
    fontSize: 11,
    lineHeight: 16,
    textAlign: 'center',
  },
  features: {
    marginTop: 27,
    paddingHorizontal: 2,
  },
  featureRow: {
    minHeight: 67,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 13,
  },
  featureNumber: {
    width: 29,
    color: colors.blue,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 0.4,
  },
  featureCopy: {
    flex: 1,
  },
  featureTitle: {
    color: colors.text,
    fontSize: 13,
    fontWeight: '700',
  },
  featureDescription: {
    marginTop: 4,
    color: colors.textSubtle,
    fontSize: 11,
    lineHeight: 16,
  },
  featureDivider: {
    height: 1,
    marginLeft: 42,
    backgroundColor: colors.border,
  },
  featureArrow: {
    width: 25,
    height: 25,
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 13,
    backgroundColor: colors.surfaceRaised,
  },
  featureArrowText: {
    color: colors.textSubtle,
    fontSize: 13,
    fontWeight: '700',
  },
  footer: {
    marginTop: 30,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  footerRule: {
    flex: 1,
    height: 1,
    backgroundColor: colors.border,
  },
  footerText: {
    color: colors.textSubtle,
    fontSize: 8,
    fontWeight: '700',
    letterSpacing: 1.1,
  },
});
