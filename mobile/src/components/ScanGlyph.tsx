import { StyleSheet, View } from 'react-native';

import { colors } from '../theme/colors';

export function ScanGlyph({ color = colors.background }: { color?: string }) {
  return (
    <View accessible={false} style={styles.frame}>
      <View style={[styles.corner, styles.topLeft, { borderColor: color }]} />
      <View style={[styles.corner, styles.topRight, { borderColor: color }]} />
      <View style={[styles.corner, styles.bottomLeft, { borderColor: color }]} />
      <View style={[styles.corner, styles.bottomRight, { borderColor: color }]} />
      <View style={[styles.centerDot, { backgroundColor: color }]} />
    </View>
  );
}

const styles = StyleSheet.create({
  frame: {
    width: 28,
    height: 28,
    position: 'relative',
  },
  corner: {
    position: 'absolute',
    width: 9,
    height: 9,
  },
  topLeft: {
    top: 0,
    left: 0,
    borderTopWidth: 2,
    borderLeftWidth: 2,
    borderTopLeftRadius: 3,
  },
  topRight: {
    top: 0,
    right: 0,
    borderTopWidth: 2,
    borderRightWidth: 2,
    borderTopRightRadius: 3,
  },
  bottomLeft: {
    bottom: 0,
    left: 0,
    borderBottomWidth: 2,
    borderLeftWidth: 2,
    borderBottomLeftRadius: 3,
  },
  bottomRight: {
    bottom: 0,
    right: 0,
    borderBottomWidth: 2,
    borderRightWidth: 2,
    borderBottomRightRadius: 3,
  },
  centerDot: {
    position: 'absolute',
    width: 5,
    height: 5,
    top: 11.5,
    left: 11.5,
    borderRadius: 3,
  },
});
