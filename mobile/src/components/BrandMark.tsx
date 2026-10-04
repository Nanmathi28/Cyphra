import { StyleSheet, View } from 'react-native';

import { colors } from '../theme/colors';

const QR_MARK = [
  '1110111',
  '1010101',
  '1110111',
  '0001000',
  '1110111',
  '1010101',
  '1110111',
];

export function BrandMark() {
  return (
    <View accessible={false} style={styles.frame}>
      <View style={styles.grid}>
        {QR_MARK.flatMap((row, rowIndex) =>
          [...row].map((cell, columnIndex) => (
            <View
              key={`${rowIndex}-${columnIndex}`}
              style={[styles.module, cell === '0' && styles.moduleEmpty]}
            />
          )),
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  frame: {
    width: 48,
    height: 48,
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 15,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.blueTint,
  },
  grid: {
    width: 31,
    height: 31,
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 2,
  },
  module: {
    width: 3,
    height: 3,
    borderRadius: 1,
    backgroundColor: colors.accent,
  },
  moduleEmpty: {
    backgroundColor: 'transparent',
  },
});
