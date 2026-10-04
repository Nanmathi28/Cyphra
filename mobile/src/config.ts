// Android emulator host alias. Override with EXPO_PUBLIC_NIVARA_API_BASE_URL
// when running on a physical phone or another development target.
export const NIVARA_API_BASE_URL = (
  process.env.EXPO_PUBLIC_NIVARA_API_BASE_URL || 'http://10.0.2.2:8000'
).replace(/\/+$/, '');

export const NIVARA_API_TIMEOUT_MS = 20_000;
