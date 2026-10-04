# NIVARA mobile foundation

This is the initial Expo / React Native Android-compatible app foundation for NIVARA. It includes a home screen and navigation to a clearly marked scanner placeholder. Camera scanning and backend requests are not implemented in this step.

## Run the development server

```powershell
npm install
npm start
```

Open the project with an Expo Go version compatible with Expo SDK 57, or build/run it on an Android development machine with Android Studio and the Android SDK installed. `npm run android` starts the Android target through Expo; it does not install Android tooling.

## Backend connection

The app defaults to `http://10.0.2.2:8000`, which reaches the development computer from the standard Android emulator. Override the URL with Expo's public environment variable before starting the dev server:

```powershell
$env:EXPO_PUBLIC_NIVARA_API_BASE_URL = "http://10.0.2.2:8000"
npm start
```

For a physical phone, set the value to the development computer's reachable LAN address, for example `http://192.168.1.20:8000`, and ensure the phone and computer share a network and the computer firewall allows the backend port. The backend's default host is `0.0.0.0`. Restart Expo after changing the variable so it is included in the app bundle. Do not use `localhost` on a physical phone to reach the computer.

## Current demo scope

- Home screen describes the QR destination safety goal.
- The **Scan QR Code** button opens a camera based QR scanner.
- Only valid HTTP and HTTPS URL content is submitted to `POST /api/v1/analyze/url`.
- Scanned URLs are never opened automatically; risk decisions and evidence are displayed from the backend response.
- Camera hardware and live backend connectivity still need to be verified on the intended Android device/network.
