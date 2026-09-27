# Pinaka — TaaSen field officer app (Android + iPhone)

The store version of Pinaka. It is the same app as **taasenclaims.com/pinaka**, packaged
with Capacitor 8 so it can go on Google Play and the App Store. It rings through Firebase,
so the alarm sounds even when the app is closed.

| | |
|---|---|
| App name | Pinaka |
| Android package / iOS bundle ID | `com.taasenclaims.pinaka` |
| Version | 2.0.0 (build 3) |
| Talks to | `https://taasenclaims.com/api/app/*` (portal v34.9 or later) |
| Privacy policy URL | `https://taasenclaims.com/pinaka/privacy` |

## Folders

- `www/index.html`: the app. It is a copy of `pinaka.html` from the skd-portal repo. Change it there, copy it here, then run `npx cap sync`.
- `android/`: the Android Studio project.
- `ios/`: the Xcode project.
- `assets/`: the source icons and splash. `npm run icons` regenerates every size.
- `android/app/src/main/res/raw/pinaka_alarm.wav` and `ios/App/App/pinaka_alarm.wav`: the alarm sound (original, ~8 s).
- `.github/workflows/android.yml`: GitHub builds the APK and AAB for you.

---

## Step 1 · Firebase (one time, ~10 minutes)

1. Go to https://console.firebase.google.com → **Add project** → name it `Pinaka`. Analytics is not needed.
2. **Add app → Android.** Package name `com.taasenclaims.pinaka`, then download **google-services.json**.
3. **Add app → iOS.** Bundle ID `com.taasenclaims.pinaka`, then download **GoogleService-Info.plist**.
4. **Project settings → Cloud Messaging → Apple app configuration → Upload APNs Authentication Key.**
   Get the key from developer.apple.com → Certificates, IDs & Profiles → Keys → **+** → tick *Apple Push Notifications service (APNs)*. Download the `.p8` and note the Key ID and your Team ID.
5. **Project settings → Service accounts → Generate new private key.** This downloads a JSON file. Copy three values from it into Cloudflare → Workers → **skd-portal** → Settings → Variables and Secrets, each as a **Secret**:
   - `FCM_PROJECT_ID` ← `project_id`
   - `FCM_CLIENT_EMAIL` ← `client_email`
   - `FCM_PRIVATE_KEY` ← `private_key` (the whole text, including the BEGIN and END lines)

The portal's **Pinaka App** page turns green once these are set.

## Step 2 · Android → Google Play

### Option A: GitHub builds it (no Android Studio needed)

1. Create a **private** repo, e.g. `sujit-dnai/pinaka-app`, and upload this whole folder.
   The `node_modules` folder is not needed; `.gitignore` skips it.
2. Make an upload keystore once, on any computer with Java:
   ```
   keytool -genkeypair -v -keystore pinaka-upload.jks -alias pinaka -keyalg RSA -keysize 2048 -validity 10000
   ```
   Keep the `.jks` file and both passwords safe. Every update must be signed with this key.
3. Go to repo → Settings → Secrets and variables → Actions → **New repository secret**, and add:
   - `GOOGLE_SERVICES_JSON`: paste the whole google-services.json
   - `ANDROID_KEYSTORE_BASE64`: the output of `base64 -i pinaka-upload.jks`
   - `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` (`pinaka`), `ANDROID_KEY_PASSWORD`
4. Open the **Actions** tab → *Android build* → **Run workflow**. When it finishes, download:
   - **pinaka-debug-apk**: install it on a phone to test straight away
   - **pinaka-release-aab**: upload this to Play

### Option B: Android Studio

Put `google-services.json` in `android/app/`, then run `npm install`, then `npx cap sync android`, then `npx cap open android`.
In Android Studio, use **Build → Generate Signed App Bundle**.

### Play Console

1. **Create app**: name Pinaka, category Business, free.
2. **Testing → Internal testing**: upload the AAB and add your officers' Gmail IDs as testers. This is the fastest way to get it onto 300 phones.
3. **Store listing**: use the texts at the end of this file and the icon `assets/icon-only.png` (resize it to 512 × 512).
4. **App content**:
   - Privacy policy: `https://taasenclaims.com/pinaka/privacy`
   - App access: *All or some functionality is restricted*. Give the reviewer a login (see "Review login" below).
   - Data safety: the app collects **Name, Phone number, User IDs** (for app functionality, not shared), a **Device ID** (the push token), **Precise location** (only while on duty), **Photos** (bills) and **Voice recordings** (Translator, kept as proof). Data is encrypted in transit. Deletion is on request.
   - Ads: none. Target audience: 18+.
5. **Full-screen notification (Android 14+)**: this app does **not** use the full-screen-intent permission. The alarm is a max-importance notification on its own alarm channel, and it repeats every 2 minutes. That avoids Play's calling/alarm-apps-only restriction.

## Step 3 · iPhone → App Store

This needs a Mac with Xcode 16 or later.

1. Put `GoogleService-Info.plist` into `ios/App/App/`. In Xcode, right-click the App folder → *Add Files* → tick the App target.
2. Run `npm install`, then `npx cap sync ios`, then `npx cap open ios`.
3. In Xcode, select **App target → Signing & Capabilities**:
   - choose your Team
   - check **Push Notifications** and **Background Modes → Remote notifications** are present (the entitlements file already asks for them)
   - add **Time Sensitive Notifications**
4. Choose **Product → Archive**, then **Distribute App → App Store Connect**.
5. In App Store Connect, create the app with bundle ID `com.taasenclaims.pinaka`, fill the listing, attach the build, and submit.
   - App Privacy: Contact Info (name, phone), Identifiers (user ID, device ID), Location (precise), Photos, Audio Data. All are used for App Functionality and none for tracking.
   - Encryption: the app uses only standard HTTPS. `ITSAppUsesNonExemptEncryption` is already set to NO.
   - Sign-in: accounts are issued by the employer, so no in-app sign-up or account deletion is needed. Say this in the review notes.

## Review login (both stores)

Reviewers need a way in. On the portal, go to **Pinaka App**, search for your own test officer (or type a name such as "Store Review" into Give access), and press **Give access**.
Put the **Employee ID** and the **6-digit code** in the review notes. The code lasts 72 hours and works once, so make it on the day you submit. Make a fresh one if the store asks again.
Mention in the notes: *"Internal app for TaaSen field officers. Access codes are issued by the employer's portal. New cases arrive as push alarms."*

## What 2.1.0 adds (versionCode 4 / iOS build 4)
- Team Chat on every case: chat icon in the Case Workspace header (count + yellow @), Chat tab with Chats and Mentions, @ tags that ring the tagged person, Reply, Voice → English, offline queue.
- Document scanner on every touch point: the box turns green when the paper is inside and steady, crop corners, Clean / B&W / Original, pages → one PDF, "What is this document?" list (Field Masters), rename / re-scan / delete later.
- Spot visit: 8 spot photos + 360° video.
- SOS button in every header → his OHS, State Coordinator, admin and boss are rung; "I am safe now"; Call 112; offline queue.
- Sign-in doors read TaaSen User / External User.
- Leave (Profile → Leave): apply any time with the reason (Translator mic); OHS → State Coordinator → manager / admin approve step by step; 2 days or more lists his cases that go back to the office once approved ("I understand" tick); cancel until decided.
- Old installed apps are stopped with "Please install the new Pinaka".
- The app needs no new permission: camera, microphone and location were already declared.

## What 2.0.0 adds — the app is Sujit's design (pinaka-des)

- **Sign in with the Employee ID** + password (set on the portal), then a daily PIN. No logout; only admin signs a phone out.
- **Punch attendance** (selfie + GPS, from 7 AM; Late after 8:30 with a reason) and the **morning plan**.
- Home (next action), My Cases (TAT chips, out-of-TAT block), Case Workspace with the Health / Motor TP / **Cashless 20 h** timers.
- **Touch points** with the camera: the photos-needed checklist and a GPS stamp burned into every photo.
- **Final Report** (Field Masters questions) → **Case Complete Report** → travel expense.
- **Today's work** (6–7:30 PM), **Fine Amount** with **Appeal**, Battery settings, GPS-off lock.
- **Permissions the stores will ask about:** Camera (selfie + touch-point photos, including the punch selfie), Location (on duty, punch, photos), Microphone (Translator), Notifications (alarm).
- Data safety adds: **Photos** (selfies and verification photos, kept by TaaSen as proof).

## What 1.1.0 adds

- **Sign-in:** TaaSen User (Employee ID or mobile + the password set on the portal) or External User (opens the portal). A one-time code from the portal still works.
- **Start duty / End duty:** location is shared only while on duty, including with the screen locked (background location plugin, with an "On duty" notification). Duty ends by itself at 9 PM.
- **Expenses:** today's purposes, limits and words, plus status chips, totals, edit/delete while Submitted, month view, expense date, From/To and touch point, Fuel km from GPS × ₹4, several bills, remarks, a duplicate check and an offline queue. Approval runs OHS → State Coordinator → Admin → Accounts Payouts on the portal.
- **Translator:** a mic beside every free-text box. The officer speaks in his language; the portal turns it into English (keys stay on the portal, never in the app).
- **Permissions the stores will ask you to explain:**
  - Location "all the time" / background, only while on duty. Play needs a **background-location declaration** and a short video of the Start duty button.
  - Camera, for bill photos.
  - Microphone, only while the officer taps the Translator mic.
  - Notifications, for the alarm.

The location plugin (`@capacitor-community/background-geolocation` 1.2.26) lists support up to Capacitor 7. This project is on Capacitor 8, so check tracking first on the test APK.

## How the alarm works

1. A manager allocates a case on taasenclaims.com, or SKD puts a case on the officer's name.
2. The portal sends a Firebase message on the channel `pinaka_alarm` with the sound `pinaka_alarm`, at max priority. On iPhone it is a time-sensitive alert with the same sound.
3. The phone rings, even when the app is closed. Tapping it opens a full-screen alarm with a 20:00 countdown, a looping sound and vibration, and **Accept / Reject**.
4. Until the officer opens it, the portal rings again every 2 minutes, up to 10 times.

The alarm channel is created the first time the officer taps **Turn on alarm**. If an officer muted it, fix it in Settings → Apps → Pinaka → Notifications → New case alarm.

## Store texts

**Short description (80 characters):** TaaSen field officer app: new-case alarm, your cases and one-tap accept.

**Full description:**
Pinaka is the work app for TaaSen Claims field officers.
• A new case rings your phone the moment it is given to you, even with the app closed.
• Accept or reject within 20 minutes, with the reason.
• See all your open cases: insured, hospital, address, your part of a shared case, and the manager.
• Call the insured or open the map in one tap.
• Use it in English, தமிழ், తెలుగు, ಕನ್ನಡ, മലയാളം, मराठी or हिंदी.
Access is given by TaaSen on the company portal. This app is for TaaSen staff only.

## Every update

1. Change `pinaka.html` in skd-portal, then run `sh scripts/copy-from-portal.sh ../skd-portal` here. It copies the file, fixes the two link paths and runs the sync.
2. Raise `versionCode` and `versionName` in `android/app/build.gradle`, and Version / Build in Xcode.
3. Run `npx cap sync`, then build and upload.
