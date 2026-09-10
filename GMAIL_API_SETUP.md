# PhishTrace - Gmail API Integration Guide

To allow PhishTrace to pull raw MIME contents securely (and without permanently storing the emails), we use the official **Gmail API** combined with Chrome Extension Identity OAuth (`chrome.identity.getAuthToken`). 

Because OAuth requires an official Google Cloud Project, follow these steps to configure your environment.

## Step 1: Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project (e.g., `phishtrace-gmail`).
3. Once the project is created, select it from the top dropdown.

## Step 2: Enable the Gmail API

1. In the sidebar, navigate to **APIs & Services > Library**.
2. Search for **Gmail API**.
3. Click **Enable**.

## Step 3: Configure OAuth Consent Screen

1. Go to **APIs & Services > OAuth consent screen**.
2. Choose **External** (unless you are in a Google Workspace organization, then choose **Internal**).
3. Fill in the required application details (App Name: PhishTrace, User Support Email, Developer Contact Info).
4. Proceed to **Scopes**. Click **Add or Remove Scopes**.
5. Manually add the scope: `https://www.googleapis.com/auth/gmail.readonly` (This gives us read-only access to email metadata and raw body, strictly necessary for forensics).
6. Proceed to **Test Users**. Add the email addresses that will be testing this extension (e.g. `sharathkumarshetty7795@gmail.com`).
7. Save and Continue.

## Step 4: Create OAuth 2.0 Credentials (Chrome Extension)

1. Go to **APIs & Services > Credentials**.
2. Click **Create Credentials** -> **OAuth client ID**.
3. Application Type: **Chrome app**.
4. In the **Application ID** field, paste the ID of your unpacked Chrome extension.
   - *How to get this ID:* Go to `chrome://extensions/`, ensure Developer Mode is on, and load the `extension-final` folder. Note the generated ID.
5. Click **Create**.
6. Note the generated **Client ID**.

## Step 5: Update the Extension Manifest

1. Open `extension-final/manifest.json`.
2. Locate the `oauth2` block.
3. Replace the `client_id` string with the Client ID you generated in Step 4.

```json
  "oauth2": {
    "client_id": "YOUR_CLIENT_ID_HERE.apps.googleusercontent.com",
    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
  }
```

4. Reload the extension in `chrome://extensions/`.

## Privacy & Security Note
* The OAuth token is fetched dynamically in the service worker.
* The `GET_RAW_EMAIL_API` handler intercepts the Gmail DOM's `messageId` and fetches the raw MIME locally.
* The raw MIME is streamed to the backend `/detect` route.
* **The raw email is immediately discarded after structural forensics are calculated.** We only persist structured security markers (SPF, DKIM, IP Chain) in SQLite. No user data is retained.
