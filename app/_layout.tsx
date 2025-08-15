import * as AppleAuthentication from 'expo-apple-authentication';
import * as AuthSession from 'expo-auth-session';
import * as Google from 'expo-auth-session/providers/google';
import Constants from 'expo-constants';
import * as WebBrowser from 'expo-web-browser';
import React from 'react';
import { Alert, KeyboardAvoidingView, Platform, StatusBar } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { WebView } from 'react-native-webview';

WebBrowser.maybeCompleteAuthSession();

export default function RootLayout() {
  console.log('🔥 RootLayout 렌더링됨!');
  // 환경변수 미설정 시 Render 백엔드로 폴백
  const apiBaseUrl = (process.env.EXPO_PUBLIC_API_BASE_URL as string) || 'https://reconnect-backend.onrender.com';
  const apiPrefix = (process.env.EXPO_PUBLIC_API_PREFIX as string) || '/api';
  const userAgent = Platform.select({
    ios: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    android: 'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    default: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  });

  const webViewRef = React.useRef<WebView>(null);
  const isAppleLoginInProgress = React.useRef(false);

  const isExpoGo = Constants.appOwnership === 'expo';
  console.log('🟢 Google OAuth 설정 - isExpoGo:', isExpoGo);

  // 네이티브용 Google redirectUri (Google 권장 스킴)
  // 환경변수에 전체 ID("...apps.googleusercontent.com")가 들어올 수 있어, 도메인 접미사를 제거해 구성합니다.
  const buildNativeGoogleRedirectUri = (rawClientId?: string) => {
    if (!rawClientId) return undefined;
    const baseId = rawClientId.replace(/\.apps\.googleusercontent\.com$/i, '');
    return `com.googleusercontent.apps.${baseId}:/oauth2redirect`;
  };

  const nativeGoogleRedirectUri = !isExpoGo
    ? (Platform.OS === 'android'
        ? buildNativeGoogleRedirectUri(process.env.EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID as string | undefined)
        : buildNativeGoogleRedirectUri(process.env.EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID as string | undefined))
    : undefined;
  console.log('🟢 nativeGoogleRedirectUri =', nativeGoogleRedirectUri);

  // Google OAuth 요청 훅 (네이티브에서는 webClientId 전달하지 않음)
  const [googleRequest, googleResponse, promptGoogleAsync] = Google.useAuthRequest({
    iosClientId: process.env.EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID as string | undefined,
    androidClientId: process.env.EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID as string | undefined,
    webClientId: isExpoGo ? (process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID as string | undefined) : undefined,
    redirectUri: nativeGoogleRedirectUri,
    scopes: ['openid', 'profile', 'email'],
    responseType: 'code',
    extraParams: { access_type: 'offline', prompt: 'consent' },
  });

  React.useEffect(() => {
    if (isExpoGo) {
      if (!process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID) {
        console.log('🟢 경고: EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID가 설정되지 않았습니다. Google Cloud Console에서 Web Client ID를 발급받아 환경변수로 설정하세요.');
      }
    } else {
      if (Platform.OS === 'ios' && !process.env.EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID) {
        console.log('🟢 경고: iOS 네이티브용 EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID가 설정되지 않았습니다.');
      }
      if (Platform.OS === 'android' && !process.env.EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID) {
        console.log('🟢 경고: Android 네이티브용 EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID가 설정되지 않았습니다.');
      }
    }
  }, [isExpoGo]);

  // Apple 로그인
  const handleAppleLogin = async () => {
    console.log('🍏 handleAppleLogin 호출됨');
    // iOS에서만 동작하도록 가드 (안드로이드는 무시)
    if (Platform.OS !== 'ios') {
      console.log('🍏 Apple 로그인 요청 무시: 플랫폼이 iOS가 아닙니다 ->', Platform.OS);
      return;
    }
    if (isAppleLoginInProgress.current) return;
    isAppleLoginInProgress.current = true;
    try {
      const isAvailable = await AppleAuthentication.isAvailableAsync();
      console.log('🍏 AppleAuthentication 사용 가능:', isAvailable);
      if (!isAvailable) {
        Alert.alert('Apple 로그인 오류', 'Apple 로그인이 사용할 수 없습니다.');
        return;
      }
      const credential = await AppleAuthentication.signInAsync({
        requestedScopes: [
          AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
          AppleAuthentication.AppleAuthenticationScope.EMAIL,
        ],
      });
      console.log('🍏 Apple 로그인 credential:', credential);
      if (webViewRef.current) {
        // 웹뷰 쪽에서 사용할 수 있도록 자격정보 노출
        webViewRef.current.injectJavaScript(`window.__APPLE_CREDENTIAL__=${JSON.stringify(credential)}; true;`);
        webViewRef.current.postMessage(JSON.stringify({
          type: 'apple-login-success',
          credential,
        }));
        console.log('🍏 WebView로 apple-login-success 메시지 전송');
      }
    } catch (error: any) {
      console.log('🍏 Apple 로그인 에러:', error);
      if (error.code !== 'ERR_CANCELED') {
        Alert.alert('Apple 로그인 오류', 'Apple 로그인 중 오류가 발생했습니다.');
      }
    } finally {
      isAppleLoginInProgress.current = false;
    }
  };

  // Google 로그인 (Expo Go 개발은 프록시 + Web Client, 배포 네이티브는 iOS/Android 클라이언트)
  const handleGoogleLogin = async () => {
    console.log('🟢 handleGoogleLogin 호출됨');
    try {
      if (isExpoGo) {
        const clientId = process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID as string | undefined;
        if (!clientId) {
          Alert.alert('Google 로그인 오류', 'EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID가 설정되지 않았습니다.');
          return;
        }
        // makeRedirectUri가 환경에 따라 exp://를 반환하는 문제가 있어, 프록시 URI를 고정 문자열로 사용합니다.
        const redirectUri = 'https://auth.expo.dev/@kwcc/reconnect';
        console.log('🟢 [Expo Go] 고정 redirectUri(https) =', redirectUri);
        const request = new AuthSession.AuthRequest({
          clientId,
          scopes: ['openid', 'profile', 'email'],
          redirectUri,
          responseType: AuthSession.ResponseType.Code,
          extraParams: { access_type: 'offline', prompt: 'consent' },
        });
        const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
        const result = await request.promptAsync({ authorizationEndpoint: authUrl }, { useProxy: true } as any);
        console.log('🟢 Google 로그인 result (Expo Go):', result);
        if (result.type === 'success' && webViewRef.current) {
          webViewRef.current.postMessage(JSON.stringify({
            type: 'google-login-success',
            credential: {
              authCode: result.params.code,
              state: result.params.state,
              scope: result.params.scope,
            },
          }));
        }
        if (result.type !== 'success') {
          console.log('🟢 Google 로그인 종료 상태:', result.type);
          if (webViewRef.current) {
            webViewRef.current.postMessage(JSON.stringify({ type: 'debug', message: '[google] result.type=' + result.type }));
          }
        }
        return;
      }

      // 네이티브(Android/iOS)에서는 명시적으로 올바른 redirectUri 사용
      const platformClientId = Platform.OS === 'android'
        ? (process.env.EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID as string | undefined)
        : (process.env.EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID as string | undefined);
      
      if (!platformClientId) {
        Alert.alert('Google 로그인 오류', `플랫폼 클라이언트 ID가 설정되지 않았습니다. (${Platform.OS})`);
        return;
      }

      // 네이티브에서는 기본 useAuthRequest 훅 사용 (Expo가 자동으로 올바른 redirectUri 생성)
      console.log('🟢 네이티브 Google 로그인 - 기본 훅 사용');
      const debugClientId = platformClientId?.slice(0, 12) + '…';
      const debugRedirect = googleRequest?.redirectUri || nativeGoogleRedirectUri;
      Alert.alert('🟢 네이티브 인증 시작', `clientId=${debugClientId}\nredirectUri=${debugRedirect}`);
      const result = await promptGoogleAsync();
      console.log('🟢 Google 로그인 result:', result);
      if (result.type === 'success' && webViewRef.current) {
        webViewRef.current.postMessage(JSON.stringify({
          type: 'google-login-success',
          credential: {
            authCode: result.params.code,
            state: result.params.state,
            scope: result.params.scope,
          },
        }));
        console.log('🟢 WebView로 google-login-success 메시지 전송:', {
          authCode: result.params.code,
          state: result.params.state,
          scope: result.params.scope,
        });
      }
    } catch (error: any) {
      console.log('🟢 Google 로그인 에러:', error);
      Alert.alert('Google 로그인 오류', 'Google 로그인 중 오류가 발생했습니다.');
    }
  };

  // WebView에 주입할 JS (버튼 클릭 감지)
  const injectedJavaScript = `
    document.addEventListener('click', function(e) {
      const t = e.target;
      // 사용자 직접 클릭이 아닌 프로그램적 클릭은 무시
      if (e && e.isTrusted === false) { return true; }
      if (t && (t.textContent?.includes('Apple') || t.className?.includes('apple') || t.id?.includes('apple'))) {
        window.ReactNativeWebView?.postMessage(JSON.stringify({ type: 'request-apple-login' }));
        e.preventDefault(); e.stopPropagation();
        return false;
      }
      if (t && (t.textContent?.includes('Google') || t.className?.includes('google') || t.id?.includes('google'))) {
        window.ReactNativeWebView?.postMessage(JSON.stringify({ type: 'request-google-login' }));
        e.preventDefault(); e.stopPropagation();
        return false;
      }
    }, true);
    // 네트워크 패치가 혹시 선주입에서 실패한 경우를 대비한 지연 주입
    (function(){
      try {
        var RNW = window.ReactNativeWebView;
        function sendDebug(message) { try { RNW && RNW.postMessage(JSON.stringify({ type: 'debug', message: String(message) })); } catch (_) {} }
        // 설정 재주입
        if (!window.__API_BASE__) window.__API_BASE__ = ${JSON.stringify(apiBaseUrl)};
        if (!window.__API_PREFIX__) window.__API_PREFIX__ = ${JSON.stringify(apiPrefix)};
        if (!window._originalFetch && window.fetch) {
          window._originalFetch = window.fetch.bind(window);
          window.fetch = function(input, init) {
            var originalUrl = (typeof input === 'string') ? input : (input && input.url);
            var method = (init && init.method) || (input && input.method) || 'GET';
            var base = window.__API_BASE__ || '';
            var prefix = window.__API_PREFIX__ || '';
            var newInput = input;
            var rewrittenUrl = originalUrl;
            try {
              var makeAbs = function(u){ try { return new URL(u, window.location.origin); } catch(_) { return null; } };
              if (typeof originalUrl === 'string' && base) {
                var abs = makeAbs(originalUrl);
                if (abs && (abs.origin === window.location.origin || originalUrl.indexOf('/') === 0)) {
                  var pfx = prefix ? ('/' + String(prefix).replace(/^\\/+|\\/+$/g, '')) : '';
                  var pathWithQuery = abs.pathname + (abs.search||'') + (abs.hash||'');
                  rewrittenUrl = base.replace(/\\/$/, '') + pfx + pathWithQuery;
                  newInput = rewrittenUrl;
                }
              }
            } catch (_) {}
            if (rewrittenUrl !== originalUrl) sendDebug('[rewrite:fetch] ' + originalUrl + ' -> ' + rewrittenUrl);
            sendDebug('[fetch:start] ' + method + ' ' + (rewrittenUrl || originalUrl));
            return window._originalFetch(newInput, init)
              .then(function(res){
                try { sendDebug('[fetch:response] ' + res.status + ' ' + res.statusText + ' ' + (rewrittenUrl || originalUrl)); } catch(_) {}
                return res;
              })
              .catch(function(err){
                var em = (err && err.message) ? err.message : String(err);
                sendDebug('[fetch:error] ' + em + ' ' + (rewrittenUrl || originalUrl));
                throw err;
              });
          };
          sendDebug('[late-inject] fetch patched');
        }
      } catch (e) {}
    })();
    true;
  `;

  // 네트워크/에러 디버깅 주입 (문서 로드 이전)
  const injectedJavaScriptBeforeContentLoaded = `
    (function(){
      try {
        var RNW = window.ReactNativeWebView;
        function sendDebug(message) {
          try { RNW && RNW.postMessage(JSON.stringify({ type: 'debug', message: String(message) })); } catch (_) {}
        }

        // API Base 설정
        window.__API_BASE__ = ${JSON.stringify(apiBaseUrl)};
        window.__API_PREFIX__ = ${JSON.stringify(apiPrefix)};
        sendDebug('[config] API_BASE=' + (window.__API_BASE__ || '(empty)'));
        sendDebug('[config] API_PREFIX=' + (window.__API_PREFIX__ || '(empty)'));

        // Global error handlers
        window.addEventListener('error', function(e){
          var msg = (e && e.message) ? e.message : e.toString();
          sendDebug('[window.error] ' + msg);
        });
        window.addEventListener('unhandledrejection', function(e){
          var reason = e && e.reason ? (e.reason.message || e.reason) : 'unknown';
          sendDebug('[unhandledrejection] ' + reason);
        });

        // Patch fetch
        if (!window._originalFetch && window.fetch) {
          window._originalFetch = window.fetch.bind(window);
          window.fetch = function(input, init) {
            var originalUrl = (typeof input === 'string') ? input : (input && input.url);
            var method = (init && init.method) || (input && input.method) || 'GET';
            var base = window.__API_BASE__ || '';
            var prefix = window.__API_PREFIX__ || '';
            var newInput = input;
            var rewrittenUrl = originalUrl;
            var bodyPreview = '';
            try {
              // 요청 바디 프리뷰 (문자열/JSON 일부만 출력)
              if (init && init.body) {
                try {
                  if (typeof init.body === 'string') bodyPreview = init.body.slice(0, 500);
                  else bodyPreview = JSON.stringify(init.body).slice(0, 500);
                } catch(_) {}
              }
              var makeAbs = function(u){ try { return new URL(u, window.location.origin); } catch(_) { return null; } };
              if (typeof originalUrl === 'string' && base) {
                var abs = makeAbs(originalUrl);
                if (abs && (abs.origin === window.location.origin || originalUrl.indexOf('/') === 0)) {
                  // 애플 로그인 API 자동 보정 (메서드/바디/헤더)
                  if (abs.pathname.indexOf('/auth/apple/login') === 0) {
                    init = init || {};
                    method = init.method = (init.method || 'POST');
                    try {
                      var headersObj = {};
                      if (init.headers) {
                        if (init.headers.forEach) { init.headers.forEach(function(v,k){ headersObj[k] = v; }); }
                        else if (Array.isArray(init.headers)) { init.headers.forEach(function(p){ headersObj[p[0]] = p[1]; }); }
                        else if (typeof init.headers === 'object') { headersObj = Object.assign({}, init.headers); }
                      }
                      headersObj['content-type'] = headersObj['content-type'] || headersObj['Content-Type'] || 'application/json';
                      init.headers = headersObj;
                    } catch(_) {}
                    if (!init.body && window.__APPLE_CREDENTIAL__) {
                      var c = window.__APPLE_CREDENTIAL__;
                      var payload = { identityToken: c.identityToken, authorizationCode: c.authorizationCode, user: c.user };
                      init.body = JSON.stringify(payload);
                      try { sendDebug('[fetch:autofill-body] /auth/apple/login ' + JSON.stringify(payload).slice(0,300)); } catch(_) {}
                    }
                    if (!init.credentials) { init.credentials = 'include'; }
                  }
                  var pfx = prefix ? ('/' + String(prefix).replace(/^\/+|\/+$/g, '')) : '';
                  var pathWithQuery = abs.pathname + (abs.search||'') + (abs.hash||'');
                  rewrittenUrl = base.replace(/\/$/, '') + pfx + pathWithQuery;
                  newInput = rewrittenUrl;
                }
              } else if (input && typeof input === 'object' && input.url && base) {
                // Request 객체인 경우 재구성
                var reqInit = {
                  method: input.method,
                  headers: input.headers,
                  body: input.body,
                  mode: input.mode,
                  credentials: input.credentials,
                  cache: input.cache,
                  redirect: input.redirect,
                  referrer: input.referrer,
                  referrerPolicy: input.referrerPolicy,
                  integrity: input.integrity,
                  keepalive: input.keepalive,
                  signal: input.signal
                };
                var abs2 = makeAbs(input.url);
                if (abs2 && (abs2.origin === window.location.origin || String(input.url).indexOf('/') === 0)) {
                  if (abs2.pathname.indexOf('/auth/apple/login') === 0) {
                    reqInit.method = reqInit.method || 'POST';
                    try {
                      var headersObj2 = {};
                      if (reqInit.headers) {
                        if (reqInit.headers.forEach) { reqInit.headers.forEach(function(v,k){ headersObj2[k] = v; }); }
                        else if (Array.isArray(reqInit.headers)) { reqInit.headers.forEach(function(p){ headersObj2[p[0]] = p[1]; }); }
                        else if (typeof reqInit.headers === 'object') { headersObj2 = Object.assign({}, reqInit.headers); }
                      }
                      headersObj2['content-type'] = headersObj2['content-type'] || headersObj2['Content-Type'] || 'application/json';
                      reqInit.headers = headersObj2;
                    } catch(_) {}
                    if (!reqInit.body && window.__APPLE_CREDENTIAL__) {
                      var c2 = window.__APPLE_CREDENTIAL__;
                      var payload2 = { identityToken: c2.identityToken, authorizationCode: c2.authorizationCode, user: c2.user };
                      reqInit.body = JSON.stringify(payload2);
                      try { sendDebug('[fetch:autofill-body] /auth/apple/login ' + JSON.stringify(payload2).slice(0,300)); } catch(_) {}
                    }
                    if (!reqInit.credentials) { reqInit.credentials = 'include'; }
                  }
                  var pfx2 = prefix ? ('/' + String(prefix).replace(/^\/+|\/+$/g, '')) : '';
                  var pathWithQuery2 = abs2.pathname + (abs2.search||'') + (abs2.hash||'');
                  rewrittenUrl = base.replace(/\/$/, '') + pfx2 + pathWithQuery2;
                  newInput = new Request(rewrittenUrl, reqInit);
                }
              }
            } catch (_) {}
            if (rewrittenUrl !== originalUrl) {
              sendDebug('[rewrite:fetch] ' + originalUrl + ' -> ' + rewrittenUrl);
            }
            if (bodyPreview && (String(originalUrl).includes('/auth/apple/login') || String(rewrittenUrl).includes('/auth/apple/login'))) {
              sendDebug('[fetch:request-body] ' + bodyPreview);
            }
            sendDebug('[fetch:start] ' + method + ' ' + (rewrittenUrl || originalUrl));
            return window._originalFetch(newInput, init)
              .then(function(res) {
                try { sendDebug('[fetch:response] ' + res.status + ' ' + res.statusText + ' ' + (rewrittenUrl || originalUrl)); } catch (_) {}
                if (!res.ok || String(rewrittenUrl||originalUrl).includes('/auth/apple/login')) {
                  try {
                    res.clone().text().then(function(body){
                      if (body) { sendDebug('[fetch:response-body] ' + String(body).slice(0, 500)); }
                    }).catch(function(){});
                  } catch (_) {}
                }
                return res;
              })
              .catch(function(err) {
                var em = (err && err.message) ? err.message : String(err);
                sendDebug('[fetch:error] ' + em + ' ' + (rewrittenUrl || originalUrl));
                throw err;
              });
          };
        }

        // Patch XMLHttpRequest
        if (window.XMLHttpRequest) {
          (function(){
            var origOpen = XMLHttpRequest.prototype.open;
            var origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
              var base = window.__API_BASE__ || '';
              var prefix = window.__API_PREFIX__ || '';
              var originalUrl = url;
              var makeAbs = function(u){ try { return new URL(u, window.location.origin); } catch(_) { return null; } };
              if (typeof url === 'string' && base) {
                var abs = makeAbs(url);
                if (abs && (abs.origin === window.location.origin || url.indexOf('/') === 0)) {
                  var pfx = prefix ? ('/' + String(prefix).replace(/^\/+|\/+$/g, '')) : '';
                  var pathWithQuery = abs.pathname + (abs.search||'') + (abs.hash||'');
                  url = base.replace(/\/$/, '') + pfx + pathWithQuery;
                  try { sendDebug('[rewrite:xhr] ' + originalUrl + ' -> ' + url); } catch (_) {}
                }
              }
              this._method = method; this._url = url;
              return origOpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
              var xhr = this;
              try {
                xhr.addEventListener('load', function(){
                  sendDebug('[xhr:load] ' + (xhr._method||'?') + ' ' + (xhr._url||'?') + ' ' + xhr.status);
                });
                xhr.addEventListener('error', function(){
                  sendDebug('[xhr:error] ' + (xhr._method||'?') + ' ' + (xhr._url||'?'));
                });
                xhr.addEventListener('timeout', function(){
                  sendDebug('[xhr:timeout] ' + (xhr._method||'?') + ' ' + (xhr._url||'?'));
                });
              } catch (_) {}
              return origSend.apply(xhr, arguments);
            };
          })();
        }

        // Patch navigator.sendBeacon
        if (navigator && navigator.sendBeacon) {
          try {
            var _origBeacon = navigator.sendBeacon.bind(navigator);
            navigator.sendBeacon = function(url, data) {
              sendDebug('[beacon] ' + url + ' size=' + (data && data.size ? data.size : (data ? (data.length||'?') : 0)));
              return _origBeacon(url, data);
            };
          } catch (_) {}
        }

      } catch (e) {
        try { window.ReactNativeWebView && window.ReactNativeWebView.postMessage(JSON.stringify({ type: 'debug', message: '[inject-error] ' + (e && e.message ? e.message : String(e)) })); } catch (_) {}
      }
    })();
    true;
  `;

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#000' }} edges={['top']}>
      <StatusBar barStyle="light-content" backgroundColor="#000" />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <WebView
          ref={webViewRef}
          source={{ uri: 'https://reconnect-ivory.vercel.app/' }}
          style={{ flex: 1 }}
          userAgent={userAgent}
          javaScriptEnabled
          domStorageEnabled
          startInLoadingState
          allowsInlineMediaPlayback
          mediaPlaybackRequiresUserAction={false}
          keyboardDisplayRequiresUserAction={false}
          automaticallyAdjustContentInsets={false}
          scrollEnabled
          bounces
          allowsLinkPreview
          sharedCookiesEnabled
          injectedJavaScriptBeforeContentLoaded={injectedJavaScriptBeforeContentLoaded}
          injectedJavaScript={injectedJavaScript}
          onMessage={event => {
            console.log('💬 WebView onMessage 수신:', event.nativeEvent.data);
            try {
              const data = JSON.parse(event.nativeEvent.data);
              if (data.type === 'debug') {
                console.log('[웹앱 디버그]', data.message);
              }
              if (data.type === 'request-apple-login') {
                if (Platform.OS === 'ios') handleAppleLogin();
                else console.log('🍏 안드로이드에서 수신된 애플 로그인 요청 무시');
              }
              else if (data.type === 'request-google-login') handleGoogleLogin();
            } catch (e) {
              console.log('💬 WebView onMessage 파싱 에러:', e);
            }
          }}
          // 딥링크만 처리: OAuth 완료 후 com.reconnect.kwcc:// 로 돌아올 때만 잡아준다
          onShouldStartLoadWithRequest={req => {
            try {
              const url = req.url || '';
              console.log('🔍 WebView navigation request:', url);
              if (/^com\.reconnect\.kwcc:\/\//.test(url)) {
                console.log('🔗 딥링크 감지 → 네이티브 처리:', url);
                return false;
              }
            } catch (error) {
              console.log('🔍 onShouldStartLoadWithRequest 에러:', error);
            }
            return true;
          }}
          onError={e => {
            console.log('🌐 WebView onError:', e.nativeEvent);
            Alert.alert('오류', '페이지를 불러오는 중 오류가 발생했습니다.');
          }}
          onHttpError={e => {
            console.log('🌐 WebView onHttpError:', e.nativeEvent);
          }}
        />
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}
