import React from 'react';
import { KeyboardAvoidingView, Platform, StatusBar } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { WebView } from 'react-native-webview';

export default function RootLayout() {
  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#000000' }} edges={['top']}>
      <StatusBar barStyle="light-content" backgroundColor="#000000" />
      <KeyboardAvoidingView 
        style={{ flex: 1 }}
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        keyboardVerticalOffset={Platform.OS === 'ios' ? 0 : 0}
      >
        <WebView
          source={{ uri: 'https://reconnect-ivory.vercel.app/' }}
          style={{ flex: 1 }}
          keyboardDisplayRequiresUserAction={false}
          automaticallyAdjustContentInsets={false}
          scrollEnabled={true}
          bounces={true}
        />
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}
