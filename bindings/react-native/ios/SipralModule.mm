// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The TurboModule on iOS. NativeSipralSpec is what codegen writes from
// src/NativeSipral.ts; each method here reads what JavaScript handed over
// and passes it to SipralReactBridge (Bridge/, over bindings/swift), which
// settles the promise. Nothing else lives here.

#import <SipralReactNativeSpec/SipralReactNativeSpec.h>

#if __has_include(<sipral_react_native/sipral_react_native-Swift.h>)
#import <sipral_react_native/sipral_react_native-Swift.h>
#else
#import "sipral_react_native-Swift.h"
#endif

@interface SipralModule : NativeSipralSpecBase <NativeSipralSpec>
@end

// What JavaScript left out is left out here too, so that the Swift side
// sees the default rather than an empty string or a zero it did not send.
static void put(NSMutableDictionary *into, NSString *key, id _Nullable value)
{
  if (value != nil) {
    into[key] = value;
  }
}

@implementation SipralModule {
  SipralReactBridge *_bridge;
}

+ (NSString *)moduleName
{
  return @"Sipral";
}

- (instancetype)init
{
  if (self = [super init]) {
    __weak SipralModule *weakSelf = self;
    _bridge = [[SipralReactBridge alloc] initWithEmit:^(NSDictionary<NSString *, id> *event) {
      [weakSelf emitOnEvent:event];
    }];
  }
  return self;
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeSipralSpecJSI>(params);
}

- (void)invalidate
{
  [_bridge invalidate];
}

- (void)open:(JS::NativeSipral::NativeOpenOptions &)options
     resolve:(RCTPromiseResolveBlock)resolve
      reject:(RCTPromiseRejectBlock)reject
{
  NSMutableDictionary *given = [NSMutableDictionary dictionary];
  put(given, @"bindHost", options.bindHost());
  if (options.bindPort().has_value()) {
    put(given, @"bindPort", @(options.bindPort().value()));
  }
  put(given, @"userAgent", options.userAgent());
  put(given, @"codecs", options.codecs());
  put(given, @"signalling", options.signalling());
  put(given, @"signallingServer", options.signallingServer());
  put(given, @"stunServer", options.stunServer());
  if (options.manualAudio().has_value()) {
    put(given, @"manualAudio", @(options.manualAudio().value()));
  }
  put(given, @"srtp", options.srtp());
  put(given, @"srtpSuites", options.srtpSuites());
  if (options.pathMtu().has_value()) {
    put(given, @"pathMtu", @(options.pathMtu().value()));
  }
  if (options.datagramWithoutStreamBytes().has_value()) {
    put(given, @"datagramWithoutStreamBytes", @(options.datagramWithoutStreamBytes().value()));
  }
  put(given, @"pseudonymSalt", options.pseudonymSalt());
  if (options.diagnosticTrace().has_value()) {
    put(given, @"diagnosticTrace", @(options.diagnosticTrace().value()));
  }
  put(given, @"tlsPin", options.tlsPin());
  if (options.systemEchoCancellation().has_value()) {
    put(given, @"systemEchoCancellation", @(options.systemEchoCancellation().value()));
  }
  put(given, @"heldAudio", options.heldAudio());
  if (options.maxDialogs().has_value()) {
    put(given, @"maxDialogs", @(options.maxDialogs().value()));
  }
  if (options.maxServerTransactions().has_value()) {
    put(given, @"maxServerTransactions", @(options.maxServerTransactions().value()));
  }
  [_bridge open:given resolve:resolve reject:reject];
}

- (void)close:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge closeWithResolve:resolve reject:reject];
}

- (void)addAccount:(JS::NativeSipral::NativeAccountOptions &)options
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject
{
  NSMutableDictionary *given = [NSMutableDictionary dictionary];
  put(given, @"aor", options.aor());
  put(given, @"registrarAddress", options.registrarAddress());
  put(given, @"serverUri", options.serverUri());
  if (options.serverNaptr().has_value()) {
    put(given, @"serverNaptr", @(options.serverNaptr().value()));
  }
  if (options.keepaliveMs().has_value()) {
    put(given, @"keepaliveMs", @(options.keepaliveMs().value()));
  }
  put(given, @"registrar", options.registrar());
  put(given, @"contact", options.contact());
  put(given, @"displayName", options.displayName());
  put(given, @"authUser", options.authUser());
  put(given, @"authPassword", options.authPassword());
  if (options.expiresSeconds().has_value()) {
    put(given, @"expiresSeconds", @(options.expiresSeconds().value()));
  }
  put(given, @"streamProtocol", options.streamProtocol());
  put(given, @"tlsPin", options.tlsPin());
  put(given, @"realms", options.realms());
  [_bridge addAccount:given resolve:resolve reject:reject];
}

- (void)register:(NSString *)account resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge register:account resolve:resolve reject:reject];
}

- (void)unregister:(NSString *)account resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge unregister:account resolve:resolve reject:reject];
}

- (void)setAccessToken:(NSString *)account
                 token:(NSString *)token
               resolve:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject
{
  [_bridge setAccessToken:account token:token resolve:resolve reject:reject];
}

- (void)removeAccount:(NSString *)account
              resolve:(RCTPromiseResolveBlock)resolve
               reject:(RCTPromiseRejectBlock)reject
{
  [_bridge removeAccount:account resolve:resolve reject:reject];
}

- (void)placeCall:(NSString *)account
           target:(NSString *)target
          options:(JS::NativeSipral::NativeCallOptions &)options
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  NSMutableDictionary *given = [NSMutableDictionary dictionary];
  put(given, @"destination", options.destination());
  put(given, @"codecs", options.codecs());
  if (options.followRedirects().has_value()) {
    put(given, @"followRedirects", @(options.followRedirects().value()));
  }
  [_bridge placeCall:account target:target options:given resolve:resolve reject:reject];
}

- (void)answer:(NSString *)call
        options:(JS::NativeSipral::NativeAnswerOptions &)options
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject
{
  NSMutableDictionary *given = [NSMutableDictionary dictionary];
  put(given, @"codecs", options.codecs());
  [_bridge answer:call options:given resolve:resolve reject:reject];
}

- (void)reject:(NSString *)call
          code:(NSInteger)code
       resolve:(RCTPromiseResolveBlock)resolve
        reject:(RCTPromiseRejectBlock)reject
{
  [_bridge reject:call code:code resolve:resolve reject:reject];
}

- (void)hangup:(NSString *)call resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge hangup:call resolve:resolve reject:reject];
}

- (void)hold:(NSString *)call resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge hold:call resolve:resolve reject:reject];
}

- (void)resume:(NSString *)call resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge resume:call resolve:resolve reject:reject];
}

- (void)transfer:(NSString *)call
          target:(NSString *)target
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject
{
  [_bridge transfer:call target:target resolve:resolve reject:reject];
}

- (void)acceptTransfer:(NSString *)call
               resolve:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject
{
  [_bridge acceptTransfer:call resolve:resolve reject:reject];
}

- (void)rejectTransfer:(NSString *)call
                  code:(NSInteger)code
               resolve:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject
{
  [_bridge rejectTransfer:call code:code resolve:resolve reject:reject];
}

- (void)sendDtmf:(NSString *)call
          digits:(NSString *)digits
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject
{
  [_bridge sendDtmf:call digits:digits resolve:resolve reject:reject];
}

- (void)activateAudio:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge activateAudioWithResolve:resolve reject:reject];
}

- (void)deactivateAudio:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge deactivateAudioWithResolve:resolve reject:reject];
}

- (void)setMuted:(BOOL)muted resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge setMuted:muted resolve:resolve reject:reject];
}

- (void)setSystemEchoCancellation:(BOOL)on
                          resolve:(RCTPromiseResolveBlock)resolve
                           reject:(RCTPromiseRejectBlock)reject
{
  [_bridge setSystemEchoCancellation:on resolve:resolve reject:reject];
}

- (void)setDiagnosticTrace:(BOOL)on resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge setDiagnosticTrace:on resolve:resolve reject:reject];
}

- (void)networkTest:(NSString *)account
           echoCall:(NSString *)echoCall
             echoMs:(double)echoMs
          timeoutMs:(double)timeoutMs
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject
{
  [_bridge networkTest:account echoCall:echoCall echoMs:echoMs timeoutMs:timeoutMs resolve:resolve reject:reject];
}

- (void)setCallGain:(NSString *)call
          direction:(NSString *)direction
               gain:(double)gain
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject
{
  [_bridge setCallGain:call direction:direction gain:gain resolve:resolve reject:reject];
}

- (void)setCallMuted:(NSString *)call
           direction:(NSString *)direction
               muted:(BOOL)muted
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject
{
  [_bridge setCallMuted:call direction:direction muted:muted resolve:resolve reject:reject];
}

- (void)callAudio:(NSString *)call
        direction:(NSString *)direction
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  [_bridge callAudio:call direction:direction resolve:resolve reject:reject];
}

- (void)setAppRate:(NSString *)call
                hz:(NSInteger)hz
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject
{
  [_bridge setAppRate:call hz:hz resolve:resolve reject:reject];
}

- (void)settings:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge settingsWithResolve:resolve reject:reject];
}

@end
