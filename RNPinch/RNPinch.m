//
//  RNNativeFetch.m
//  medipass
//
//  Created by Paul Wong on 13/10/16.
//  Copyright © 2016 Localz. All rights reserved.
//

#import "RNPinch.h"
#import "RCTBridge.h"

@interface RNPinchException : NSException
@end
@implementation RNPinchException
@end

// private delegate for verifying certs
@interface NSURLSessionSSLPinningDelegate:NSObject <NSURLSessionDelegate>

- (id)initWithCertNames:(NSArray<NSString *> *)certNames andP12:(NSString*) p12 ignoreErrors:(Boolean)ignoreErrors;

@property (nonatomic, strong) NSArray<NSString *> *certNames;
@property (nonatomic, strong) NSString * p12;
@property (nonatomic, strong) NSString * clientSecret;
@property (nonatomic) Boolean ignoreErrors;

@end

@implementation NSURLSessionSSLPinningDelegate

- (id)initWithCertNames:(NSArray<NSString *> *)certNames andP12:(NSString*)p12 ignoreErrors:(Boolean)ignoreErrors {
    if (self = [super init]) {
        _certNames = certNames;
        _p12 = p12;
        NSString *path = [[NSBundle mainBundle] pathForResource:@"configuration" ofType:@"plist"];
        NSDictionary *settings = [[NSDictionary alloc] initWithContentsOfFile:path];
        _clientSecret = [settings valueForKey:_p12];
        _ignoreErrors = ignoreErrors;
    }
    return self;
}

- (NSArray *)pinnedCertificateData {
    NSMutableArray *localCertData = [NSMutableArray array];
    for (NSString* certName in self.certNames) {
        NSString *cerPath = [[NSBundle mainBundle] pathForResource:certName ofType:@"cer"];
        if (cerPath == nil) {
            @throw [[RNPinchException alloc]
                    initWithName:@"CertificateError"
                    reason:@"Can not load certicate given, check it's in the app resources."
                    userInfo:nil];
        }
        [localCertData addObject:[NSData dataWithContentsOfFile:cerPath]];
    }
    
    NSMutableArray *pinnedCertificates = [NSMutableArray array];
    for (NSData *certificateData in localCertData) {
        [pinnedCertificates addObject:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData)];
    }
    return pinnedCertificates;
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {
    
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSString *domain = challenge.protectionSpace.host;
        SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];

        NSArray *policies = @[(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)domain)];

        SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);
        // setup
        SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)self.pinnedCertificateData);
        SecTrustResultType result;

        // evaluate
        OSStatus errorCode = SecTrustEvaluate(serverTrust, &result);

        BOOL evaluatesAsTrusted = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);
        if (errorCode == errSecSuccess && evaluatesAsTrusted) {
            NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        } else if (self.ignoreErrors){
            NSURLCredential *credential = [NSURLCredential credentialForTrust: challenge.protectionSpace.serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        } else {
            completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, NULL);
        }
    } else if ([[[challenge protectionSpace] authenticationMethod] isEqualToString:NSURLAuthenticationMethodClientCertificate]){
        NSLog(@"REQUEST FOR CLIENT CERTIFICATE");
        
        // gets a certificate from local resources
        NSString *thePath = [[NSBundle mainBundle] pathForResource:_p12 ofType:@"p12"];
        NSData *PKCS12Data = [[NSData alloc] initWithContentsOfFile:thePath];
        CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
        
        SecIdentityRef identity;
        // extract the ideneity from the certificate
        [self extractIdentity :inPKCS12Data :&identity];
        
        SecCertificateRef certificate = NULL;
        SecIdentityCopyCertificate (identity, &certificate);
        
        const void *certs[] = {certificate};
        CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
        // create a credential from the certificate and ideneity, then reply to the challenge with the credential
        NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identity certificates:(__bridge NSArray*)certArray persistence:NSURLCredentialPersistencePermanent];
        
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
    }
}

- (OSStatus)extractIdentity:(CFDataRef)inP12Data :(SecIdentityRef*)identity {
    OSStatus securityError = errSecSuccess;
    
    CFStringRef password = (__bridge CFStringRef)_clientSecret;
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12Data, options, &items);
    
    if (securityError == 0) {
        CFDictionaryRef ident = CFArrayGetValueAtIndex(items,0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
        
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityError;
}

@end

@interface RNPinch()

@property (nonatomic, strong) NSURLSessionConfiguration *sessionConfig;

@end

@implementation RNPinch
RCT_EXPORT_MODULE();

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        self.sessionConfig.HTTPCookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    }
    return self;
}

RCT_EXPORT_METHOD(fetch:(NSString *)url obj:(NSDictionary *)obj callback:(RCTResponseSenderBlock)callback) {
    NSURL *u = [NSURL URLWithString:url];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:u];
    
    NSURLSession *session;
    if (obj) {
        if (obj[@"method"]) {
            [request setHTTPMethod:obj[@"method"]];
        }
        if (obj[@"timeoutInterval"]) {
            [request setTimeoutInterval:[obj[@"timeoutInterval"] doubleValue] / 1000];
        }
        if (obj[@"headers"] && [obj[@"headers"] isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *m = [obj[@"headers"] mutableCopy];
            for (NSString *key in [m allKeys]) {
                if (![m[key] isKindOfClass:[NSString class]]) {
                    m[key] = [m[key] stringValue];
                }
            }
            [request setAllHTTPHeaderFields:m];
        }
        if (obj[@"body"]) {
            NSData *data = [obj[@"body"] dataUsingEncoding:NSUTF8StringEncoding];
            [request setHTTPBody:data];
        }
    }
    NSString* p12 = nil;
    if(obj && obj[@"sslPinning"] && obj[@"sslPinning"][@"p12"]){
        p12 = (NSString*)obj[@"sslPinning"][@"p12"];
    }
    if (obj && obj[@"sslPinning"] && obj[@"sslPinning"][@"cert"]) {
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithCertNames:@[obj[@"sslPinning"][@"cert"]] andP12:p12 ignoreErrors:(Boolean)obj[@"ignoreErrors"]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    } else if (obj && obj[@"sslPinning"] && obj[@"sslPinning"][@"certs"]) {
        // load all certs
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithCertNames:obj[@"sslPinning"][@"certs"] andP12:p12 ignoreErrors:(Boolean)obj[@"ignoreErrors"]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    } else {
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithCertNames:obj[@"sslPinning"][@"certs"] andP12:p12 ignoreErrors:(Boolean)obj[@"ignoreErrors"]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    }
    
    __block NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (!error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*) response;
                NSInteger statusCode = httpResp.statusCode;
                NSString *bodyString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                NSString *statusText = [NSHTTPURLResponse localizedStringForStatusCode:httpResp.statusCode];
                
                NSDictionary *res = @{
                                      @"status": @(statusCode),
                                      @"headers": httpResp.allHeaderFields,
                                      @"bodyString": bodyString,
                                      @"statusText": statusText
                                      };
                callback(@[[NSNull null], res]);
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                callback(@[@{@"message":error.localizedDescription}, [NSNull null]]);
            });
        }
    }];
    
    [dataTask resume];
}

@end
