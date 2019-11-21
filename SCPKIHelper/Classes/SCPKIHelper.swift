//
//  SCPKIHelper.swift
//  SCPKIHelper
//
//  Created by Kimi on 28/06/2019.
//

import UIKit
import LocalAuthentication

public enum SCPKIError : Error {
    case itemAlreadyExistInKeychain(String)
    case keyNotFound(String)
    case certificateNotFound(String)
    case couldNotCreateKeyPair(String)
    case couldNotRetrievePublicKey(String)
    case couldNotRetrievePrivateKey(String)
    case couldNotRetrieveCertificate(String)
}

open class SCPKIHelper : NSObject {

    public static let shared = SCPKIHelper()
    
    private(set) var serviceName : String
    private(set) var authenticationContext : LAContext
    
    private override convenience init() {
        guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
            fatalError("Bundle.main.bundleIdentifier is nil")
        }
        
        self.init(serviceName: bundleIdentifier)
    }
    
    init(serviceName : String) {
        self.serviceName = serviceName
        self.authenticationContext = LAContext()
        self.authenticationContext.touchIDAuthenticationAllowableReuseDuration = 10
    }
    
    public func set(authenticationContext: LAContext) {
        self.authenticationContext = authenticationContext
    }
    
}

// Generate key pair
@available(iOS 11.3, *)
@available(iOS 11.3, *)
@available(iOS 11.3, *)
public extension SCPKIHelper {
    
    private func defaultSecAccessControl(storeInKeychain: Bool) -> SecAccessControl {
        var accessControlError: Unmanaged<CFError>?
        
        let accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryAny, &accessControlError)
               
        precondition(accessControl != nil, "SecAccessControlCreateWithFlags failed")
        return accessControl!
    }
    
    func removeKeys(identifiedBy identifier: String) -> Bool {
        let keyPairIdentifier = "\(self.serviceName).\(identifier)"
        
        let keysParams: [CFString: Any] = [
                          kSecAttrApplicationTag: "\(keyPairIdentifier)",
                          kSecClass: kSecClassKey]
                
        let publicKeyParams: [CFString: Any] = [
                           kSecAttrApplicationTag: "\(keyPairIdentifier).public",
                           kSecClass: kSecClassKey]
        
        let privateKeyParams: [CFString: Any] = [
                           kSecAttrApplicationTag: "\(keyPairIdentifier).private",
                           kSecClass: kSecClassKey]
        
        let delStatus = SecItemDelete(keysParams as CFDictionary)
        let delPublicStatus = SecItemDelete(publicKeyParams as CFDictionary)
        let delPrivateStatus = SecItemDelete(privateKeyParams as CFDictionary)
        
        return delPublicStatus == errSecSuccess || delPrivateStatus == errSecSuccess || delStatus == errSecSuccess
    }
    
    func getKeyPair(with spec : SCPKIKeySpec, identifiedBy identifier: String, _ completion: (@escaping (_ publicKey : SecKey?, _ privateKey : SecKey?, _ error: Error?) -> Void)) {
    
        getPublicKey(with: spec, identifiedBy: identifier) {[weak self] publicKey, error1 in
            guard let self = self else { return }
            if let error1 = error1 {
                completion(nil, nil, error1)
                return
            }
            self.getPrivateKey(with: spec, identifiedBy: identifier) { privateKey, error2 in
                if let error2 = error2 {
                    completion(nil, nil, error2)
                    return
                }
                completion(publicKey, privateKey, nil)
            }
        }
    }
    
    func getCertificate(identifiedBy identifier: String, _ completion: (@escaping (_ certificate : SecCertificate?, _ error: Error?) -> Void)) {
        
        let certificateIdentifier = "\(self.serviceName).\(identifier)"
        
        let certificateParams: [CFString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: "\(certificateIdentifier).certificate",
            kSecUseAuthenticationContext: authenticationContext,
            kSecUseOperationPrompt: authenticationContext.localizedReason,
            kSecUseAuthenticationUI: kSecUseAuthenticationUIAllow,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnRef: true]
        
        DispatchQueue.global().async {
            var result : AnyObject?

            let status = SecItemCopyMatching(certificateParams as CFDictionary, &result)
            
            if status == errSecSuccess {
                guard let certificate = result as! SecCertificate? else {
                    completion(nil, SCPKIError.couldNotRetrieveCertificate(certificateIdentifier))
                    return
                }
                
                completion(certificate, nil)
                return
            }
            completion(nil, SCPKIError.certificateNotFound(certificateIdentifier))
        }
    }
    
    func getPrivateKey(with spec : SCPKIKeySpec, identifiedBy identifier: String, _ completion: (@escaping (_ privateKey : SecKey?, _ error: Error?) -> Void)) {
    
        let keyPairIdentifier = "\(self.serviceName).\(identifier)"
     
        let privateKeyParams: [CFString: Any] = [
                    kSecAttrIsPermanent: spec.storeInKeychain,
                    kSecAttrApplicationTag: "\(keyPairIdentifier).private",
                    kSecClass: kSecClassKey,
                    kSecUseAuthenticationContext: authenticationContext,
                    kSecUseOperationPrompt: authenticationContext.localizedReason,
                    kSecUseAuthenticationUI: kSecUseAuthenticationUIAllow,
                    kSecMatchLimit: kSecMatchLimitOne,
                    kSecReturnData: true]

        
        DispatchQueue.global().async {
            var result : AnyObject?

            let status = SecItemCopyMatching(privateKeyParams as CFDictionary, &result)
            
            if status == errSecSuccess {
                guard let privateKey = result as! SecKey? else {
                    completion(nil, SCPKIError.couldNotRetrievePrivateKey(keyPairIdentifier))
                    return
                }
                
                completion(privateKey, nil)
                return
            }
            completion(nil, SCPKIError.keyNotFound(keyPairIdentifier))
        }
    }
    
    func getPublicKey(with spec : SCPKIKeySpec, identifiedBy identifier: String, _ completion: (@escaping (_ publicKey : SecKey?, _ error: Error?) -> Void)) {
    
        let keyPairIdentifier = "\(self.serviceName).\(identifier)"
                
        let publicKeyParams: [CFString: Any] = [
                    kSecAttrIsPermanent: spec.storeInKeychain,
                    kSecAttrApplicationTag: "\(keyPairIdentifier).public",
                    kSecClass: kSecClassKey,
                    kSecUseAuthenticationContext: authenticationContext,
                    kSecUseOperationPrompt: authenticationContext.localizedReason,
                    kSecUseAuthenticationUI: kSecUseAuthenticationUIAllow,
                    kSecMatchLimit: kSecMatchLimitOne,
                    kSecReturnData: true]
       
        DispatchQueue.global().async {
            var result : AnyObject?

            let status = SecItemCopyMatching(publicKeyParams as CFDictionary, &result)
            
            if status == errSecSuccess {
                guard let publicKey = result as! SecKey? else {
                    completion(nil, SCPKIError.couldNotRetrievePublicKey(keyPairIdentifier))
                    return
                }
                completion(publicKey, nil)
                return
            }
            completion(nil, SCPKIError.keyNotFound(keyPairIdentifier))
        }
    }
    
    func generateKeyPair(with spec : SCPKIKeySpec, identifiedBy identifier: String, _ completion:  (@escaping (_ publicKey : SecKey?, _ privateKey : SecKey?, _ error: Error?) -> Void)) {
        
        let keyPairIdentifier = "\(self.serviceName).\(identifier)"
        
        let privateKeySpec: [CFString : Any] = [
            kSecAttrIsPermanent: spec.storeInKeychain,
            kSecAttrApplicationTag: "\(keyPairIdentifier).private"
        ]
        
        let publicKeyParams: [CFString : Any] = [
            kSecAttrIsPermanent: spec.storeInKeychain,
            kSecAttrApplicationTag: "\(keyPairIdentifier).public"
        ]
        
        let keyPairParams: [CFString: Any] = [
            kSecPublicKeyAttrs: publicKeyParams,
            kSecPrivateKeyAttrs: privateKeySpec,
            kSecAttrKeyType: spec.keyType,
            kSecAttrKeySizeInBits: spec.sizeInBits,
            kSecAttrAccessControl: defaultSecAccessControl(storeInKeychain: spec.storeInKeychain)
        ]
        
        // private / public key generation takes a lot of time, so this operation must be perform in another thread.
        DispatchQueue.global().async {
            var publicKey : SecKey?
            var privateKey : SecKey?
            
            let status = SecKeyGeneratePair(keyPairParams as CFDictionary, &publicKey, &privateKey)
            
            if status != errSecSuccess {
                let defaultErrorMessage = "An unknown error ocurred while generating pair with code: \(status)"
                var error = SCPKIError.couldNotCreateKeyPair(defaultErrorMessage)
                
                switch (status) {
                    case errSecDuplicateItem: error = SCPKIError.itemAlreadyExistInKeychain("The item identified by '\(keyPairIdentifier)' already exist in the Keychain")
                    case errSecItemNotFound: error = SCPKIError.keyNotFound("The item identified by '\(keyPairIdentifier)' does not exist")
                    default: break
                }
                
                DispatchQueue.main.async {
                    completion(nil, nil, error)
                }
                return
            }
            
            DispatchQueue.main.async {
                completion(publicKey, privateKey, nil)
            }
        }
    }
}

