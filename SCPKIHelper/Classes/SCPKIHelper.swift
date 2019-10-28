//
//  SCPKIHelper.swift
//  SCPKIHelper
//
//  Created by Kimi on 28/06/2019.
//

import UIKit

public enum SCPKIError : Error {
    case itemAlreadyExistInKeychain(String)
    case keyNotFound(String)
    case couldNotCreateKeyPair(String)
    case couldNotRetrievePublicKey(String)
    case couldNotRetrievePrivateKey(String)
}

open class SCPKIHelper : NSObject {

    public static let shared = SCPKIHelper()
    
    private(set) var serviceName : String
    
    private override convenience init() {
        guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
            fatalError("Bundle.main.bundleIdentifier is nil")
        }
        
        self.init(serviceName: bundleIdentifier)
    }
    
    init(serviceName : String) {
        self.serviceName = serviceName
    }
    
}

// Generate key pair
@available(iOS 11.3, *)
@available(iOS 11.3, *)
@available(iOS 11.3, *)
public extension SCPKIHelper {
    
    func getKeyPair(with spec : SCPKIKeySpec, identifiedBy identifier: String, _ completion: (@escaping (_ publicKey : SecKey?, _ privateKey : SecKey?, _ error: Error?) -> Void)) {
    
        let keyPairIdentifier = "\(self.serviceName).\(identifier)"
                
        let publicKeyParams: [CFString: Any] = [
                    kSecAttrIsPermanent: true as NSObject,
                    kSecAttrApplicationTag: "\(keyPairIdentifier).public",
                    kSecClass: kSecClassKey,
                    kSecReturnData: true]

        let privateKeyParams: [CFString: Any] = [
                    kSecAttrIsPermanent: true as NSObject,
                    kSecAttrApplicationTag: "\(keyPairIdentifier).private",
                    kSecClass: kSecClassKey,
                    kSecReturnData: true]

        
        DispatchQueue.global().async {
            var result : AnyObject?

            var status = SecItemCopyMatching(publicKeyParams as CFDictionary, &result)
            
            if status == errSecSuccess {
                guard let publicKey = result as! SecKey? else {
                    completion(nil, nil, SCPKIError.couldNotRetrievePublicKey(keyPairIdentifier))
                    return
                }
                
                status = SecItemCopyMatching(privateKeyParams as CFDictionary, &result)
                
                if status == errSecSuccess {
                    guard let privateKey = result as! SecKey? else {
                        completion(nil, nil, SCPKIError.couldNotRetrievePrivateKey(keyPairIdentifier))
                        return
                    }
                    
                    completion(publicKey, privateKey, nil)
                    return
                }
            }
            completion(nil, nil, SCPKIError.keyNotFound(keyPairIdentifier))
        }
    }
    
    @available(iOS 11.3, *)
    @available(iOS 11.3, *)
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
        
        var accessControlError: Unmanaged<CFError>?
        
        let flags = SecAccessControlCreateFlags.biometryCurrentSet.rawValue | SecAccessControlCreateFlags.devicePasscode.rawValue

        guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                  kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                  SecAccessControlCreateFlags(rawValue: flags),
                                                                  &accessControlError) else {
                                                                    completion(nil, nil, accessControlError as? Error)
            return
        }

        let keyPairParams: [CFString: Any] = [
            kSecPublicKeyAttrs: publicKeyParams,
            kSecPrivateKeyAttrs: privateKeySpec,
            kSecAttrKeyType: spec.keyType,
            kSecAttrKeySizeInBits: spec.sizeInBits,
            kSecAttrAccessControl: accessControl
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
