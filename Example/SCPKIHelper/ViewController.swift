//
//  ViewController.swift
//  SCPKIHelper
//
//  Created by eaceto on 06/28/2019.
//  Copyright (c) 2019 eaceto. All rights reserved.
//

import UIKit
import SCPKIHelper
import LocalAuthentication

class ViewController: UIViewController {

    let spec = SCPKIKeySpec.common
    
    let keysId = "test_key_1"
    
    private var publicKey: SecKey?
    private var privateKey: SecKey?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        _ = spec.secureInKeychain(true)
        let authContext = LAContext()
        authContext.localizedReason = "Access private key"
        authContext.localizedCancelTitle = "Cancel"
        authContext.localizedFallbackTitle = "Fallback"
        authContext.touchIDAuthenticationAllowableReuseDuration = 60
        
        SCPKIHelper.shared.set(authenticationContext: authContext)
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    @IBAction func clearAll(_ sender: Any) {
        SCPKIHelper.shared.removeKeys(identifiedBy: keysId)
    }
    
    @IBAction func generateKeys(_ sender: Any) {
        SCPKIHelper.shared.generateKeyPair(with: spec, identifiedBy: keysId) { [weak self] publicKey, privateKey, error in
            self?.publicKey = publicKey
            self?.privateKey = privateKey
            debugPrint("\(publicKey)")
            debugPrint("\(privateKey)")
            debugPrint("\(error)")
        }
    }
    
    @IBAction func getKeys(_ sender: Any) {
        SCPKIHelper.shared.getKeyPair(with: spec, identifiedBy:
            keysId)  { [weak self] publicKey, privateKey, error in
                self?.publicKey = publicKey
                self?.privateKey = privateKey
                debugPrint("\(publicKey)")
                debugPrint("\(privateKey)")
                debugPrint("\(error)")
       }
    }
    
    @IBAction func getPrivate(_ sender: Any) {
        SCPKIHelper.shared.getPrivateKey(with: spec, identifiedBy: keysId) { privateKey, error in
            debugPrint("\(privateKey)")
            debugPrint("\(error)")
        }
    }
    
    @IBAction func getPublic(_ sender: Any) {
        SCPKIHelper.shared.getPublicKey(with: spec, identifiedBy: keysId) { publicKey, error in
            
            debugPrint("\(publicKey)")
            debugPrint("\(error)")
        }
    }
    
    @IBAction func getCSR(_ sender: Any) {

    }
}

