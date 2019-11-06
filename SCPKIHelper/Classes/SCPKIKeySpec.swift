//
//  SCPKIKeySpec.swift
//  SCPKIHelper
//
//  Created by Kimi on 28/06/2019.
//

import UIKit

public enum SignatureAlgorithm {
    case sha1, sha256, sha512
}

open class SCPKIKeySpec {

    public static let common = SCPKIKeySpec(keyType: kSecAttrKeyTypeRSA, sizeInBits: 4096, padding: SecPadding.PKCS1SHA512, signatureAlgorithm: .sha256)
    
    private(set) var keyType : CFString
    private(set) var sizeInBits : Int
    private(set) var padding : SecPadding
    private(set) var storeInKeychain = false
    private(set) var signatureAlgorithm : SignatureAlgorithm
    
    public init(keyType : CFString, sizeInBits: Int, padding: SecPadding, signatureAlgorithm: SignatureAlgorithm) {
        self.keyType = keyType
        self.sizeInBits = sizeInBits
        self.padding = padding
        self.signatureAlgorithm = signatureAlgorithm
    }
    
    public static func from(_ sourceSpec : SCPKIKeySpec) -> SCPKIKeySpec {
        return SCPKIKeySpec(keyType: sourceSpec.keyType, sizeInBits: sourceSpec.sizeInBits, padding: sourceSpec.padding, signatureAlgorithm: sourceSpec.signatureAlgorithm)
    }
    
    public func secureInKeychain(_ store: Bool) -> SCPKIKeySpec {
        storeInKeychain = store
        return self
    }

}
