//
//  SCPKIKeySpec.swift
//  SCPKIHelper
//
//  Created by Kimi on 28/06/2019.
//

import UIKit

open class SCPKIKeySpec {

    public static let common = SCPKIKeySpec(keyType: kSecAttrKeyTypeRSA, sizeInBits: 4096, padding: SecPadding.PKCS1SHA512)
    
    private(set) var keyType : CFString
    private(set) var sizeInBits : Int
    private(set) var padding : SecPadding
    private(set) var storeInKeychain = false
    
    public init(keyType : CFString, sizeInBits: Int, padding: SecPadding) {
        self.keyType = keyType
        self.sizeInBits = sizeInBits
        self.padding = padding
    }
    
    public static func from(_ sourceSpec : SCPKIKeySpec) -> SCPKIKeySpec {
        return SCPKIKeySpec(keyType: sourceSpec.keyType, sizeInBits: sourceSpec.sizeInBits, padding: sourceSpec.padding)
    }
    
    public func secureInKeychain(_ store: Bool) -> SCPKIKeySpec {
        storeInKeychain = store
        return self
    }
    
}
