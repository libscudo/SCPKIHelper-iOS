// https://github.com/Quick/Quick

import Quick
import Nimble
@testable import SCPKIHelper

class SCKPIHelperSpec: QuickSpec {
    override func spec() {
        describe("SCKPIHelper") {
            
            it("defines a common spec for keys with the following specs. RSA / 4096 / padding PKCS1SHA512") {
                let spec = SCPKIKeySpec.common
                expect(spec.keyType).to(equal(kSecAttrKeyTypeRSA))
                expect(spec.sizeInBits).to(equal(4096))
                expect(spec.padding).to(equal(SecPadding.PKCS1SHA512))
                expect(spec.storeInKeychain).to(equal(false))
            }

            it("can create a private / public key pair with default specification") {
                let spec = SCPKIKeySpec.common
                waitUntil (timeout: 10) { done in
                    SCPKIHelper.shared.generateKeyPair(with: spec, identifiedBy: "test_key_1") { publicKey, privateKey, error in
                        expect(publicKey).notTo(be(nil))
                        expect(privateKey).notTo(be(nil))
                        expect(error).to(beNil())
                        
                        if let pub = publicKey {
                            if #available(iOS 10.0, *) {
                                let pubAttributes = SecKeyCopyAttributes(pub) as! [String: Any]
                                
                                // is RSA?
                                let type = Int(pubAttributes[kSecAttrKeyType as String] as! String)
                                let rsaType = Int(kSecAttrKeyTypeRSA as String)
                                expect(type).notTo(beNil())
                                expect(type).to(equal(rsaType))
                                
                                // is a Pubic Key?
                                let keyType = Int(pubAttributes[kSecAttrKeyClass as String] as! String)
                                let pubKeyType = Int(kSecAttrKeyClassPublic as String)
                                expect(keyType).notTo(beNil())
                                expect(keyType).to(equal(pubKeyType))
                                
                                // Check key size
                                let keySize = pubAttributes[kSecAttrKeySizeInBits as String] as! Int
                                expect(keySize).notTo(beNil())
                                expect(keySize).to(equal(4096))
                            }
                        }
                        done()
                    }
                }
            }
            
            it("can create a private / public key pair, save it into the Keychain, and recover it using SCKeychainManager") {
                let spec = SCPKIKeySpec.from(SCPKIKeySpec.common)
                spec.storeInKeychain = true
                
                //SCPKIKeySpec.common.storeInKeychain untouched
                expect(SCPKIKeySpec.common.storeInKeychain).to(equal(false))
                
                waitUntil (timeout: 10) { done in
                    SCPKIHelper.shared.generateKeyPair(with: spec, identifiedBy: "test_key_2") { publicKey, privateKey, error in
                        expect(publicKey).notTo(be(nil))
                        expect(privateKey).notTo(be(nil))
                        expect(error).to(beNil())
                        
                        if let pub = publicKey {
                            if #available(iOS 10.0, *) {
                                let pubAttributes = SecKeyCopyAttributes(pub) as! [String: Any]
                                
                                // is RSA?
                                let type = Int(pubAttributes[kSecAttrKeyType as String] as! String)
                                let rsaType = Int(kSecAttrKeyTypeRSA as String)
                                expect(type).notTo(beNil())
                                expect(type).to(equal(rsaType))
                                
                                // is a Pubic Key?
                                let keyType = Int(pubAttributes[kSecAttrKeyClass as String] as! String)
                                let pubKeyType = Int(kSecAttrKeyClassPublic as String)
                                expect(keyType).notTo(beNil())
                                expect(keyType).to(equal(pubKeyType))
                                
                                // Check key size
                                let keySize = pubAttributes[kSecAttrKeySizeInBits as String] as! Int
                                expect(keySize).notTo(beNil())
                                expect(keySize).to(equal(4096))
                            }
                        }

                        done()
                    }
                }
            }
        }
    }
}
