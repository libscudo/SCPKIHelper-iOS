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
                waitUntil (timeout: 5) { done in
                    SCPKIHelper.shared.generateKeyPair(with: spec, identifiedBy: "test_key_1") { publicKey, privateKey, error in
                        expect(publicKey).notTo(be(nil))
                        expect(privateKey).notTo(be(nil))
                        expect(error).to(beNil())
                        done()
                    }
                }
            }
            
            it("can create a private / public key pair, save it into the Keychain, and recover it using SCKeychainManager") {
                let spec = SCPKIKeySpec.common
                spec.storeInKeychain = true
                waitUntil (timeout: 5) { done in
                    SCPKIHelper.shared.generateKeyPair(with: spec, identifiedBy: "test_key_2") { _, _, error in
                        expect(error).to(beNil())
                        
                        done()
                    }
                }
            }
            
            
        }
    }
}
