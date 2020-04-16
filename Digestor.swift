//
//  Digestor.swift
//
//  Created by wujungao on 2020/4/15.
//  Copyright © 2020 com.wujungao. All rights reserved.
//

import Foundation
import CommonCrypto
import RxSwift

class Digestor{
    //512 ctx
    var sha512CTX:UnsafeMutablePointer<CC_SHA512_CTX>
    //result
    typealias Result = DigestResult<Int32,Swift.Error>
    var result:Result
    
    init() {
        self.sha512CTX=UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: MemoryLayout<CC_SHA512_CTX>.size)
        self.sha512CTX.initialize(to: CC_SHA512_CTX.init())
        
        let result=CC_SHA512_Init(self.sha512CTX)
        self.result=result==1 ? .success(result) : .failure(NSError.init(domain: String.DigestDomain, code: Int(result), userInfo: nil))
    }
    
    func update(data:Data) -> Result{
        
        switch self.result {
        case .failure(_):
            return self.result
        case .success(_):
            let r=data.withUnsafeBytes { dataPtr in
                CC_SHA512_Update(self.sha512CTX, dataPtr.baseAddress!, CC_LONG(dataPtr.count))
            }
            
            return r==1 ? .success(r) : .failure(NSError.init(domain: String.DigestDomain, code: Int(r), userInfo: nil))
        }
    }
    
    func rxfinal() -> Observable<String>{
        
        return Observable.create { (observer) -> Disposable in
            
            let digest=UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
            digest.initialize(to: 0)
            
            let r=CC_SHA512_Final(digest, self.sha512CTX)
            if(r != 1){
                observer.onError(NSError.init(domain: String.DigestDomain, code: -1, userInfo: nil))
            }
            else{
                var digestHex=""//%02x
                for index in 0 ..< Int(CC_SHA512_DIGEST_LENGTH) {
                    digestHex += String(format: "%02x",digest[index])
                }
                if(digestHex.isEmpty){
                    observer.onError(NSError.init(domain: String.DigestDomain, code: -1, userInfo: nil))
                }
                else{
                    observer.onNext(digestHex)
                    observer.onCompleted()
                }
            }
                        
            return Disposables.create()
        }
    }
    
    func final() -> String?{
        
        let digest=UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
        digest.initialize(to: 0)
        
        let r=CC_SHA512_Final(digest, self.sha512CTX)
        if(r != 1){
            return nil
        }
           
        var digestHex=""//%02x
        for index in 0 ..< Int(CC_SHA512_DIGEST_LENGTH) {
            digestHex += String(format: "%02x",digest[index])
        }
        if(digestHex.isEmpty){
            return nil
        }
        
        return digestHex
    }
    
    //MARK: - result enum
    enum DigestResult<Success,Failure:Error> {
        case success(Success)
        case failure(Failure)
    }
}

//MARK: - string
extension String{
    static var DigestDomain:String{
        return "custom.digest.domain"
    }
    
    func rxsha512() ->Observable<String>{
        
        return Observable.create { (observer) -> Disposable in

            let digest=UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
            digest.initialize(to: 0)
            
            if let data = self.data(using: .utf8){
                data.withUnsafeBytes { (point) ->Void in
                    CC_SHA512(point.baseAddress!, CC_LONG(point.count), digest)
                }
            }
            
            var digestHex=""//%02x
            for index in 0 ..< Int(CC_SHA512_DIGEST_LENGTH) {
                digestHex += String(format: "%02x",digest[index])
            }
            
            if(digestHex.isEmpty){
                observer.onError(NSError.init(domain: String.DigestDomain, code: -1, userInfo: nil))
            }
            else{
                observer.onNext(digestHex)
                observer.onCompleted()
            }
            
            return Disposables.create()
        }
    }
    
    func sha512() ->String?{
        let digest=UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
        digest.initialize(to: 0)
        
        if let data = self.data(using: .utf8){
            data.withUnsafeBytes { (point) ->Void in
                CC_SHA512(point.baseAddress!, CC_LONG(point.count), digest)
            }
        }
        
        var digestHex=""//%02x
        for index in 0 ..< Int(CC_SHA512_DIGEST_LENGTH) {
            digestHex += String(format: "%02x",digest[index])
        }
        
        return digestHex.isEmpty ? nil : digestHex
    }
}

extension Data{
    
    func sha512() -> String?{
        let digest=UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
        digest.initialize(to: 0)
        
        self.withUnsafeBytes { (point) ->Void in
            CC_SHA512(point.baseAddress!, CC_LONG(point.count), digest)
        }
        
        var digestHex=""//%02x
        for index in 0 ..< Int(CC_SHA512_DIGEST_LENGTH) {
            digestHex += String(format: "%02x",digest[index])
        }
        
        return digestHex.isEmpty ? nil : digestHex
    }
    
    func rxsha512() ->Observable<String>{
        
        return Observable.create { (observer) -> Disposable in

            let digest=UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA512_DIGEST_LENGTH))
            digest.initialize(to: 0)
            
            self.withUnsafeBytes { (point) ->Void in
                CC_SHA512(point.baseAddress!, CC_LONG(point.count), digest)
            }
            
            var digestHex=""//%02x
            for index in 0 ..< Int(CC_SHA512_DIGEST_LENGTH) {
                digestHex += String(format: "%02x",digest[index])
            }
            
            if(digestHex.isEmpty){
                observer.onError(NSError.init(domain: String.DigestDomain, code: -1, userInfo: nil))
            }
            else{
                observer.onNext(digestHex)
                observer.onCompleted()
            }
            
            return Disposables.create()
        }
    }
}
