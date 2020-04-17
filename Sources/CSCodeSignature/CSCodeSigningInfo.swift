//
//  CSCodeSigningInfo.swift
//
//  Created by Charles Srstka on 10/12/13.
//
//

import Foundation
import CSErrors

public struct CodeSignature {
    private static let sandboxEntitlementName = "com.apple.security.app-sandbox"

    public enum Status {
        case valid
        case invalid(Error)
        case notSigned
    }

    public struct Info {
        public let identifier: String?
        public let authorities: [Authority]
        public let designatedRequirement: String?
        public let additionalRequirements: String?
        public let format: String?
        public let signingDate: Date?

        public var isSandboxed: Bool { self.entitlements[CodeSignature.sandboxEntitlementName] as? Bool ?? false }
        public private(set) var entitlements: [String: Any]

        init(
            identifier: String? = nil,
            authorities: [Authority] = [],
            designatedRequirement: String? = nil,
            additionalRequirements: String? = nil,
            format: String? = nil,
            signingDate: Date? = nil,
            entitlements: [String: Any] = [:]
        ) {
            self.identifier = identifier
            self.authorities = authorities
            self.designatedRequirement = designatedRequirement
            self.additionalRequirements = additionalRequirements
            self.format = format
            self.signingDate = signingDate
            self.entitlements = entitlements
        }
    }

    public struct Authority {
        public let name: String
        public let warning: String?
        public let error: String?
    }

    public let status: Status
    public let info: Info

    public var isValid: Bool { if case .valid = self.status { return true } else { return false } }

    public init(url: URL) throws {
        let code = try CodeSignature.getStaticCode(url: url)

        let status = CodeSignature.getStatus(code: code, url: url)

        do {
            self.info = try CodeSignature.getInfo(code: code, url: url)
            self.status = status
        } catch {
            self.info = Info()
            self.status = .invalid(error)
        }
    }

    private static func getStaticCode(url: URL) throws -> SecStaticCode {
        var code: SecStaticCode?
        let err = SecStaticCodeCreateWithPath(url as CFURL, [], &code)

        if err != errSecSuccess {
            throw OSStatusError(err, url: url)
        }

        guard let unwrappedCode = code else {
            throw CocoaError(.fileReadUnknown)
        }

        return unwrappedCode
    }

    private static func getStatus(code: SecStaticCode, url: URL) -> Status {
        var error: Unmanaged<CFError>?
        let err = SecStaticCodeCheckValidityWithErrors(code, [], nil, &error)

        switch err {
        case errSecSuccess:
            return .valid
        case errSecCSUnsigned:
            error?.release()
            return .notSigned
        default:
            return .invalid(OSStatusError(err, url: url, underlying: error?.takeRetainedValue()))
        }
    }

    private static func getInfo(code: SecStaticCode, url: URL) throws -> Info {
        let infoDictionary = try self.getInfoDictionary(code: code, url: url)

        let id = infoDictionary[kSecCodeInfoIdentifier] as? String
        let authorities = self.getAuthorities(info: infoDictionary)
        let requirements = self.getRequirements(info: infoDictionary)

        let format = infoDictionary[kSecCodeInfoFormat] as? String
        let signingDate = infoDictionary[kSecCodeInfoTime] as? Date
        let entitlements = infoDictionary[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]

        let info = Info(
            identifier: id,
            authorities: authorities,
            designatedRequirement: requirements.designated,
            additionalRequirements: requirements.additional,
            format: format,
            signingDate: signingDate,
            entitlements: entitlements
        )

        return info
    }

    private static func getInfoDictionary(code: SecStaticCode, url: URL) throws -> [AnyHashable: Any] {
        var cfInfo: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        let err = SecCodeCopySigningInformation(code, flags, &cfInfo)

        if err != errSecSuccess {
            throw OSStatusError(err, url: url)
        }

        guard let info = cfInfo as? [AnyHashable: Any] else { throw CocoaError(.fileReadUnknown) }

        return info
    }

    private static func getAuthorities(info: [AnyHashable: Any]) -> [Authority] {
        guard let cfTrust = info[kSecCodeInfoTrust] as CFTypeRef?,
            CFGetTypeID(cfTrust) == SecTrustGetTypeID(),
            case let trust = cfTrust as! SecTrust, // swiftlint:disable:this force_cast
            let trustInfo = SecTrustCopyProperties(trust) as? [[AnyHashable: Any]] else {
                return []
        }

        return trustInfo.map {
            let _name = $0[kSecPropertyTypeTitle] as? String
            let warning = $0[kSecPropertyTypeWarning] as? String
            let _error = $0[kSecPropertyTypeError] as? String

            let name: String
            let error: String?

            if let _name = _name {
                name = _name
                error = _error
            } else {
                let unknownError = CocoaError(.fileReadUnknown).localizedDescription

                name = unknownError
                error = _error ?? unknownError
            }

            return Authority(name: name, warning: warning, error: error)
        }
    }

    private static func getRequirements(info: [AnyHashable: Any]) -> (designated: String?, additional: String?) {
        let designated: String?

        if let req = info[kSecCodeInfoDesignatedRequirement] as CFTypeRef?,
            CFGetTypeID(req) == SecRequirementGetTypeID() {
            var cfRequirementString: CFString?

            // swiftlint:disable:next force_cast
            let err = SecRequirementCopyString(req as! SecRequirement, [], &cfRequirementString)

            if err != errSecSuccess {
                cfRequirementString = SecCopyErrorMessageString(err, nil)
            }

            designated = cfRequirementString as String?
        } else {
            designated = nil
        }

        let additional = (info[kSecCodeInfoRequirements] as? String).map {
            self.trimRequirements($0, designatedRequirement: designated)
        }

        return (designated: designated, additional: additional)
    }

    private static func trimRequirements(_ requirements: String, designatedRequirement: String?) -> String {
        let designatedPrefix = "designated =>"

        var newReqs = String()

        requirements.enumerateLines { line, _ in
            if let prefixRange = line.range(of: designatedPrefix, options: [.anchored]) {
                let trimmed = line[prefixRange.upperBound...]
                if let designatedRequirement = designatedRequirement?.trimmingCharacters(in: .whitespacesAndNewlines),
                    line.trimmingCharacters(in: .whitespacesAndNewlines) != designatedRequirement {
                    newReqs.append(contentsOf: trimmed)
                }
            } else {
                newReqs.append(line)
            }
        }

        return newReqs
    }
}
