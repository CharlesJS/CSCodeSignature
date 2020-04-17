// swift-tools-version:5.2

import PackageDescription

let package = Package(
    name: "CSCodeSignature",
    platforms: [
        .macOS(.v10_10)
    ],
    products: [
        .library(
            name: "CSCodeSignature",
            targets: ["CSCodeSignature"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/CharlesJS/CSErrors", from: "0.1.2")
    ],
    targets: [
        .target(
            name: "CSCodeSignature",
            dependencies: ["CSErrors"]
        )
    ]
)
