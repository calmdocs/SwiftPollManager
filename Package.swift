// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftPollManager",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13)
    //    .tvOS(.v12),
    //    .watchOS(.v5)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftPollManager",
            targets: ["SwiftPollManager"]),
    ],
    dependencies: [
        .package(url: "https://github.com/calmdocs/SwiftProcessManager", branch: "main"),
        .package(url: "https://github.com/calmdocs/SwiftKeyExchange", branch: "main")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftPollManager",
            dependencies: ["SwiftProcessManager", "SwiftKeyExchange"]),
        .testTarget(
            name: "SwiftPollManagerTests",
            dependencies: ["SwiftPollManager"]),
    ]
)
