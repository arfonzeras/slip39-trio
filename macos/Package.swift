// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "slip39-trio-mac",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "slip39-trio-mac",
            path: "Sources/slip39-trio-mac"
        )
    ]
)
