// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "BleTest",
    platforms: [.iOS(.v17)],
    targets: [
        .executableTarget(
            name: "BleTest",
            path: "BleTest"
        ),
    ]
)
