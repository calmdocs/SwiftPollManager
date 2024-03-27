# SwiftPollManager

As an alternative to building an electron app or using a gui toolkit, run a golang binary embedded in a native macOS SwiftUI app.  The golang binary and SwiftUI app communicate via [http long polling](https://en.wikipedia.org/wiki/Push_technology#Long_polling).

Given that http is unencrypted, the messages can be optionally encrypted using the [calmdocs/SwiftKeyExchange swift library](https://github.com/calmdocs/SwiftKeyExchange) and [calmdocs/keyexchange go library](https://github.com/calmdocs/keyexchange).

If you already have xCode and go installed, implementing the following example to build a new running app takes about 2 minutes.

## Example

### Setup

Create a new macOS Swift Xcode project:
- File -> Add Packages ... -> https://github.com/calmdocs/SwiftPollManager
- Select the checkbox at Target -> Signing & Capabilities -> App Sandbox -> Network -> Incoming connections (Server).
- Select the checkbox at Target -> Signing & Capabilities -> App Sandbox -> Network -> Incoming connections (Client).

### Create go binaries (for amd64 and arm64)

Run the following commands:
- git clone https://github.com/calmdocs/SwiftPollManager
- cd SwiftPollManager/gobinary
- GOOS=darwin GOARCH=amd64 go build -o gobinary-darwin-amd64 && GOOS=darwin GOARCH=arm64 go build -o gobinary-darwin-arm64

Drag the gobinary-darwin-amd64 and gobinary-darwin-arm64 files that we just built into the new macOS Swift xCode project.

### In the new Swift xCode project, replace ContentView.swift with the following code:

```
import SwiftUI
import SwiftPollManager

public struct Item: Codable, Identifiable {
    public var id: Int64
    
    let error: String?
    let name: String
    let status: String
    let progress: Double

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case error = "Error"
        case name = "Name"
        case status = "Status"
        case progress = "Progress"
    }
}

struct ContentView: View {
    @ObservedObject var ip: ItemsProvider = ItemsProvider()
     
    var body: some View {
        List {
            HStack {
                Button(action: {
                    Task {
                        await ip.publish(
                            type: "addItem",
                            id: "",
                            data: ""
                        )
                    }
                }, label: {
                    Image(systemName: "plus")
                })
                Spacer()
            }
            ForEach(ip.items) { item in
                HStack{
                    Text("\(item.name) (\(item.status))")
                    ProgressView(value: item.progress)
                    Spacer()
                    Button(action: {
                        Task {
                            await ip.publish(
                                type: "deleteItem",
                                id: String(item.id),
                                data: ""
                            )
                            self.ip.items = self.ip.items.filter { $0.id != item.id }
                        }
                    }, label: {
                        Image(systemName: "trash")
                    })
                }
            }
        }
    }
}

class ItemsProvider: ObservableObject {
    @ObservedObject var pm: PollManager = PollManager()
    @Published var items: [Item] = [Item]()

    private var isFirstRun: Bool = true
    private var port = 0

    init() {
        let binName = self.pm.systemArchitecture() == "arm64" ? "gobinary-darwin-arm64" : "gobinary-darwin-amd64"
        port = self.pm.randomOpenPort(8001..<9000)
        
        // Add binary argumants
        self.pm.processManager.addPIDAsArgument("pid")
        self.pm.processManager.addArgument("token", value: self.pm.kes.LocalPublicKey())
        self.pm.processManager.addArgument("port", value: port)
        
        Task(priority: .medium) {
            
            // Run the golang binary
            await self.pm.subscribeWithBinary(
                binURL: Bundle.main.url(forResource: binName, withExtension: nil)!,
                withRetry: true,
                withPEMWatcher: true,
                pingTimeout: {
                    print("ping timeout")
                },
                standardOutput: { output in
                    print(output)
                    
                    // Start long polling
                    if self.isFirstRun {
                        self.isFirstRun = false
                        Task {
                            while true {
                                try await Task.sleep(nanoseconds: 100_000_000)
                                     
                                try await self.publish(
                                    type: "ping",
                                    id: "",
                                    data: self.pm.objectAsString(self.items)
                                )
                            }
                        }
                    }
                },
                taskExitNotification: { err in
                    print("task exited")
                    if err != nil {
                        print(err!)
                    }
                }
            )
        }
    }
    
    func publish(
        type: String,
        id: String,
        data: String
    ) async {
        do {
            let message = try await self.pm.publishLocal(
                self.pm.kes.encodeJSONAndEncrypt(
                    TypeIDAndData(
                        type: type,
                        id: id,
                        data: data
                    ),
                    additionalData: self.pm.keyExchangeCurrentTimestampData()
                ),
                port: self.port,
                path: "/request",
                bearerToken: self.pm.bearerToken
            )
            
            // Update self.items
            if let updateItems: [Item] = try? self.pm.decryptAndDecodeJSON(
                data: message,
                kes: self.pm.kes,
                auth: self.pm.authTimestamp
            ) {
                for v in updateItems {
                    if let row = self.items.firstIndex(where: {$0.id == v.id}) {
                        self.items[row] = v
                    } else {
                        self.items.append(v)
                    }
                }
                
                return
            }
        } catch {
            print(error)
            return
        }
    }
}
```
## Security and optional encryption

macOS does not allow you to use https (i.e. encrypted) connections without significant complexity.  However, connecting the SwiftUI and golang apps via http is relatively simple.

This library creates a Diffie–Hellman Key Exchange ([DHKE](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)) connection between the SwiftUI app and golang app using the [calmdocs/SwiftKeyExchange swift library](https://github.com/calmdocs/SwiftKeyExchange) and [calmdocs/keyexchange go library](https://github.com/calmdocs/keyexchange).  The SwiftUI app sends its public key as an argumant to the golang app, and the golang app then sends its public key to stdOut as a [PEM message](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) for the SwiftUI app to read.

If you want to use this library without encypting (or if you want to use your own encryption), update gobinary.go as directed in the comments in that file, and change the swift publish function as follows:  
```
 func publish(
        type: String,
        id: String,
        data: String
    ) async {
        do {
            let message = try await self.pm.publishLocal(               
                TypeIDAndData(
                    type: type,
                    id: id,
                    data: data
                ),
                port: self.port,
                path: "/request",
                bearerToken: "bearerToken123",
            )
            
            // Update self.items
            if let updateItems: [Item] = try? JSONDecoder().decode([Item].self, from: message) {
                for v in updateItems {
                    if let row = self.items.firstIndex(where: {$0.id == v.id}) {
                        self.items[row] = v
                    } else {
                        self.items.append(v)
                    }
                }
                return
            }
        } catch {
            print(error)
            return
        }
    }
)
```

We have been as conservative as possible when creating this library.  See the security details available on the [calmdocs/SwiftKeyExchange package page](https://github.com/calmdocs/SwiftKeyExchange). Please note that you use this library and the code in this repo at your own risk, and we accept no liability in relation to its use.
