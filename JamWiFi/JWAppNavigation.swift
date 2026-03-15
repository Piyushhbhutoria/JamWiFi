import SwiftUI

enum JWScreen: Identifiable {
    case list(JWListView)
    case gatherer(JWTrafficGatherer)
    case killer(JWClientKiller)

    var id: String {
        switch self {
        case .list(let c): return "list-\(ObjectIdentifier(c))"
        case .gatherer(let g): return "gatherer-\(ObjectIdentifier(g))"
        case .killer(let k): return "killer-\(ObjectIdentifier(k))"
        }
    }
}

final class AppNavigation: ObservableObject {
    @Published var stack: [JWScreen] = []
    weak var alertState: AppAlertState?

    let listController: JWListView

    init() {
        listController = JWListView(navigation: nil)
        listController.navigation = self
        stack = [.list(listController)]
    }

    func push(_ screen: JWScreen) {
        stack.append(screen)
    }

    func pop() {
        guard stack.count > 1 else { return }
        stack.removeLast()
    }

    func popToRoot() {
        stack = [.list(listController)]
    }
}

struct ContentView: View {
    @ObservedObject var navigation: AppNavigation
    @EnvironmentObject var alertState: AppAlertState

    var body: some View {
        Group {
            if let screen = navigation.stack.last {
                switch screen {
                case .list(let controller):
                    JWListScreen(controller: controller)
                case .gatherer(let controller):
                    JWTrafficGathererScreen(controller: controller)
                case .killer(let controller):
                    JWClientKillerScreen(controller: controller)
                }
            } else {
                JWListScreen(controller: navigation.listController)
            }
        }
        .onAppear {
            navigation.alertState = alertState
            navigation.listController.alertState = alertState
        }
        .alert(alertState.title, isPresented: $alertState.isPresented) {
            Button("OK") {
                if alertState.isAdminError {
                    exit(0)
                }
            }
        } message: {
            Text(alertState.message)
        }
    }
}
