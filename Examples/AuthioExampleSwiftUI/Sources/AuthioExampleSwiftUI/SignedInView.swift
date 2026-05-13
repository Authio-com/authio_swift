// SignedInView.swift — the "in" state. Shows the user id, active org,
// a switch-org picker when memberships > 1, and a sign-out button.

#if canImport(SwiftUI) && (os(iOS) || os(macOS) || os(visionOS))

import SwiftUI
import Authio

@available(iOS 16, macOS 13, visionOS 1, *)
@MainActor
struct SignedInView: View {
    @ObservedObject var store: AuthioStore

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 48))
                .foregroundStyle(.green)
            Text("Signed in").font(.title.bold())

            if let s = store.session {
                LabeledRow("User", s.userId)
                LabeledRow("Active org", s.orgId ?? "—")
                LabeledRow("Role", s.role ?? "—")
                LabeledRow("Expires", s.expiresAt.formatted(date: .abbreviated, time: .shortened))
            }

            if store.memberships.count > 1 {
                Divider()
                Text("Switch organization").font(.headline)
                ForEach(store.memberships, id: \.id) { m in
                    Button {
                        Task { await store.switchOrg(m.organizationId) }
                    } label: {
                        HStack {
                            Text(m.organization.name).bold()
                            Spacer()
                            Text(m.role).foregroundStyle(.secondary)
                            if store.session?.orgId == m.organizationId {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                    .buttonStyle(.bordered)
                }
            }

            Spacer()

            Button(role: .destructive) {
                Task { await store.signOut() }
            } label: {
                Label("Sign out", systemImage: "rectangle.portrait.and.arrow.right")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .task { await store.loadOrganizations() }
    }
}

@available(iOS 16, macOS 13, visionOS 1, *)
struct LabeledRow: View {
    let label: String
    let value: String
    init(_ label: String, _ value: String) {
        self.label = label
        self.value = value
    }
    var body: some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).fontDesign(.monospaced)
        }
    }
}

#endif
